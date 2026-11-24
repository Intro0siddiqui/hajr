const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .linux) @compileError("landlock is Linux-specific");
}

const landlock_ruleset_attr = extern struct {
    handled_access_fs: u64,
};

const landlock_path_beneath_attr = extern struct {
    allowed_access: u64,
    parent_fd: i32,
};

const LANDLOCK_CREATE_RULESET_VERSION: u64 = 1 << 0;
const LANDLOCK_ADD_RULE_PATH_BENEATH: u64 = 1;

// Filesystem access rights matching <linux/landlock.h>
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
pub const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

const fs_access_v1: u64 = (1 << 13) - 1; // Bits 0..12

const read_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
const write_access_v1 =
    LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_REMOVE_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_FILE |
    LANDLOCK_ACCESS_FS_MAKE_CHAR |
    LANDLOCK_ACCESS_FS_MAKE_DIR |
    LANDLOCK_ACCESS_FS_MAKE_REG |
    LANDLOCK_ACCESS_FS_MAKE_SOCK |
    LANDLOCK_ACCESS_FS_MAKE_FIFO |
    LANDLOCK_ACCESS_FS_MAKE_BLOCK |
    LANDLOCK_ACCESS_FS_MAKE_SYM;

const PR_SET_NO_NEW_PRIVS: u64 = 38;

/// A single path exception for Landlock filtering.
pub const PathRule = struct {
    path: [*:0]const u8,
    read: bool = false,
    write: bool = false,
};

/// Query highest supported Landlock ABI version from kernel.
pub fn getAbiVersion() !u32 {
    const compat_res = std.os.linux.syscall3(.landlock_create_ruleset, 0, 0, LANDLOCK_CREATE_RULESET_VERSION);
    const err = std.os.linux.errno(compat_res);
    if (err != .SUCCESS) {
        if (err == .NOSYS) return error.KernelTooOld;
        return error.LandlockNotSupported;
    }
    return @as(u32, @truncate(compat_res));
}

fn openPathWithErrno(path: [*:0]const u8, out_err: *std.os.linux.E) ?i32 {
    const o_path = @as(u32, @bitCast(std.posix.O{ .PATH = true, .CLOEXEC = true }));
    const fd = std.os.linux.syscall4(
        .openat,
        @as(u64, @bitCast(@as(i64, std.posix.AT.FDCWD))),
        @intFromPtr(path),
        @as(u64, o_path),
        @as(u64, 0),
    );
    const err = std.os.linux.errno(fd);
    if (err == .SUCCESS) {
        out_err.* = .SUCCESS;
        return @as(i32, @intCast(fd));
    }

    // Fallback: read-only without O_PATH
    const o_rdonly = @as(u32, @bitCast(std.posix.O{ .ACCMODE = .RDONLY, .CLOEXEC = true }));
    const fd_ro = std.os.linux.syscall4(
        .openat,
        @as(u64, @bitCast(@as(i64, std.posix.AT.FDCWD))),
        @intFromPtr(path),
        @as(u64, o_rdonly),
        @as(u64, 0),
    );
    const err_ro = std.os.linux.errno(fd_ro);
    if (err_ro == .SUCCESS) {
        out_err.* = .SUCCESS;
        return @as(i32, @intCast(fd_ro));
    }
    out_err.* = err_ro;
    return null;
}

fn openPath(path: [*:0]const u8) ?i32 {
    var err: std.os.linux.E = .SUCCESS;
    return openPathWithErrno(path, &err);
}

fn createRuleset(handled_access: u64) !i32 {
    const attr = landlock_ruleset_attr{ .handled_access_fs = handled_access };
    const fd = std.os.linux.syscall3(
        .landlock_create_ruleset,
        @intFromPtr(&attr),
        @sizeOf(@TypeOf(attr)),
        @as(u64, 0),
    );
    const err = std.os.linux.errno(fd);
    if (err != .SUCCESS) {
        return switch (err) {
            .OPNOTSUPP => error.LandlockNotSupported,
            .NOSYS => error.KernelTooOld,
            else => error.LandlockFailed,
        };
    }
    return @as(i32, @intCast(fd));
}

fn addPathRule(ruleset_fd: i32, path_fd: i32, allowed_access: u64) !void {
    const path_attr = landlock_path_beneath_attr{
        .allowed_access = allowed_access,
        .parent_fd = path_fd,
    };

    const add_res = std.os.linux.syscall4(
        .landlock_add_rule,
        @as(u64, @intCast(ruleset_fd)),
        LANDLOCK_ADD_RULE_PATH_BENEATH,
        @intFromPtr(&path_attr),
        @as(u64, 0),
    );

    if (std.os.linux.errno(add_res) != .SUCCESS) {
        return error.LandlockRuleFailed;
    }
}

fn applyRuleset(ruleset_fd: i32) !void {
    // Landlock requires PR_SET_NO_NEW_PRIVS for unprivileged processes (without CAP_SYS_ADMIN).
    // Ensure it is set before landlock_restrict_self.
    const prctl_res = std.os.linux.syscall5(.prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (std.os.linux.errno(prctl_res) != .SUCCESS) {
        _ = std.os.linux.syscall1(.close, @as(u64, @intCast(ruleset_fd)));
        return error.PrctlFailed;
    }

    const restrict_res = std.os.linux.syscall2(
        .landlock_restrict_self,
        @as(u64, @intCast(ruleset_fd)),
        0,
    );
    _ = std.os.linux.syscall1(.close, @as(u64, @intCast(ruleset_fd)));

    if (std.os.linux.errno(restrict_res) != .SUCCESS) {
        return switch (std.os.linux.errno(restrict_res)) {
            .NOSYS => error.KernelTooOld,
            .OPNOTSUPP => error.LandlockNotSupported,
            else => error.LandlockFailed,
        };
    }
}

/// Deny all filesystem access with specific path exceptions.
///
/// This creates a Landlock ruleset that denies everything, then adds
/// exceptions for the specified paths. Paths that cannot be opened are
/// logged with path and errno and skipped.
pub fn denyWithExceptions(rules: []const PathRule) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    const abi = try getAbiVersion();
    if (abi < 1) return error.LandlockNotSupported;

    var handled_fs: u64 = fs_access_v1;
    if (abi >= 2) handled_fs |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) handled_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) handled_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;

    const ruleset_fd = try createRuleset(handled_fs);

    // Directory access flags
    const effective_dir_read = (read_access | LANDLOCK_ACCESS_FS_EXECUTE) & handled_fs;
    var effective_dir_rw = (read_access | LANDLOCK_ACCESS_FS_EXECUTE | write_access_v1) & handled_fs;
    if (abi >= 2) effective_dir_rw |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) effective_dir_rw |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) effective_dir_rw |= LANDLOCK_ACCESS_FS_IOCTL_DEV;

    // File / device access flags (never includes directory-only flags like READ_DIR, MAKE_*, REMOVE_*, REFER)
    var file_access_mask = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE;
    if (abi >= 3) file_access_mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) file_access_mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    file_access_mask &= handled_fs;

    const effective_file_read = effective_dir_read & file_access_mask;
    const effective_file_rw = effective_dir_rw & file_access_mask;

    for (rules) |rule| {
        var open_err: std.os.linux.E = .SUCCESS;
        const maybe_fd = openPathWithErrno(rule.path, &open_err);
        if (maybe_fd == null) {
            std.debug.print(
                "[HAJR-LANDLOCK] WARNING: failed to open path '{s}', errno={d} ({s})\n",
                .{ rule.path, @intFromEnum(open_err), @tagName(open_err) },
            );
            continue;
        }
        const path_fd = maybe_fd.?;
        defer _ = std.os.linux.syscall1(.close, @as(u64, @intCast(path_fd)));

        var st: std.os.linux.Statx = undefined;
        const rc_stat = std.os.linux.statx(
            path_fd,
            "",
            std.os.linux.AT.EMPTY_PATH,
            .{ .TYPE = true, .MODE = true },
            &st,
        );
        const is_dir = if (std.os.linux.errno(rc_stat) == .SUCCESS)
            (st.mode & std.posix.S.IFMT) == std.posix.S.IFDIR
        else
            false;

        var access: u64 = 0;
        if (rule.write) {
            access = if (is_dir) effective_dir_rw else effective_file_rw;
        } else if (rule.read) {
            access = if (is_dir) effective_dir_read else effective_file_read;
        }

        if (access != 0) {
            const path_attr = landlock_path_beneath_attr{
                .allowed_access = access,
                .parent_fd = path_fd,
            };

            const add_res = std.os.linux.syscall4(
                .landlock_add_rule,
                @as(u64, @intCast(ruleset_fd)),
                LANDLOCK_ADD_RULE_PATH_BENEATH,
                @intFromPtr(&path_attr),
                @as(u64, 0),
            );
            const add_err = std.os.linux.errno(add_res);
            if (add_err != .SUCCESS) {
                std.debug.print(
                    "[HAJR-LANDLOCK] ERROR: addPathRule failed for '{s}' (is_dir={}, access=0x{x}), errno={d} ({s})\n",
                    .{ rule.path, is_dir, access, @intFromEnum(add_err), @tagName(add_err) },
                );
                return error.LandlockRuleFailed;
            }
        }
    }

    try applyRuleset(ruleset_fd);
}

/// Deny all filesystem access (no exceptions).
pub fn denyAllAccess() !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    const abi = try getAbiVersion();
    if (abi < 1) return error.LandlockNotSupported;

    var handled_fs: u64 = fs_access_v1;
    if (abi >= 2) handled_fs |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) handled_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) handled_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;

    const ruleset_fd = try createRuleset(handled_fs);
    try applyRuleset(ruleset_fd);
}

/// Allow access to a specific path (used for building exception lists).
pub fn allowPathAccess(path: [:0]const u8, allowed_access: u64) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    const abi = try getAbiVersion();
    if (abi < 1) return error.LandlockNotSupported;

    var handled_fs: u64 = fs_access_v1;
    if (abi >= 2) handled_fs |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) handled_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) handled_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;

    const ruleset_fd = try createRuleset(handled_fs);

    var open_err: std.os.linux.E = .SUCCESS;
    const path_fd_opt = openPathWithErrno(path.ptr, &open_err);
    if (path_fd_opt == null) {
        std.debug.print(
            "[HAJR-LANDLOCK] ERROR: allowPathAccess failed to open path '{s}', errno={d} ({s})\n",
            .{ path, @intFromEnum(open_err), @tagName(open_err) },
        );
        _ = std.os.linux.syscall1(.close, @as(u64, @intCast(ruleset_fd)));
        return error.PathOpenFailed;
    }
    const path_fd = path_fd_opt.?;
    defer _ = std.os.linux.syscall1(.close, @as(u64, @intCast(path_fd)));

    var st: std.os.linux.Statx = undefined;
    const rc_stat = std.os.linux.statx(
        path_fd,
        "",
        std.os.linux.AT.EMPTY_PATH,
        .{ .TYPE = true, .MODE = true },
        &st,
    );
    const is_dir = if (std.os.linux.errno(rc_stat) == .SUCCESS)
        (st.mode & std.posix.S.IFMT) == std.posix.S.IFDIR
    else
        false;

    var access = allowed_access & handled_fs;
    if (!is_dir) {
        var file_mask = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE;
        if (abi >= 3) file_mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
        if (abi >= 5) file_mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        access &= (file_mask & handled_fs);
    }

    const path_attr = landlock_path_beneath_attr{
        .allowed_access = access,
        .parent_fd = path_fd,
    };

    const add_res = std.os.linux.syscall4(
        .landlock_add_rule,
        @as(u64, @intCast(ruleset_fd)),
        LANDLOCK_ADD_RULE_PATH_BENEATH,
        @intFromPtr(&path_attr),
        @as(u64, 0),
    );
    const add_err = std.os.linux.errno(add_res);
    if (add_err != .SUCCESS) {
        std.debug.print(
            "[HAJR-LANDLOCK] ERROR: addPathRule failed for '{s}' (is_dir={}, access=0x{x}), errno={d} ({s})\n",
            .{ path, is_dir, access, @intFromEnum(add_err), @tagName(add_err) },
        );
        _ = std.os.linux.syscall1(.close, @as(u64, @intCast(ruleset_fd)));
        return error.LandlockRuleFailed;
    }

    try applyRuleset(ruleset_fd);
}

test "landlock abi version query on linux" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const abi = try getAbiVersion();
    try std.testing.expect(abi >= 1);
}

test "landlock denies disallowed paths in child process" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const res_fork = std.os.linux.syscall0(.fork);
    if (res_fork == 0) {
        // In child process: test lockdown with /tmp exception
        const rules = [_]PathRule{
            .{ .path = "/tmp", .read = true, .write = true },
        };
        denyWithExceptions(&rules) catch |err| {
            std.debug.print("[HAJR-TEST] denyWithExceptions failed: {}\n", .{err});
            _ = std.os.linux.syscall1(.exit_group, 10);
        };

        // Allowed path check: /tmp should be openable
        const o_rdonly = @as(u32, @bitCast(std.posix.O{ .ACCMODE = .RDONLY, .CLOEXEC = true }));
        const check_tmp = std.os.linux.syscall4(
            .openat,
            @as(u64, @bitCast(@as(i64, std.posix.AT.FDCWD))),
            @intFromPtr("/tmp"),
            @as(u64, o_rdonly),
            0,
        );
        if (std.os.linux.errno(check_tmp) != .SUCCESS) _ = std.os.linux.syscall1(.exit_group, 11);
        _ = std.os.linux.syscall1(.close, check_tmp);

        // Denied path check: /etc/shadow should return EACCES
        const check_denied = std.os.linux.syscall4(
            .openat,
            @as(u64, @bitCast(@as(i64, std.posix.AT.FDCWD))),
            @intFromPtr("/etc/shadow"),
            @as(u64, o_rdonly),
            0,
        );
        if (std.os.linux.errno(check_denied) != .ACCES) _ = std.os.linux.syscall1(.exit_group, 12);

        _ = std.os.linux.syscall1(.exit_group, 0);
    }

    var status: i32 = 0;
    _ = std.os.linux.syscall4(.wait4, res_fork, @intFromPtr(&status), 0, 0);
    const exit_code = (status >> 8) & 0xff;
    try std.testing.expectEqual(@as(i32, 0), exit_code);
}
