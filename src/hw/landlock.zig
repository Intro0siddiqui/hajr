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

const LANDLOCK_CREATE_RULESET_VERSION: u64 = 1;
const LANDLOCK_ADD_RULE_PATH_BENEATH: u64 = 1;
const LANDLOCK_RESTRICT_SELF: u64 = 2;

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_WRITE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 13;

const all_fs_access =
    LANDLOCK_ACCESS_FS_EXECUTE |
    LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_READ_DIR |
    LANDLOCK_ACCESS_FS_WRITE_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_FILE |
    LANDLOCK_ACCESS_FS_REMOVE_DIR |
    LANDLOCK_ACCESS_FS_MAKE_CHAR |
    LANDLOCK_ACCESS_FS_MAKE_DIR |
    LANDLOCK_ACCESS_FS_MAKE_REG |
    LANDLOCK_ACCESS_FS_MAKE_SOCK |
    LANDLOCK_ACCESS_FS_MAKE_FIFO |
    LANDLOCK_ACCESS_FS_MAKE_BLOCK |
    LANDLOCK_ACCESS_FS_MAKE_SYM;

const read_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
const read_write_access = read_access | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_WRITE_DIR;

/// A single path exception for Landlock filtering.
pub const PathRule = struct {
    path: [*:0]const u8,
    read: bool = false,
    write: bool = false,
};

fn openPath(path: [*:0]const u8) ?i32 {
    const fd = std.os.linux.syscall4(
        .openat,
        @as(u64, @bitCast(@as(i64, std.posix.AT.FDCWD))),
        @intFromPtr(path),
        @as(u64, 0), // O_RDONLY
        @as(u64, 0),
    );
    const fd_i32: i32 = @intCast(fd);
    if (fd_i32 < 0) return null;
    return fd_i32;
}

fn createRuleset() !i32 {
    const compat_res = std.os.linux.syscall2(.landlock_create_ruleset, LANDLOCK_CREATE_RULESET_VERSION, 0);
    if (std.os.linux.errno(compat_res) != .SUCCESS) {
        if (std.os.linux.errno(compat_res) == .NOSYS) return error.KernelTooOld;
        return error.LandlockNotSupported;
    }

    const attr = landlock_ruleset_attr{ .handled_access_fs = all_fs_access };
    const fd = std.os.linux.syscall3(
        .landlock_create_ruleset,
        @intFromPtr(&attr),
        @sizeOf(@TypeOf(attr)),
        @as(u64, 0),
    );
    const fd_i32: i32 = @intCast(fd);
    if (fd_i32 < 0) {
        return switch (std.os.linux.errno(fd)) {
            .OPNOTSUPP => error.LandlockNotSupported,
            .NOSYS => error.KernelTooOld,
            else => error.LandlockFailed,
        };
    }
    return fd_i32;
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
/// silently skipped (they remain denied).
pub fn denyWithExceptions(rules: []const PathRule) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    const ruleset_fd = try createRuleset();

    for (rules) |rule| {
        if (openPath(rule.path)) |path_fd| {
            var access: u64 = 0;
            if (rule.read) access |= read_access;
            if (rule.write) access |= read_write_access;

            if (access != 0) {
                addPathRule(ruleset_fd, path_fd, access) catch {};
            }
            _ = std.os.linux.syscall1(.close, @as(u64, @intCast(path_fd)));
        }
    }

    try applyRuleset(ruleset_fd);
}

/// Deny all filesystem access (no exceptions).
pub fn denyAllAccess() !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    const ruleset_fd = try createRuleset();
    try applyRuleset(ruleset_fd);
}

/// Allow access to a specific path (used for building exception lists).
pub fn allowPathAccess(path: []const u8, allowed_access: u64) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    const ruleset_fd = try createRuleset();

    const path_fd = std.os.linux.syscall3(.open, @intFromPtr(path.ptr), @as(u64, 0), @as(u64, 0));
    const path_fd_i32: i32 = @intCast(path_fd);
    if (path_fd_i32 < 0) {
        _ = std.os.linux.syscall1(.close, @intCast(ruleset_fd));
        return error.PathOpenFailed;
    }

    try addPathRule(ruleset_fd, path_fd_i32, allowed_access);

    _ = std.os.linux.syscall1(.close, @as(u64, @intCast(path_fd_i32)));

    try applyRuleset(ruleset_fd);
}

test "landlock deny all returns expected error on non-Linux" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
}
