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

pub fn denyAllAccess() !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

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

    const restrict_res = std.os.linux.syscall2(.landlock_restrict_self, @as(u64, @intCast(fd_i32)), 0);
    _ = std.os.linux.syscall1(.close, @as(u64, @intCast(fd_i32)));

    if (std.os.linux.errno(restrict_res) != .SUCCESS) {
        return switch (std.os.linux.errno(restrict_res)) {
            .NOSYS => error.KernelTooOld,
            .OPNOTSUPP => error.LandlockNotSupported,
            else => error.LandlockFailed,
        };
    }
}

pub fn allowPathAccess(path: []const u8, allowed_access: u64) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    const attr = landlock_ruleset_attr{ .handled_access_fs = all_fs_access };
    const fd = std.os.linux.syscall3(
        .landlock_create_ruleset,
        @intFromPtr(&attr),
        @sizeOf(@TypeOf(attr)),
        @as(u64, 0),
    );
    const fd_i32: i32 = @intCast(fd);
    if (fd_i32 < 0) return error.LandlockFailed;

    const path_fd = std.os.linux.syscall3(.open, @intFromPtr(path.ptr), @as(u64, 0), @as(u64, 0));
    const path_fd_i32: i32 = @intCast(path_fd);
    if (path_fd_i32 < 0) {
        _ = std.os.linux.syscall1(.close, @intCast(fd));
        return error.PathOpenFailed;
    }

    const path_attr = landlock_path_beneath_attr{
        .allowed_access = allowed_access,
        .parent_fd = path_fd_i32,
    };

    const add_res = std.os.linux.syscall4(
        .landlock_add_rule,
        @as(u64, @intCast(fd_i32)),
        LANDLOCK_ADD_RULE_PATH_BENEATH,
        @intFromPtr(&path_attr),
        @as(u64, 0),
    );

    _ = std.os.linux.syscall1(.close, @as(u64, @intCast(path_fd_i32)));

    if (std.os.linux.errno(add_res) != .SUCCESS) {
        _ = std.os.linux.syscall1(.close, @intCast(fd));
        return error.LandlockRuleFailed;
    }

    const restrict_res = std.os.linux.syscall2(.landlock_restrict_self, @as(u64, @intCast(fd_i32)), 0);
    _ = std.os.linux.syscall1(.close, @as(u64, @intCast(fd_i32)));

    if (std.os.linux.errno(restrict_res) != .SUCCESS) {
        return switch (std.os.linux.errno(restrict_res)) {
            .NOSYS => error.KernelTooOld,
            else => error.LandlockFailed,
        };
    }
}

test "landlock deny all returns expected error on non-Linux" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
}
