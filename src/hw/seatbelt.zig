const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .macos) @compileError("seatbelt is macOS-specific");
}

extern "System" fn sandbox_init(
    profile: [*:0]const u8,
    flags: u64,
    errorbuf: ?*?*u8,
) callconv(.c) c_int;

extern "System" fn sandbox_free_error(errorbuf: *u8) callconv(.c) void;

pub const Profile = enum {
    no_internet,
    no_write,
    no_write_except_system,
};

pub fn apply(profile: Profile) !void {
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;

    const name = switch (profile) {
        .no_internet => "no-internet\x00",
        .no_write => "no-write\x00",
        .no_write_except_system => "no-write-except-system-log\x00",
    };

    const result = sandbox_init(name, 1, null);
    if (result != 0) return error.SandboxInitFailed;
}

pub fn applyCustom(profile_contents: []const u8) !void {
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;

    const null_terminated = try std.heap.page_allocator.dupeZ(u8, profile_contents);
    defer std.heap.page_allocator.free(null_terminated);

    var error_buf: ?*u8 = null;
    const result = sandbox_init(@ptrCast(null_terminated), 3, &error_buf);
    if (result != 0) {
        if (error_buf) |buf| {
            sandbox_free_error(buf);
        }
        return error.SandboxInitFailed;
    }
}

pub const full_jail_profile =
    "(version 1)\n" ++
    "(deny default)\n" ++
    "(allow sysctl-read)\n" ++
    "(allow mach-lookup (global-name \"com.apple.system.logger\"))\n";

test "seatbelt profile exists" {
    try std.testing.expect(full_jail_profile.len > 0);
}
