const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

var fault_callback: ?*const fn (sig: i32, info: *const posix.siginfo_t) callconv(.C) void = null;

pub fn registerCallback(cb: *const fn (sig: i32, info: *const posix.siginfo_t) callconv(.C) void) void {
    fault_callback = cb;
}

pub fn init() void {
    if (builtin.os.tag != .linux) return;

    var sa: posix.Sigaction = .{
        .handler = .{ .sigaction = handleFault },
        .mask = posix.empty_sigset,
        .flags = posix.SA.SIGINFO | posix.SA.RESTART,
    };

    posix.sigaction(posix.SIG.SEGV, &sa, null) catch {};
    posix.sigaction(posix.SIG.BUS, &sa, null) catch {};
}

fn handleFault(sig: i32, info: *const posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.C) void {
    _ = ctx_ptr;

    const msg = "HARDWARE FAULT: Protection boundary violation detected.\n";
    _ = posix.write(posix.STDERR_FILENO, msg) catch {};

    if (fault_callback) |cb| {
        cb(sig, info);
    } else {
        posix.exit(1);
    }
}
