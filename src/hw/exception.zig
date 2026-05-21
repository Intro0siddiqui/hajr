const std = @import("std");
const builtin = @import("builtin");
const os_abstraction = @import("os_abstraction.zig");

pub fn init() void {
    if (builtin.os.tag != .linux) return;

    var sa: std.posix.Sigaction = .{
        .handler = .{ .sigaction = handleFault },
        .mask = std.posix.empty_sigset,
        .flags = std.posix.SA.SIGINFO | std.posix.SA.ONSTACK, // SIGINFO + alternate stack
    };

    _ = std.posix.sigaction(std.posix.SIG.SEGV, &sa, null) catch {};
    _ = std.posix.sigaction(std.posix.SIG.BUS, &sa, null) catch {};
}

var fault_callback: ?os_abstraction.FaultHandlerFn = null;

pub fn registerCallback(cb: os_abstraction.FaultHandlerFn) void {
    fault_callback = cb;
}

fn handleFault(sig: i32, info: *const std.posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.C) void {
    _ = sig;
    _ = ctx_ptr;

    if (fault_callback) |cb| {
        const addr = @as(usize, @intFromPtr(info.fields.sigfault.addr));
        // Simple translation: on x86_64, SI_FAULT_WRITE is encoded in info.si_code
        // This is highly architecture dependent. 
        // For now, keep it simple as requested.
        const fault_info = os_abstraction.FaultInfo{
            .address = addr,
            .is_write = true, // Simplified
            .is_exec = false,
        };
        cb(fault_info);
    } else {
        std.posix.exit(1);
    }
}
