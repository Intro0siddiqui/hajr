const std = @import("std");
const builtin = @import("builtin");

var fault_callback: ?*const fn (sig: i32, info: *const std.posix.siginfo_t) callconv(.C) void = null;

/// Register a callback to be invoked when a hardware fault occurs.
pub fn registerCallback(cb: *const fn (sig: i32, info: *const std.posix.siginfo_t) callconv(.C) void) void {
    fault_callback = cb;
}

/// Initialize the hardware exception handler.
/// This registers a signal handler for SIGSEGV and SIGBUS to catch
/// hardware protection faults (MPK/MTE).
pub fn init() void {
    if (builtin.os.tag != .linux) return;

    const sa = std.posix.Sigaction{
        .handler = .{ .sigaction = handleFault },
        .mask = std.posix.empty_sigset,
        .flags = std.posix.SA.SIGINFO | std.posix.SA.RESTART,
    };

    std.posix.sigaction(std.posix.SIG.SEGV, &sa, null) catch {};
    std.posix.sigaction(std.posix.SIG.BUS, &sa, null) catch {};
}

fn handleFault(sig: i32, info: *const std.posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.C) void {
    _ = ctx_ptr;

    // In a real implementation, we would check info.fields.sigfault.code
    // for SEGV_PKERR (MPK) or SEGV_MTESERR/SEGV_MTEAERR (MTE).
    
    // For now, we follow the "crash-only recovery" philosophy:
    // log the fault and invoke the recovery callback.
    
    const msg = "HARDWARE FAULT: Protection boundary violation detected.\n";
    _ = std.posix.write(std.posix.STDERR_FILENO, msg) catch {};
    
    if (fault_callback) |cb| {
        cb(sig, info);
    } else {
        std.posix.exit(1);
    }
}
