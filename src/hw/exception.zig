const std = @import("std");
const builtin = @import("builtin");
const os_abstraction = @import("os_abstraction.zig");

pub fn init() void {
    if (builtin.os.tag == .windows) return;

    var sa: std.posix.Sigaction = .{
        .handler = .{ .sigaction = handleFault },
        .mask = std.posix.sigset_t{0},
        .flags = std.posix.SA.SIGINFO | std.posix.SA.ONSTACK,
    };

    _ = std.posix.sigaction(std.posix.SIG.SEGV, &sa, null);
    _ = std.posix.sigaction(std.posix.SIG.BUS, &sa, null);
}

var fault_callback: ?os_abstraction.FaultHandlerFn = null;

pub fn registerCallback(cb: os_abstraction.FaultHandlerFn) void {
    fault_callback = cb;
}

fn handleFault(sig: std.posix.SIG, info: *const std.posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) void {
    _ = sig;
    _ = ctx_ptr;

    if (fault_callback) |cb| {
        const addr = extractFaultAddress(info);
        const fault_type = extractFaultType(info);
        const fault_info = os_abstraction.FaultInfo{
            .address = addr,
            .is_write = fault_type.is_write,
            .is_exec = fault_type.is_exec,
        };
        cb(fault_info);
    } else {
        if (comptime builtin.os.tag == .linux) {
            std.os.linux.exit(1);
        } else {
            std.posix._exit(1);
        }
    }
}

fn extractFaultType(info: *const std.posix.siginfo_t) struct { is_write: bool, is_exec: bool } {
    if (comptime builtin.os.tag == .linux) {
        return .{ .is_write = info.code == 4, .is_exec = false };
    } else {
        return .{ .is_write = true, .is_exec = false };
    }
}

fn extractFaultAddress(info: *const std.posix.siginfo_t) usize {
    if (comptime builtin.os.tag == .linux) {
        return @as(usize, @intFromPtr(info.fields.sigfault.addr));
    } else {
        // macOS and other POSIX: siginfo_t has si_addr as a direct field
        return @intFromPtr(@field(info, "si_addr"));
    }
}
