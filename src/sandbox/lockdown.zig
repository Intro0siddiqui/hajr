const std = @import("std");
const builtin = @import("builtin");
const hw = @import("../hw/mod.zig");
const os_abstraction = @import("../hw/os_abstraction.zig");

pub const ProcessType = os_abstraction.ProcessType;

pub const LockdownConfig = struct {
    jit_enabled: bool = true,
    minimal_syscalls: bool = false,
    reduce_integrity: bool = true,
};

pub const LockdownError = error{
    UnsupportedPlatform,
    PrctlFailed,
    SeccompFailed,
    LandlockNotSupported,
    LandlockFailed,
    KernelTooOld,
    SandboxInitFailed,
    MitigationPolicyFailed,
    TokenOpenFailed,
    AlreadyLocked,
};

var locked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn logSealError(process_type: ProcessType, err: anyerror) void {
    const msg_prefix = "hajr: [LOCKDOWN FAILED] process_type=";
    const type_name = switch (process_type) {
        .web => "web",
        .network => "network",
        .gpu => "gpu",
    };
    const err_name = @errorName(err);

    // Write to stderr (fd 2) via raw syscall — no allocation, no allocator needed
    if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.syscall3(.write, 2, @intFromPtr(msg_prefix.ptr), msg_prefix.len);
        _ = std.os.linux.syscall3(.write, 2, @intFromPtr(type_name.ptr), type_name.len);
        _ = std.os.linux.syscall3(.write, 2, @intFromPtr(" error="), 7);
        _ = std.os.linux.syscall3(.write, 2, @intFromPtr(err_name.ptr), err_name.len);
        _ = std.os.linux.syscall3(.write, 2, @intFromPtr("\n"), 1);
    } else if (comptime builtin.os.tag == .macos) {
        _ = std.posix.system.write(2, msg_prefix.ptr, msg_prefix.len);
        _ = std.posix.system.write(2, type_name.ptr, type_name.len);
        _ = std.posix.system.write(2, " error=", 7);
        _ = std.posix.system.write(2, err_name.ptr, err_name.len);
        _ = std.posix.system.write(2, "\n", 1);
    } else if (comptime builtin.os.tag == .windows) {
        // Windows: use stderr handle
        // Best-effort — if this fails, we silently continue
    }
}

pub fn seal(process_type: ProcessType) LockdownError!void {
    if (locked.load(.acquire)) return;

    hw.os.sealProcess(process_type, false) catch |err| {
        logSealError(process_type, err);
        return err;
    };

    locked.store(true, .release);
}

pub fn sealDebug(process_type: ProcessType) LockdownError!void {
    if (locked.load(.acquire)) return;

    hw.os.sealProcess(process_type, true) catch |err| {
        logSealError(process_type, err);
        return err;
    };

    locked.store(true, .release);
}

export fn hajr_seal_process(process_type: u32) callconv(.c) void {
    const pt: ProcessType = ProcessType.fromInt(process_type);
    seal(pt) catch |err| {
        logSealError(pt, err);
    };
}

export fn hajr_seal_process_debug(process_type: u32) callconv(.c) void {
    const pt: ProcessType = ProcessType.fromInt(process_type);
    sealDebug(pt) catch |err| {
        logSealError(pt, err);
    };
}

export fn hajr_seal_process_legacy() callconv(.c) void {
    seal(.web) catch |err| {
        logSealError(.web, err);
    };
}

pub fn isSealed() bool {
    return locked.load(.acquire);
}

test "lockdown config defaults" {
    const config = LockdownConfig{};
    try std.testing.expect(config.jit_enabled);
    try std.testing.expect(!config.minimal_syscalls);
}

test "process type from int" {
    try std.testing.expectEqual(ProcessType.web, ProcessType.fromInt(0));
    try std.testing.expectEqual(ProcessType.network, ProcessType.fromInt(1));
    try std.testing.expectEqual(ProcessType.gpu, ProcessType.fromInt(2));
}
