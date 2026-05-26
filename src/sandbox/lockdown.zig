const std = @import("std");
const builtin = @import("builtin");
const hw = @import("../hw/mod.zig");

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

pub fn seal(config: LockdownConfig) LockdownError!void {
    _ = config;
    if (locked.load(.acquire)) return;

    try hw.os.sealProcess();

    locked.store(true, .release);
}

export fn hajr_seal_process() callconv(.c) void {
    seal(.{}) catch {};
}

export fn hajr_seal_process_ex(jit_enabled: bool, minimal: bool, reduce_il: bool) callconv(.c) void {
    seal(.{
        .jit_enabled = jit_enabled,
        .minimal_syscalls = minimal,
        .reduce_integrity = reduce_il,
    }) catch {};
}

pub fn isSealed() bool {
    return locked.load(.acquire);
}

test "lockdown config defaults" {
    const config = LockdownConfig{};
    try std.testing.expect(config.jit_enabled);
    try std.testing.expect(!config.minimal_syscalls);
}
