const std = @import("std");
const builtin = @import("builtin");
const hw = @import("../hw/mod.zig");
const ipc = @import("../ipc/ipc.zig");
const sandbox = @import("../core/sandbox.zig");

// Global state for fault handler communication
var fault_occurred: bool = false;
var tier1_key_global: u32 = 0;

/// Hardware fault handler called by the OS on memory protection violations.
/// This handler must use C calling convention as it's called from a signal handler.
fn testFaultHandler(info: hw.os.FaultInfo) callconv(.c) void {
    _ = info;
    fault_occurred = true;
    
    // To allow the test to continue and not loop on the same instruction,
    // we grant access to the Tier 1 region that caused the fault.
    // In a real system, this might log the event or terminate the sandbox.
    hw.setKeyPermission(tier1_key_global, .read_write);
}

test "Boundary Audit Test" {
    // This test requires Linux and hardware with Intel MPK support.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hw.compartment.global_allocator.detectMpk()) return error.SkipZigTest;

    // 1. Initialize fault handling
    hw.os.registerFaultHandler(testFaultHandler);

    // 2. Resolve keys for Tier 1 (Trusted) and Tier 3 (Isolated)
    const tier1_key = sandbox.SandboxTier.trusted.getProtectionKey();
    const tier3_key = sandbox.SandboxTier.isolated.getProtectionKey();
    tier1_key_global = tier1_key;

    // 3. Allocate memory regions
    const tier1_mem = try hw.os.memAlloc(4096);
    defer hw.os.memFree(tier1_mem);
    const tier3_mem = try hw.os.memAlloc(4096);
    defer hw.os.memFree(tier3_mem);

    // 4. Apply hardware protection to regions
    try hw.applyProtectionToRegion(tier1_mem.ptr, tier1_mem.len, tier1_key);
    try hw.applyProtectionToRegion(tier3_mem.ptr, tier3_mem.len, tier3_key);

    // 5. Set initial permissions to allow setup
    hw.setKeyPermission(tier1_key, .read_write);
    hw.setKeyPermission(tier3_key, .read_write);

    // Write initial values
    tier1_mem[0] = 0x11;
    tier3_mem[0] = 0x33;

    // 6. Simulate a Tier 3 process context
    // We deny access to Tier 1 (Trusted) and allow read/write to Tier 3 (Isolated).
    fault_occurred = false;
    hw.setKeyPermission(tier1_key, .none);
    hw.setKeyPermission(tier3_key, .read_write);

    // 7. Attempt to write to the Tier 1 region from the simulated Tier 3 context.
    // This should trigger a hardware fault (SIGSEGV) which our handler intercepts.
    tier1_mem[0] = 0xFF;

    // 8. Verify the fault was correctly triggered and intercepted
    try std.testing.expect(fault_occurred);
    // Our handler re-enabled access, so the write should have eventually succeeded.
    try std.testing.expect(tier1_mem[0] == 0xFF);
}

test "Fault-Injection Test" {
    const allocator = std.testing.allocator;

    // 1. Initialize an IpcRing (from src/ipc/ipc.zig)
    const ring = try ipc.IpcRing.create(8, 0, .trusted, .untrusted);
    defer ring.destroy();

    // 2. Write a valid message to the ring
    const payload = "HardeningTestPayload";
    try ring.send(.execute, 1, 2, payload);

    // 3. Manually corrupt the checksum in the ring's raw memory
    // Access the first slot which we just populated.
    ring.slots[0].header.checksum = 0xDEADBEEF;

    // 4. Attempt to receive the message
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    const result = ring.recv(allocator, &buf);

    // 5. Verify the IPC layer returns a corruption error
    // In our implementation, this is error.ChecksumMismatch.
    try std.testing.expectError(error.ChecksumMismatch, result);
}
