//! Hajr Browser Sandbox - Simple Example
//! 
//! Demonstrates basic sandbox creation, IPC, and hardware protection.

const std = @import("std");
const sandbox = @import("core/sandbox.zig");
const ipc = @import("ipc/ipc.zig");

pub fn main() !void {
    std.debug.print("Hajr Browser Sandbox - Simple Example\n", .{});
    std.debug.print("======================================\n\n", .{});
    
    // Detect hardware protection mechanism
    const mechanism = sandbox.HardwareProtection.detect();
    std.debug.print("Hardware protection: {s}\n", .{@tagName(mechanism)});
    
    // Create sandbox manager
    var manager = try sandbox.SandboxManager.init(.{
        .max_sandboxes = 4,
        .ring_buffer_size = 4096,
        .enable_hardware_protection = true,
        .crash_recovery_enabled = true,
    });
    defer manager.shutdown();
    
    std.debug.print("\nCreated sandbox manager with 4 max sandboxes\n", .{});
    
    // Create sandboxes at different tiers
    std.debug.print("\nCreating sandboxes...\n", .{});
    
    const trusted = try manager.createSandbox(.trusted);
    std.debug.print("  Created trusted sandbox (ID: {})\n", .{trusted.id});
    
    const untrusted = try manager.createSandbox(.untrusted);
    std.debug.print("  Created untrusted sandbox (ID: {})\n", .{untrusted.id});
    
    // Allocate memory arenas
    std.debug.print("\nAllocating memory arenas...\n", .{});
    
    const trusted_arena = try trusted.allocateArena(1024 * 1024);
    std.debug.print("  Trusted arena: {} bytes at {*}\n", .{ trusted_arena.size, trusted_arena });
    
    const untrusted_arena = try untrusted.allocateArena(512 * 1024);
    std.debug.print("  Untrusted arena: {} bytes at {*}\n", .{ untrusted_arena.size, untrusted_arena });
    
    // Create IPC channel between sandboxes
    std.debug.print("\nCreating IPC channel...\n", .{});
    
    const channel = try ipc.IpcChannel.create(
        trusted.id,
        untrusted.id,
        sandbox.SandboxTier.getProtectionKey(.trusted),
        sandbox.SandboxTier.getProtectionKey(.untrusted),
    );
    defer channel.destroy();
    
    std.debug.print("  IPC channel created between sandbox {} and {}\n", .{
        trusted.id, untrusted.id
    });
    
    // Test IPC messaging
    std.debug.print("\nTesting IPC...\n", .{});
    
    // Send message from trusted to untrusted
    const test_message = "Hello from trusted sandbox!";
    try channel.sendMsg(.execute, test_message);
    std.debug.print("  Sent: \"{s}\"\n", .{test_message});
    
    // Receive message in untrusted sandbox
    var recv_buf = std.ArrayList(u8).init(std.heap.page_allocator);
    defer recv_buf.deinit();
    
    const header = try channel.recvMsg(&recv_buf);
    std.debug.print("  Received ({} bytes, seq={}): \"{s}\"\n", .{
        header.payload_len, header.sequence, recv_buf.items
    });
    
    // Start sandboxes
    std.debug.print("\nStarting sandboxes...\n", .{});
    
    trusted.start();
    untrusted.start();
    
    std.debug.print("  Trusted sandbox running\n", .{});
    std.debug.print("  Untrusted sandbox running\n", .{});
    
    // Simulate work
    std.debug.print("\nSimulating sandbox work...\n", .{});
    
    for (0..3) |i| {
        std.debug.print("  Tick {}: Sandbox {} active\n", .{ i, trusted.id });
        std.atomic.spinLoopHint();
    }
    
    // Simulate fault and recovery
    std.debug.print("\nTesting fault handling...\n", .{});
    
    trusted.fault();
    std.debug.print("  Simulated fault in trusted sandbox\n", .{});
    
    std.debug.print("\n=== Example completed successfully ===\n", .{});
    
    // Cleanup happens via defer
    _ = channel;
}

test "Basic sandbox operations" {
    var manager = try sandbox.SandboxManager.init(.{
        .max_sandboxes = 2,
    });
    defer manager.shutdown();
    
    const sandbox1 = try manager.createSandbox(.trusted);
    try std.testing.expect(sandbox1.state == .created);
    
    sandbox1.start();
    try std.testing.expect(sandbox1.state == .running);
    
    sandbox1.terminate();
    try std.testing.expect(sandbox1.state == .terminated);
}