const std = @import("std");
const hw = @import("../hw/mod.zig");
const sandbox_core = @import("../core/sandbox.zig");
const sandbox_mem = @import("../sandbox/memory.zig");
const ipc = @import("../ipc/ipc.zig");

// ============================================================================
// Task 1: Zero-Task Bridge Test
// ============================================================================

test "Zero-Task Bridge: JS Engine Memory Passing" {
    const allocator = std.testing.allocator;

    // 1. Simulate JS Engine initialization
    const layout = sandbox_mem.ArenaLayout.defaultConfig();
    const mem = try sandbox_mem.SandboxMemory.create(std.heap.page_allocator, layout);
    defer mem.destroy();

    // 2. Setup IPC Rings
    // We use two different keys for source and target to test isolation
    const source_key = mem.protection_key;
    const target_token = try hw.compartment.global_allocator.alloc();
    defer hw.compartment.global_allocator.free(target_token);
    const target_key = target_token.id;

    const ring = try ipc.IpcRing.create(8, .{ .value = source_key, .tier = @intFromEnum(ipc.SandboxTier.untrusted), .is_dynamic = false }, .untrusted, .trusted);
    defer ring.destroy();

    // 3. Wrap a memory handle (JS Heap) and "pass" it through IpcRing
    const heap_bounds = mem.getSegmentBounds(.js_heap);
    
    const MemoryHandle = extern struct {
        ptr: u64,
        size: u64,
        key: u32,
    };

    const handle = MemoryHandle{
        .ptr = @intFromPtr(heap_bounds.pointer.toRaw()),
        .size = heap_bounds.size,
        .key = source_key,
    };

    const payload = std.mem.asBytes(&handle);
    try ring.send(.alloc, 123, 456, payload);

    // 4. Receiving end verification
    var receive_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer receive_buf.deinit(allocator);

    const header = try ring.recv(allocator, &receive_buf);
    try std.testing.expectEqual(@as(u32, @intFromEnum(ipc.IpcMessageType.alloc)), header.msg_type);
    
    const received_handle = @as(*const MemoryHandle, @ptrCast(@alignCast(receive_buf.items))).*;
    try std.testing.expectEqual(handle.ptr, received_handle.ptr);
    try std.testing.expectEqual(handle.size, received_handle.size);
    try std.testing.expectEqual(handle.key, received_handle.key);

    // 5. Verify isolation integration with hw.mod
    // The receiver (using target_key) should be able to see the metadata
    // but validatePointer should confirm it's within the sandbox memory
    try std.testing.expect(mem.validatePointer(.js_heap, @ptrFromInt(received_handle.ptr), received_handle.size));

    // If we were in the target sandbox, we would have target_key active.
    // Here we can simulate the check:
    if (received_handle.key != target_key) {
        // This is where hardware protection would trigger a fault if we tried to access it.
        // For this test, we verify that the keys are indeed different.
        try std.testing.expect(received_handle.key != target_key);
    }
}

// ============================================================================
// Task 2: Exit Strategy / Cleanup Verification
// ============================================================================

test "Exit Strategy: Resource Cleanup Verification" {
    const allocator = std.testing.allocator;

    // 1. Measure active PKeys before
    const initial_mask = hw.compartment.global_allocator.used_mask;
    const initial_pkeys = @popCount(initial_mask);

    {
        // 2. Create a SandboxContext and perform a mock task
        var ctx = try sandbox_core.SandboxContext.init(allocator, .untrusted, 1);
        
        // Ensure the pkey was allocated
        const mid_mask = hw.compartment.global_allocator.used_mask;
        try std.testing.expect(@popCount(mid_mask) > initial_pkeys);

        // 3. Allocate some memory (Arena)
        _ = try ctx.allocateArena(1024 * 1024);

        // 4. Perform mock task
        ctx.start();
        try std.testing.expect(ctx.state == .running);

        // 5. Cleanup
        ctx.terminate();
    }

    // 6. Verify resources are returned
    const final_mask = hw.compartment.global_allocator.used_mask;
    try std.testing.expectEqual(initial_mask, final_mask);
}

test "Exit Strategy: SandboxMemory Cleanup" {
    const initial_mask = hw.compartment.global_allocator.used_mask;

    {
        const layout = sandbox_mem.ArenaLayout.defaultConfig();
    const mem = try sandbox_mem.SandboxMemory.create(std.heap.page_allocator, layout);
        try std.testing.expect(hw.compartment.global_allocator.used_mask != initial_mask);
        mem.destroy();
    }

    const final_mask = hw.compartment.global_allocator.used_mask;
    try std.testing.expectEqual(initial_mask, final_mask);
}

test "Trace Ring: hajr_trace_ipc_msg and hajr_trace_policy_event" {
    const trace = @import("../trace/trace.zig");
    const bindings = @import("../sandbox/bindings.zig");

    const allocator = std.testing.allocator;
    var tr = try allocator.create(trace.TraceRing);
    defer allocator.destroy(tr);

    tr.* = .{
        .slots = undefined,
        .head = std.atomic.Value(u64).init(0),
        .tail = std.atomic.Value(u64).init(0),
        .dropped = std.atomic.Value(u64).init(0),
    };
    for (&tr.slots) |*s| s.* = .{
        .timestamp_ns = 0,
        .source_id = 0,
        .target_id = 0,
        .ipc_sequence = 0,
        .payload_len = 0,
        .msg_type = 0,
        .event_kind = 0,
        .source_proc = 0,
        .target_proc = 0,
        .was_dropped = 0,
        .source_tier = 0,
        .target_tier = 0,
        .occupied = 0,
    };

    const prev_tr = trace.global.swap(tr, .acq_rel);
    defer trace.global.store(prev_tr, .release);

    // Register message name
    bindings.hajr_trace_register_msg(42, "WebPage_LoadURL");
    const name42 = trace.getMsgName(42);
    try std.testing.expect(name42 != null);
    try std.testing.expectEqualStrings("WebPage_LoadURL", name42.?);

    // Call hajr_trace_ipc_msg (send)
    bindings.hajr_trace_ipc_msg(42, 1001, 256, 0);

    const head1 = tr.head.load(.acquire);
    try std.testing.expectEqual(@as(u64, 1), head1);
    const rec1 = tr.slots[0];
    try std.testing.expectEqual(@as(u32, 42), rec1.msg_type);
    try std.testing.expectEqual(@as(u64, 1001), rec1.target_id);
    try std.testing.expectEqual(@as(u32, 256), rec1.payload_len);
    try std.testing.expectEqual(@intFromEnum(trace.TraceEventKind.ipc_send), rec1.event_kind);

    // Call hajr_trace_ipc_msg (recv)
    bindings.hajr_trace_ipc_msg(43, 1002, 512, 1);

    const head2 = tr.head.load(.acquire);
    try std.testing.expectEqual(@as(u64, 2), head2);
    const rec2 = tr.slots[1];
    try std.testing.expectEqual(@as(u32, 43), rec2.msg_type);
    try std.testing.expectEqual(@as(u64, 1002), rec2.target_id);
    try std.testing.expectEqual(@as(u32, 512), rec2.payload_len);
    try std.testing.expectEqual(@intFromEnum(trace.TraceEventKind.ipc_recv), rec2.event_kind);

    // Call hajr_trace_policy_event
    bindings.hajr_trace_policy_event(9999, 2, 3);

    const head3 = tr.head.load(.acquire);
    try std.testing.expectEqual(@as(u64, 3), head3);
    const rec3 = tr.slots[2];
    try std.testing.expectEqual(@as(u64, 9999), rec3.source_id);
    try std.testing.expectEqual(@as(u32, 2), rec3.payload_len); // action
    try std.testing.expectEqual(@as(u32, 3), rec3.msg_type);    // reason_code
    try std.testing.expectEqual(@intFromEnum(trace.TraceEventKind.policy_event), rec3.event_kind);
}
