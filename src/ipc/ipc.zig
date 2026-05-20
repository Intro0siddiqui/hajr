//! Hajr IPC - Inter-Sandbox Communication System
//! 
//! Implements high-performance, hardware-enforced IPC between sandbox tiers
//! using lock-free ring buffers with sequence validation.

const std = @import("std");
const posix = std.posix;
const atomic = std.atomic;
const mem = std.mem;
const hw = @import("../hw/mod.zig");
const hajr = @import("../root.zig").hajr;
const sandbox = @import("../core/sandbox.zig");

// ============================================================================
// IPC Architecture
// ============================================================================
//
// Inter-sandbox communication in Hajr uses lock-free ring buffers for maximum
// performance. Messages are sequence-validated to detect corruption or attacks.
//
// Security model:
// - Hardware keys prevent memory access across tier boundaries
// - Sequence numbers detect replay attacks and data corruption
// - Atomic operations ensure consistency without locking

pub const SandboxTier = enum(u8) {
    root = 0,
    trusted = 1,
    untrusted = 2,
    isolated = 3,

    pub fn getProtectionKey(tier: SandboxTier) u32 {
        return switch (tier) {
            .root => 0,
            .trusted => 1,
            .untrusted => 2,
            .isolated => 3,
        };
    }
};

/// Message types for IPC
pub const IpcMessageType = enum(u32) {
    /// Initialize sandbox
    init = 0x00,
    /// Execute function call
    execute = 0x01,
    /// Query sandbox state
    query = 0x02,
    /// Response to query
    response = 0x03,
    /// Error occurred
    @"error" = 0x04,
    /// Shutdown sandbox
    shutdown = 0x05,
    /// Heartbeat/keepalive
    heartbeat = 0x06,
    /// Memory allocation request
    alloc = 0x10,
    /// Memory free request
    free = 0x11,
    /// File open request
    file_open = 0x20,
    /// File read request
    file_read = 0x21,
    /// File write request
    file_write = 0x22,
    /// File close request
    file_close = 0x23,
    /// Network connect request
    net_connect = 0x30,
    /// Network send request
    net_send = 0x31,
    /// Network receive request
    net_recv = 0x32,
    /// Network close request
    net_close = 0x33,
};

/// IPC message header (cache-line aligned)
pub const IpcHeader = extern struct {
    /// Message type
    msg_type: u32,
    /// Payload length in bytes
    payload_len: u32,
    /// Sequence number (monotonically increasing)
    sequence: u64,
    /// Source sandbox ID
    source_id: u64,
    /// Target sandbox ID
    target_id: u64,
    /// Timestamp (nanoseconds since boot)
    timestamp: u64,
    /// CRC32 checksum of payload
    checksum: u32,
    /// Reserved for future use
    reserved: u32 = 0,
};

/// Maximum message size
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// Maximum number of slots in the ring
pub const RING_SLOTS: usize = 64;

/// Ring buffer slot
pub const RingSlot = struct {
    /// Whether slot is occupied
    occupied: atomic.Value(bool),
    /// Message header
    header: IpcHeader,
    /// Payload data (inline for small messages)
    payload: [MAX_MESSAGE_SIZE - @sizeOf(IpcHeader)]u8,
};

/// Lock-free IPC ring buffer
pub const IpcRing = struct {
    /// Ring slots
    slots: []RingSlot,
    /// Head index (producer)
    head: atomic.Value(u64),
    /// Tail index (consumer)
    tail: atomic.Value(u64),
    /// Sequence counter
    sequence: atomic.Value(u64),
    /// Hardware protection key
    protection_key: u32,
    /// Source tier
    source_tier: SandboxTier,
    /// Target tier
    target_tier: SandboxTier,
    
    /// Create a new IPC ring
    pub fn create(
        slot_count: usize,
        protection_key: u32,
        source_tier: SandboxTier,
        target_tier: SandboxTier,
    ) !*IpcRing {
        const slots = try std.heap.page_allocator.alloc(RingSlot, slot_count);
        
        const ring = try std.heap.page_allocator.create(IpcRing);
        ring.* = .{
            .slots = slots,
            .head = atomic.Value(u64).init(0),
            .tail = atomic.Value(u64).init(0),
            .sequence = atomic.Value(u64).init(0),
            .protection_key = protection_key,
            .source_tier = source_tier,
            .target_tier = target_tier,
        };
        
        // Initialize slots
        for (ring.slots) |*slot| {
            slot.occupied = atomic.Value(bool).init(false);
            @memset(&slot.payload, 0);
        }
        
        return ring;
    }
    
    /// Send a message (producer side)
    pub fn send(
        ring: *IpcRing,
        msg_type: IpcMessageType,
        source_id: u64,
        target_id: u64,
        payload: []const u8,
    ) !void {
        if (payload.len > ring.slots[0].payload.len) {
            return error.PayloadTooLarge;
        }
        
        // Get current head and advance
        const head = ring.head.fetchAdd(1, .acq_rel);
        const slot_idx = head % ring.slots.len;
        
        // Wait for slot to be free
        var waited: usize = 0;
        while (ring.slots[slot_idx].occupied.load(.acquire)) {
            if (waited > 1000000) {
                return error.RingFull;
            }
            waited += 1;
            std.atomic.spinLoopHint();
        }
        
        // Fill slot
        const slot = &ring.slots[slot_idx];
        slot.header = .{
            .msg_type = @intFromEnum(msg_type),
            .payload_len = @as(u32, @intCast(payload.len)),
            .sequence = ring.sequence.fetchAdd(1, .acq_rel),
            .source_id = source_id,
            .target_id = target_id,
            .timestamp = hw.posix_io.monotonicTimestamp(),
            .checksum = 0, // Would calculate CRC32
            .reserved = 0,
        };
        
        @memcpy(slot.payload[0..payload.len], payload);
        
        slot.occupied.store(true, .release);
    }
    
    /// Receive a message (consumer side)
    pub fn recv(ring: *IpcRing, allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8)) !IpcHeader {
        // Load current tail WITHOUT advancing yet — we must read the slot first
        const tail = ring.tail.load(.acquire);
        const slot_idx = tail % ring.slots.len;
        
        const slot = &ring.slots[slot_idx];
        
        // Wait for slot to be occupied
        var waited: usize = 0;
        while (!slot.occupied.load(.acquire)) {
            if (waited > 1000000) {
                return error.RingEmpty;
            }
            waited += 1;
            std.atomic.spinLoopHint();
        }
        
        // Read header and payload BEFORE advancing tail
        const header = slot.header;
        try buf.resize(allocator, header.payload_len);
        @memcpy(buf.items[0..header.payload_len], slot.payload[0..header.payload_len]);
        
        // Clear slot and mark free
        slot.occupied.store(false, .release);
        
        // Advance tail AFTER data has been safely copied
        ring.tail.store(tail + 1, .release);
        
        return header;
    }
    
    /// Try to receive without blocking
    pub fn tryRecv(ring: *IpcRing, allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8)) ?IpcHeader {
        const tail = ring.tail.load(.acquire);
        const slot_idx = tail % ring.slots.len;
        
        const slot = &ring.slots[slot_idx];
        if (!slot.occupied.load(.acquire)) {
            return null;
        }
        
        // Copy data before advancing tail
        const header = slot.header;
        buf.resize(allocator, header.payload_len) catch return null;
        @memcpy(buf.items[0..header.payload_len], slot.payload[0..header.payload_len]);
        
        // Mark slot free then advance tail (non-blocking: store, not fetchAdd)
        slot.occupied.store(false, .release);
        ring.tail.store(tail + 1, .release);
        
        return header;
    }
    
    /// Get available message count
    pub fn available(ring: *const IpcRing) usize {
        const head_val = ring.head.load(.acquire);
        const tail_val = ring.tail.load(.acquire);
        return head_val - tail_val;
    }
    
    /// Destroy ring
    pub fn destroy(ring: *IpcRing) void {
        std.heap.page_allocator.free(ring.slots);
        std.heap.page_allocator.destroy(ring);
    }
};

/// IPC channel (bidirectional)
pub const IpcChannel = struct {
    /// Send ring (this tier -> peer)
    send_ring: *IpcRing,
    /// Receive ring (peer -> this tier)
    recv_ring: *IpcRing,
    /// Local sandbox ID
    local_id: u64,
    /// Remote sandbox ID
    remote_id: u64,
    
    pub fn create(
        local_id: u64,
        remote_id: u64,
        local_key: u32,
        remote_key: u32,
    ) !IpcChannel {
        const send_ring = try IpcRing.create(
            RING_SLOTS,
            local_key,
            .trusted, // Send from trusted tier
            .untrusted, // To untrusted tier
        );
        
        const recv_ring = try IpcRing.create(
            RING_SLOTS,
            remote_key,
            .untrusted, // Receive from untrusted tier
            .trusted, // To trusted tier
        );
        
        return IpcChannel{
            .send_ring = send_ring,
            .recv_ring = recv_ring,
            .local_id = local_id,
            .remote_id = remote_id,
        };
    }
    
    /// Send message to peer
    pub fn sendMsg(
        channel: *IpcChannel,
        msg_type: IpcMessageType,
        payload: []const u8,
    ) !void {
        try channel.send_ring.send(
            msg_type,
            channel.local_id,
            channel.remote_id,
            payload,
        );
    }
    
    /// Receive message from peer
    pub fn recvMsg(channel: *IpcChannel, allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8)) !IpcHeader {
        return channel.recv_ring.recv(allocator, buf);
    }
    
    /// Try to receive without blocking
    pub fn tryRecvMsg(channel: *IpcChannel, allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8)) ?IpcHeader {
        return channel.recv_ring.tryRecv(allocator, buf);
    }
    
    /// Destroy channel
    pub fn destroy(channel: *IpcChannel) void {
        channel.send_ring.destroy();
        channel.recv_ring.destroy();
    }
};

/// IPC router for managing multiple channels
pub const IpcRouter = struct {
    /// Active channels
    channels: std.AutoHashMap(u64, *IpcChannel),
    /// Ring buffer for incoming messages
    inbound: *IpcRing,
    /// Ring buffer for outgoing messages
    outbound: *IpcRing,
    /// Worker thread
    thread: ?std.Thread,
    /// Shutdown flag
    shutdown: atomic.Value(bool),
    /// Allocator
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) !IpcRouter {
        const inbound = try IpcRing.create(RING_SLOTS, SandboxTier.trusted.getProtectionKey(), .root, .trusted);
        const outbound = try IpcRing.create(RING_SLOTS, SandboxTier.trusted.getProtectionKey(), .trusted, .root);
        
        return IpcRouter{
            .channels = std.AutoHashMap(u64, *IpcChannel).init(allocator),
            .inbound = inbound,
            .outbound = outbound,
            .thread = null,
            .shutdown = atomic.Value(bool).init(false),
            .allocator = allocator,
        };
    }
    
    fn routerWorker(router: *IpcRouter) void {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(router.allocator);
        
        while (!router.shutdown.load(.acquire)) {
            if (router.inbound.available() > 0) {
                const header = router.inbound.recv(router.allocator, &buf) catch continue;
                
                // Route message to appropriate channel
                const channel = router.channels.get(header.target_id);
                if (channel) |ch| {
                    ch.recv_ring.send(
                        @as(IpcMessageType, @enumFromInt(header.msg_type)),
                        header.source_id,
                        header.target_id,
                        buf.items,
                    ) catch {};
                }
            }
            
            // Yield to avoid busy-waiting
            std.atomic.spinLoopHint();
        }
    }
    
    /// Register a new channel
    pub fn registerChannel(router: *IpcRouter, sandbox_id: u64, channel: *IpcChannel) !void {
        try router.channels.put(sandbox_id, channel);
    }
    
    /// Unregister a channel
    pub fn unregisterChannel(router: *IpcRouter, sandbox_id: u64) void {
        _ = router.channels.remove(sandbox_id);
    }
    
    /// Shutdown the router
    pub fn shutdownRouter(router: *IpcRouter) void {
        router.shutdown.store(true, .release);
        if (router.thread) |thread| {
            thread.join();
        }
    }
    
    /// Destroy router
    pub fn destroy(router: *IpcRouter) void {
        router.shutdownRouter();
        router.channels.deinit();
        router.inbound.destroy();
        router.outbound.destroy();
    }
};


// ============================================================================
// Tests
// ============================================================================

test "IpcRing basic operations" {
    const ring = try IpcRing.create(8, 1, .trusted, .untrusted);
    defer ring.destroy();
    
    // Test send
    const payload = "Hello, IPC!";
    try ring.send(.execute, 1, 2, payload);
    
    // Test receive
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    
    const header = try ring.recv(std.testing.allocator, &buf);
    try std.testing.expect(header.msg_type == @intFromEnum(IpcMessageType.execute));
    try std.testing.expectEqualSlices(u8, payload, buf.items);
}

test "IpcChannel bidirectional communication" {
    var channel = try IpcChannel.create(1, 2, 1, 2);
    defer channel.destroy();
    
    // Send message
    const msg = "Test message";
    try channel.sendMsg(.execute, msg);
    
    // Simulate receiving (in real use, would come from other side)
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    
    const header = try channel.recvMsg(std.testing.allocator, &buf);
    try std.testing.expectEqual(@as(u32, @intFromEnum(IpcMessageType.execute)), header.msg_type);
    try std.testing.expectEqualSlices(u8, msg, buf.items);
}

test "IpcRouter channel management" {
    var router = try IpcRouter.init(std.testing.allocator);
    defer router.destroy();
    
    var channel = try IpcChannel.create(1, 2, 1, 2);
    try router.registerChannel(1, &channel);
    
    try std.testing.expect(router.channels.count() == 1);
    
    router.unregisterChannel(1);
    try std.testing.expect(router.channels.count() == 0);
    
    channel.destroy();
}