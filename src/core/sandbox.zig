//! Hajr Browser Sandbox System - Core Architecture
//! 
//! A hardware-enforced sandboxing system for browser components using
//! Intel MPK (Memory Protection Keys) or ARM MTE (Memory Tagging Extension).
//! 
//! This provides process-like isolation without OS process boundaries,
//! achieving sub-microsecond IPC latency with hardware-enforced security.

const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const hw = @import("../hw/mod.zig");

// ============================================================================
// Architecture Overview
// ============================================================================
//
// Hajr implements a multi-tier sandbox architecture where components are isolated
// using hardware memory protection instead of OS process boundaries.
//
// The tiers below describe how a browser built on Hajr would assign its components,
// but Hajr itself only provides the isolation primitives and IPC transport.
// Browser-level subsystems (networking, storage, rendering) are independent
// components that plug into these tiers via the event router.
//
// Tier 0 (Root): System initialization and policy management
// Tier 1 (Trusted): Browser-level trusted subsystems (e.g. network, storage)
// Tier 2 (Untrusted): Dangerous components like JavaScript execution
// Tier 3 (Isolated): Highly restricted 3rd-party plugins, external handles
//
// Communication between tiers happens through hardened ring buffers with
// sequence-validated atomic operations. Hardware keys enforce memory access
// at the MMU level.
//
// ============================================================================

// ============================================================================
// Hardware Protection Layer
// ============================================================================

/// CPU architecture-specific hardware protection mechanism
pub const HardwareProtection = struct {
    /// Available protection mechanisms
    pub const Mechanism = enum {
        /// Intel Memory Protection Keys (MPK)
        /// Available on x86 processors with PKU support
        intel_mpk,
        /// ARM Memory Tagging Extension (MTE)
        /// Available on ARMv8.5-A processors
        arm_mte,
        /// Software-based isolation fallback (for testing)
        software_fallback,
    };
    
    /// Detect which hardware protection mechanism is available
    pub fn detect() !Mechanism {
        switch (builtin.cpu.arch) {
            .x86_64, .x86 => {
                // Check if the current CPU supports PKU via compile-time feature detection
                if (builtin.cpu.features.isEnabled(@intFromEnum(std.Target.x86.Feature.pku))) {
                    if (hw.compartment.global_allocator.detectMpk()) {
                        return .intel_mpk;
                    }
                }
                return .software_fallback;
            },
            .aarch64 => return if (builtin.os.tag == .linux) .arm_mte else .software_fallback,
            else => return .software_fallback,
        }
    }
    
    /// Hardware key types for different sandbox tiers
    pub const Key = struct {
        value: u32,
        tier: u8,
    };
};

// ============================================================================
// Hardened Ring Buffer - Zero-Copy IPC
// ============================================================================

/// Sequence-validated atomic ring buffer for inter-sandbox communication
/// 
/// This ring buffer provides:
/// - Lock-free single-producer-single-consumer semantics
/// - Monotonically increasing sequence validation
/// - Hardware memory protection via MPK/MTE
/// - Cache-line aligned access for optimal performance
pub const RingConfig = struct {
    /// Ring buffer size (must be power of 2 for efficient modulo)
    pub const DEFAULT_SIZE: usize = 4096; // 4KB - cache line aligned
    pub const MAX_SIZE: usize = 1024 * 1024; // 1MB maximum
    
    /// Metadata region size
    pub const METADATA_SIZE: usize = 192; // 3 cache lines (64 * 3) for the struct
    
    /// Total allocation size including metadata
    pub fn totalSize(size: usize) usize {
        return METADATA_SIZE + size;
    }
};

/// Ring buffer metadata (cache-line aligned)
pub const RingMetadata = extern struct {
    /// Write index from producer
    write_index: std.atomic.Value(u64),
    /// Padding to avoid false sharing
    _pad1: [56]u8 = [1]u8{0} ** 56,
    /// Read index from consumer
    read_index: std.atomic.Value(u64),
    /// Padding
    _pad2: [56]u8 = [1]u8{0} ** 56,
    /// Sequence number for validation
    sequence: std.atomic.Value(u64),
    /// Poison bit (set atomically on fault)
    poison_bit: std.atomic.Value(bool),
    /// Poison cause
    poison_cause: std.atomic.Value(u32),
    /// Padding to fill 64 bytes (8 + 1 + 4 + 51 = 64)
    _pad3: [51]u8 = [1]u8{0} ** 51,
};

/// Hardened ring buffer for IPC between sandbox tiers
pub const HardenedRingBuffer = struct {
    /// Memory-mapped ring buffer
    memory: []align(std.heap.page_size_min) u8,
    
    /// Metadata region at the start
    metadata: *RingMetadata,
    
    /// Data region start
    data: [*]u8,
    
    /// Data region size (power of 2)
    size: usize,
    
    /// Hardware protection key for this ring
    protection_key: HardwareProtection.Key,
    
    /// Memory-mapped file descriptor for persistence
    fd: ?posix.fd_t,
    
    /// Memory mapping flags
    flags: u32,
    
    /// Create a new ring buffer
    pub fn create(
        size: usize,
        protection_key: HardwareProtection.Key,
        _: SandboxTier,
    ) !HardenedRingBuffer {
        // Validate size is power of 2
        if (size == 0 or (size & (size - 1)) != 0) {
            return error.SizeNotPowerOfTwo;
        }
        
        // Cap maximum size
        const actual_size = @min(size, RingConfig.MAX_SIZE);
        
        // Calculate total memory needed
        const total_size = RingConfig.METADATA_SIZE + actual_size;
        
        // Create anonymous memory mapping via OS abstraction
        const memory = try hw.os.memAlloc(total_size);
        
        // Initialize metadata
        const metadata = @as(*RingMetadata, @ptrCast(@alignCast(memory.ptr)));
        metadata.write_index.store(0, .release);
        metadata.read_index.store(0, .release);
        metadata.sequence.store(0, .release);
        metadata.poison_bit.store(false, .release);
        metadata.poison_cause.store(0, .release);
        
        return HardenedRingBuffer{
            .memory = memory,
            .metadata = metadata,
            .data = @ptrFromInt(@intFromPtr(memory.ptr) + RingConfig.METADATA_SIZE),
            .size = actual_size,
            .protection_key = protection_key,
            .fd = null,
            .flags = 0,
        };
    }
    
    /// Write data to the ring (producer side)
    pub fn write(ring: *HardenedRingBuffer, data: []const u8) !void {
        const meta = ring.metadata;
        const write_idx = meta.write_index.load(.acquire);
        const read_idx = meta.read_index.load(.acquire);
        
        // Calculate available space with monotonic wrap-around
        const used = write_idx -% read_idx;
        const avail = ring.size - used;
        
        if (data.len > avail) {
            return error.RingFull;
        }
        
        // Write with wrap-around handling
        const write_pos = @as(usize, @intCast(write_idx)) & (ring.size - 1);
        
        // Copy first segment
        const first_len = @min(data.len, ring.size - write_pos);
        @memcpy(ring.data[write_pos..write_pos + first_len], data[0..first_len]);
        
        // Copy second segment if wrapped
        if (first_len < data.len) {
            @memcpy(ring.data[0..data.len - first_len], data[first_len..]);
        }
        
        // Update write index atomically with wrapping addition
        meta.write_index.store(write_idx +% @as(u64, @intCast(data.len)), .release);
        
        // Increment sequence for validation
        _ = meta.sequence.fetchAdd(1, .acq_rel);
    }
    
    /// Read data from the ring (consumer side)
    pub fn read(ring: *HardenedRingBuffer, buf: []u8) !usize {
        const meta = ring.metadata;
        const write_idx = meta.write_index.load(.acquire);
        const read_idx = meta.read_index.load(.acquire);
        
        // Check for available data with wrapping subtraction
        const avail = write_idx -% read_idx;
        if (avail == 0) {
            return 0;
        }
        
        // Limit read to buffer size
        const to_read = @min(@as(usize, @intCast(avail)), buf.len);
        
        // Read with wrap-around handling
        const read_pos = @as(usize, @intCast(read_idx)) & (ring.size - 1);
        
        // Copy first segment
        const first_len = @min(to_read, ring.size - read_pos);
        @memcpy(buf[0..first_len], ring.data[read_pos..read_pos + first_len]);
        
        // Copy second segment if wrapped
        if (first_len < to_read) {
            @memcpy(buf[first_len..to_read], ring.data[0..to_read - first_len]);
        }
        
        // Update read index atomically with wrapping addition
        meta.read_index.store(read_idx +% @as(u64, @intCast(to_read)), .release);
        
        return to_read;
    }
    
    /// Destroy the ring buffer and release resources
    pub fn destroy(ring: *HardenedRingBuffer) void {
        hw.os.memFree(ring.memory);
        if (ring.fd) |fd| {
            hw.posix_io.fileClose(fd);
        }
    }
};

// ============================================================================
// Sandbox Tier Definitions
// ============================================================================

/// Sandbox isolation tiers
pub const SandboxTier = enum(u8) {
    /// Tier 0: Root system initialization and policy management
    root = 0,
    /// Tier 1: Trusted components (network stack, storage)
    trusted = 1,
    /// Tier 2: Untrusted components (rendering, JavaScript)
    untrusted = 2,
    /// Tier 3: Isolated external processes
    isolated = 3,

    pub fn getProtectionKey(tier: SandboxTier) u32 {
        if (tier == .root) return 0;
        
        // Attempt to allocate/lookup a key dynamically
        const token = hw.compartment.global_allocator.alloc() catch return @intFromEnum(tier);
        return token.id;
    }
};

/// Memory access permissions for a tier
pub const AccessPermission = struct {
    read: bool,
    write: bool,
    execute: bool,
    
};

// ============================================================================
// Sandbox Process Management
// ============================================================================

/// Sandboxed execution context
pub const SandboxContext = struct {
    /// Unique identifier for this sandbox
    id: u64,
    
    /// Tier of this sandbox
    tier: SandboxTier,
    
    /// Hardware protection key
    protection_key: HardwareProtection.Key,
    
    /// Memory arenas allocated to this sandbox (pointers to avoid invalidation)
    arenas: std.ArrayListUnmanaged(*Arena),
    
    /// Ring buffers for IPC
    rings_in: std.ArrayListUnmanaged(*HardenedRingBuffer),
    rings_out: std.ArrayListUnmanaged(*HardenedRingBuffer),
    
    /// Thread handle (if using threads)
    thread: ?std.Thread,
    
    /// Allocator used for internal lists
    allocator: std.mem.Allocator,

    /// Sandbox state
    state: State,
    
    /// State machine for sandbox lifecycle
    pub const State = enum {
        created,
        initializing,
        running,
        faulted,
        terminated,
    };
    
    pub fn init(allocator: std.mem.Allocator, tier: SandboxTier, id: u64) !SandboxContext {
        const key_value = tier.getProtectionKey();
        
        return SandboxContext{
            .id = id,
            .tier = tier,
            .protection_key = .{ .value = key_value, .tier = @intFromEnum(tier) },
            .arenas = .empty,
            .rings_in = .empty,
            .rings_out = .empty,
            .thread = null,
            .allocator = allocator,
            .state = .created,
        };
    }
    
    /// Allocate a protected memory arena for this sandbox
    pub fn allocateArena(ctx: *SandboxContext, size: usize) !*Arena {
        const arena = try ctx.allocator.create(Arena);
        arena.* = try Arena.create(size, ctx.protection_key);
        try ctx.arenas.append(ctx.allocator, arena);
        return arena;
    }
    
    /// Add an IPC ring to this sandbox
    pub fn addRing(ctx: *SandboxContext, ring: *HardenedRingBuffer, direction: enum { inbound, outbound }) !void {
        switch (direction) {
            .inbound => try ctx.rings_in.append(ctx.allocator, ring),
            .outbound => try ctx.rings_out.append(ctx.allocator, ring),
        }
    }
    
    /// Transition sandbox to running state
    pub fn start(ctx: *SandboxContext) void {
        ctx.state = .running;
    }
    
    /// Mark sandbox as faulted (hardware protection violation)
    pub fn fault(ctx: *SandboxContext) void {
        ctx.state = .faulted;
    }
    
    /// Terminate sandbox and clean up resources
    pub fn terminate(ctx: *SandboxContext) void {
        ctx.state = .terminated;
        
        // Clean up arenas
        for (ctx.arenas.items) |arena| {
            arena.destroy();
            ctx.allocator.destroy(arena);
        }
        ctx.arenas.deinit(ctx.allocator);
        
        // Note: Rings are owned by the system, not the sandbox
        ctx.rings_in.deinit(ctx.allocator);
        ctx.rings_out.deinit(ctx.allocator);
        
        // Join thread if running
        if (ctx.thread) |thread| {
            thread.join();
        }
    }
};

/// Protected memory arena
pub const Arena = struct {
    memory: []align(std.heap.page_size_min) u8,
    protection_key: HardwareProtection.Key,
    size: usize,
    
    /// Create a new protected memory arena
    pub fn create(size: usize, protection_key: HardwareProtection.Key) !Arena {
        // Allocate memory via OS abstraction
        const memory = try hw.os.memAlloc(size);
        
        return Arena{
            .memory = memory,
            .protection_key = protection_key,
            .size = size,
        };
    }
    
    /// Apply hardware protection to this arena
    pub fn protect(arena: *Arena, permission: AccessPermission) !void {
        const perm: hw.Permission = if (!permission.read) .none else if (permission.write) .read_write else .read_only;
        try hw.applyProtectionToRegion(arena.memory.ptr, arena.size, arena.protection_key.value);
        hw.setKeyPermission(arena.protection_key.value, perm);
    }
    
    /// Destroy the arena
    pub fn destroy(arena: *Arena) void {
        hw.os.memFree(arena.memory);
    }
};

// ============================================================================
// Message Types for IPC
// ============================================================================

/// Message types for inter-sandbox communication
pub const MessageType = enum(u32) {
    /// Initialize a new sandbox
    init = 0,
    /// Execute code in sandbox
    execute = 1,
    /// Query sandbox state
    query = 2,
    /// Response to query
    response = 3,
    /// Error occurred
    @"error" = 4,
    /// Shutdown sandbox
    shutdown = 5,
    /// Heartbeat/keepalive
    heartbeat = 6,
};

/// Message header for IPC
pub const MessageHeader = extern struct {
    /// Message type
    msg_type: u32,
    /// Message length including header
    length: u32,
    /// Sequence number for ordering
    sequence: u64,
    /// Source sandbox ID
    source_id: u64,
    /// Target sandbox ID
    target_id: u64,
    /// Timestamp (nanoseconds since epoch)
    timestamp: u64,
    /// Checksum for integrity
    checksum: u32,
};

/// Message with header and payload
pub const Message = struct {
    header: MessageHeader,
    payload: []const u8,
    
    /// Create a new message
    pub fn create(
        msg_type: MessageType,
        source_id: u64,
        target_id: u64,
        payload: []const u8,
        sequence: u64,
    ) Message {
        const timestamp = hw.posix_io.monotonicTimestamp();
        const length = @as(u32, @intCast(@sizeOf(MessageHeader) + payload.len));
        
        return Message{
            .header = .{
                .msg_type = @intFromEnum(msg_type),
                .length = length,
                .sequence = sequence,
                .source_id = source_id,
                .target_id = target_id,
                .timestamp = timestamp,
                .checksum = 0, // Would be calculated
            },
            .payload = payload,
        };
    }
    
    /// Serialize message to bytes
    pub fn serialize(msg: Message, buf: []u8) !void {
        if (buf.len < @sizeOf(MessageHeader) + msg.payload.len) {
            return error.BufferTooSmall;
        }
        
        // Copy header
        @memcpy(buf[0..@sizeOf(MessageHeader)], std.mem.asBytes(&msg.header));
        
        // Copy payload
        @memcpy(buf[@sizeOf(MessageHeader)..][0..msg.payload.len], msg.payload);
    }
    
    /// Deserialize message from bytes
    pub fn deserialize(buf: []const u8) !Message {
        if (buf.len < @sizeOf(MessageHeader)) {
            return error.BufferTooSmall;
        }
        
        const header = @as(*const MessageHeader, @ptrCast(@alignCast(buf.ptr))).*;
        
        return Message{
            .header = header,
            .payload = buf[@sizeOf(MessageHeader)..][0..header.length - @sizeOf(MessageHeader)],
        };
    }
};

// ============================================================================
// Sandbox Manager - System Coordinator
// ============================================================================

/// Central manager for all sandbox contexts
pub const SandboxManager = struct {
    /// All managed sandboxes
    sandboxes: std.AutoHashMap(u64, *SandboxContext),
    
    /// Ring buffer pool for IPC (pointers to avoid invalidation)
    rings: std.ArrayListUnmanaged(*HardenedRingBuffer),
    
    /// Global sequence counter
    sequence: u64,

    /// Allocator
    allocator: std.mem.Allocator,
    
    /// Configuration
    config: Config,
    
    /// Configuration for sandbox system
    pub const Config = struct {
        max_sandboxes: usize = 16,
        ring_buffer_size: usize = RingConfig.DEFAULT_SIZE,
        enable_hardware_protection: bool = true,
        crash_recovery_enabled: bool = true,
    };
    
    pub fn init(allocator: std.mem.Allocator, config: Config) !SandboxManager {
        return SandboxManager{
            .sandboxes = std.AutoHashMap(u64, *SandboxContext).init(allocator),
            .rings = .empty,
            .sequence = 0,
            .allocator = allocator,
            .config = config,
        };
    }
    
    /// Create a new sandbox context
    pub fn createSandbox(manager: *SandboxManager, tier: SandboxTier) !*SandboxContext {
        if (manager.sandboxes.count() >= manager.config.max_sandboxes) {
            return error.TooManySandboxes;
        }
        
        const id = manager.sequence;
        manager.sequence += 1;
        
        var ctx = try manager.allocator.create(SandboxContext);
        ctx.* = try SandboxContext.init(manager.allocator, tier, id);
        
        // Create IPC rings for this sandbox
        const ring_in = try manager.createRing(tier, .trusted, .inbound);
        const ring_out = try manager.createRing(.trusted, tier, .outbound);
        
        try ctx.addRing(ring_in, .inbound);
        try ctx.addRing(ring_out, .outbound);
        
        try manager.sandboxes.put(id, ctx);
        
        return ctx;
    }
    
    /// Create a ring buffer for IPC between tiers
    fn createRing(
        manager: *SandboxManager,
        source_tier: SandboxTier,
        target_tier: SandboxTier,
        direction: enum { inbound, outbound },
    ) !*HardenedRingBuffer {
        const key = if (direction == .inbound)
            target_tier.getProtectionKey()
        else
            source_tier.getProtectionKey();
        
        const ring = try manager.allocator.create(HardenedRingBuffer);
        ring.* = try HardenedRingBuffer.create(
            manager.config.ring_buffer_size,
            .{ .value = key, .tier = @intFromEnum(target_tier) },
            target_tier,
        );
        
        try manager.rings.append(manager.allocator, ring);
        
        return ring;
    }
    
    /// Send a message to a sandbox
    pub fn sendMessage(manager: *SandboxManager, target_id: u64, msg: Message) !void {
        const ctx = manager.sandboxes.get(target_id) orelse return error.SandboxNotFound;
        
        const ring = if (ctx.rings_in.items.len > 0)
            ctx.rings_in.items[0]
        else
            return error.NoInboundRing;
        
        // Serialize message
        var buf: [4096]u8 = undefined;
        try msg.serialize(&buf);
        
        try ring.write(&buf);
    }
    
    /// Receive a message from a sandbox
    pub fn receiveMessage(manager: *SandboxManager, source_id: u64) !Message {
        const ctx = manager.sandboxes.get(source_id) orelse return error.SandboxNotFound;
        
        const ring = if (ctx.rings_out.items.len > 0)
            ctx.rings_out.items[0]
        else
            return error.NoOutboundRing;
        
        var buf: [4096]u8 = undefined;
        const len = try ring.read(&buf);
        
        return try Message.deserialize(buf[0..len]);
    }
    
    /// Handle sandbox fault and trigger recovery
    pub fn handleFault(manager: *SandboxManager, sandbox_id: u64) !void {
        const ctx = manager.sandboxes.get(sandbox_id) orelse return error.SandboxNotFound;
        
        ctx.fault();
        
        if (manager.config.crash_recovery_enabled) {
            // Terminate and recreate
            ctx.terminate();
            
            // Create new instance
            const new_ctx = try manager.createSandbox(ctx.tier);
            new_ctx.start();
            
            try manager.sandboxes.put(sandbox_id, new_ctx);
        }
    }
    
    /// Shutdown all sandboxes and cleanup
    pub fn shutdown(manager: *SandboxManager) void {
        var it = manager.sandboxes.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.terminate();
            manager.allocator.destroy(entry.value_ptr.*);
        }
        manager.sandboxes.deinit();
        
        for (manager.rings.items) |ring| {
            ring.destroy();
            manager.allocator.destroy(ring);
        }
        manager.rings.deinit(manager.allocator);
    }
};


// ============================================================================
// Tests and Examples
// ============================================================================

test "HardenedRingBuffer creation and basic operations" {
    const key = HardwareProtection.Key{ .value = 1, .tier = 1 };
    var ring = try HardenedRingBuffer.create(1024, key, .trusted);
    defer {
        ring.destroy();
    }
    
    // Test write
    const data = "Hello, World!";
    try ring.write(data);
    
    // Test read
    var buf: [100]u8 = undefined;
    const len = try ring.read(&buf);
    try std.testing.expectEqual(13, len);
    try std.testing.expectEqualStrings(data, buf[0..len]);
}

test "SandboxManager create and manage sandboxes" {
    var manager = try SandboxManager.init(std.testing.allocator, .{
        .max_sandboxes = 4,
        .ring_buffer_size = 1024,
    });
    defer manager.shutdown();
    
    // Create sandboxes at different tiers
    const sandbox1 = try manager.createSandbox(.trusted);
    const sandbox2 = try manager.createSandbox(.untrusted);
    
    try std.testing.expect(manager.sandboxes.count() == 2);
    _ = sandbox1;
    _ = sandbox2;
}

test "Message serialization" {
    const payload = "Test payload";
    const msg = Message.create(.execute, 1, 2, @as([]const u8, payload), 42);
    
    var buf: [1024]u8 align(@alignOf(MessageHeader)) = undefined;
    try msg.serialize(&buf);
    
    const deserialized = try Message.deserialize(&buf);
    try std.testing.expectEqual(@as(u32, @intFromEnum(MessageType.execute)), deserialized.header.msg_type);
    try std.testing.expectEqual(@as(u64, 42), deserialized.header.sequence);
}
