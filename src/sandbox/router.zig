const std = @import("std");
const atomic = std.atomic;
const sandbox = @import("../core/sandbox.zig");

// ============================================================================
// Tier 1 Event Router & Poison Protocol (Tasks 3 & 4)
// ============================================================================

pub const RingMetadata = sandbox.RingMetadata;

/// Request types for browser-level backend routing.
/// These are protocol constants — the actual backends are injected via `BackendHandler`.
pub const RequestType = enum(u32) {
    invalid = 0,
    net_fetch = 1,
    storage_read = 2,
    storage_write = 3,
};

pub const IPCRequest = extern struct {
    request_type: u32,
    payload_length: u32,
    sandbox_id: u64,
};

/// Interface for backend service routing.
/// 
/// These are *pluggable hooks* for browser-level subsystems (e.g. z-net, BrowserDB).
/// Hajr itself only provides the routing fabric and default no-op stubs.
/// The actual backend implementations live in their own repositories and
/// replace `DefaultHandlers` at browser initialization time.
pub const BackendHandler = struct {
    z_fetch: *const fn (sandbox_id: u64, payload: []const u8) void,
    browser_db: *const fn (sandbox_id: u64, payload: []const u8) void,
};

/// Default handlers for testing
pub const DefaultHandlers = BackendHandler{
    .z_fetch = struct {
        fn f(id: u64, p: []const u8) void { _ = id; _ = p; }
    }.f,
    .browser_db = struct {
        fn f(id: u64, p: []const u8) void { _ = id; _ = p; }
    }.f,
};

/// Public descriptor for an outbound ring
pub const OutboundRing = struct {
    base: [*]u8,
    size: usize,
    meta: *sandbox.RingMetadata,
    sandbox_id: u64,
    active: atomic.Value(bool),
};

/// High-performance data-oriented representation of active outbound rings
pub const ActiveRing = struct {
    sandbox_id: u64,
    outbound_base: [*]u8,
    outbound_size: usize,
    outbound_meta: *sandbox.RingMetadata,
    active_ref: *atomic.Value(bool),
};

pub const RingRouter = struct {
    allocator: std.mem.Allocator,
    rings: []ActiveRing,
    ring_count: usize,
    handlers: BackendHandler,
    
    pub const Config = struct {
        max_sandboxes: usize = 16,
        read_buffer_size: usize = std.heap.page_size_min,
    };

    pub fn init(handlers: BackendHandler, config: Config) !*RingRouter {
        const allocator = std.heap.page_allocator;
        const router = try allocator.create(RingRouter);
        router.* = .{
            .allocator = allocator,
            .rings = try allocator.alloc(ActiveRing, config.max_sandboxes),
            .ring_count = 0,
            .handlers = handlers,
        };
        return router;
    }

    pub fn destroy(self: *RingRouter) void {
        self.allocator.free(self.rings);
        self.allocator.destroy(self);
    }

    pub fn registerRing(self: *RingRouter, outbound_ring: *const OutboundRing) !void {
        if (self.ring_count >= self.rings.len) return error.TooManySandboxes;
        
        self.rings[self.ring_count] = .{
            .sandbox_id = outbound_ring.sandbox_id,
            .outbound_base = outbound_ring.base,
            .outbound_size = outbound_ring.size,
            .outbound_meta = outbound_ring.meta,
            .active_ref = &@as(*OutboundRing, @ptrCast(@constCast(outbound_ring))).active,
        };
        self.ring_count += 1;
    }

    pub fn unregisterRing(self: *RingRouter, sandbox_id: u64) void {
        for (0..self.ring_count) |i| {
            if (self.rings[i].sandbox_id == sandbox_id) {
                // Swap with last active ring
                if (i < self.ring_count - 1) {
                    self.rings[i] = self.rings[self.ring_count - 1];
                }
                self.ring_count -= 1;
                return;
            }
        }
    }

    /// Quick scan for poisoned rings
    pub fn checkAllRings(self: *RingRouter) []const u64 {
        // In a real implementation we might return a slice of poisoned IDs
        // For the purpose of the Phase 2 test, we can return a temporary list
        var poisoned_count: usize = 0;
        for (self.rings[0..self.ring_count]) |ring| {
            if (ring.outbound_meta.poison_bit.load(.acquire)) {
                poisoned_count += 1;
            }
        }

        if (poisoned_count == 0) return &[_]u64{};

        const result = self.allocator.alloc(u64, poisoned_count) catch return &[_]u64{};
        var idx: usize = 0;
        for (self.rings[0..self.ring_count]) |ring| {
            if (ring.outbound_meta.poison_bit.load(.acquire)) {
                result[idx] = ring.sandbox_id;
                idx += 1;
            }
        }
        return result;
    }

    /// Lock-free Tier 1 Polling (< 5ns overhead target)
    /// Returns number of requests processed
    pub fn poll(self: *RingRouter) usize {
        var processed: usize = 0;
        // Iterate over linearly contiguous active Hajr outbound rings
        for (self.rings[0..self.ring_count]) |*ring| {
            if (!ring.active_ref.load(.acquire)) continue;

            const meta = ring.outbound_meta;

            // Check if poisoned (fail-fast)
            if (meta.poison_bit.load(.acquire)) {
                continue;
            }

            // TASK 3: Lock-free Event Routing using atomic head/tail
            const read_idx = meta.read_index.load(.acquire);
            const write_idx = meta.write_index.load(.acquire);

            if (write_idx > read_idx) {
                const avail = write_idx - read_idx;
                if (avail < @sizeOf(IPCRequest)) continue;

                const read_pos = read_idx & (ring.outbound_size - 1);
                
                var req: IPCRequest = undefined;
                const req_size = @sizeOf(IPCRequest);

                // Handle split header
                if (read_pos + req_size > ring.outbound_size) {
                    const first_part = ring.outbound_size - read_pos;
                    const second_part = req_size - first_part;
                    @memcpy(std.mem.asBytes(&req)[0..first_part], ring.outbound_base[read_pos .. read_pos + first_part]);
                    @memcpy(std.mem.asBytes(&req)[first_part..req_size], ring.outbound_base[0..second_part]);
                } else {
                    @memcpy(std.mem.asBytes(&req), ring.outbound_base[read_pos .. read_pos + req_size]);
                }

                const req_type = @as(RequestType, @enumFromInt(req.request_type));
                
                // Safety check: ensure payload is available (bounded to prevent overflow)
                const required = req_size + req.payload_length;
                if (avail < required) continue;

                const remaining_after_header = avail - req_size;
                if (req.payload_length > remaining_after_header) continue;

                const payload_pos = (read_pos + req_size) & (ring.outbound_size - 1);
                
                // Handle split payload
                if (payload_pos + req.payload_length > ring.outbound_size) {
                    // Split payload: need a temporary buffer to provide a contiguous slice to handlers
                    // We'll use a stack buffer or the router's allocator if it's too large
                    const first_part = ring.outbound_size - payload_pos;
                    const second_part = req.payload_length - first_part;
                    
                    if (req.payload_length <= 1024) {
                        var temp_payload: [1024]u8 = undefined;
                        @memcpy(temp_payload[0..first_part], ring.outbound_base[payload_pos .. payload_pos + first_part]);
                        @memcpy(temp_payload[first_part..req.payload_length], ring.outbound_base[0..second_part]);
                        self.route(req_type, ring.sandbox_id, temp_payload[0..req.payload_length]);
                    } else {
                        // For large payloads that wrap, allocate
                        const temp_payload = self.allocator.alloc(u8, req.payload_length) catch continue;
                        defer self.allocator.free(temp_payload);
                        @memcpy(temp_payload[0..first_part], ring.outbound_base[payload_pos .. payload_pos + first_part]);
                        @memcpy(temp_payload[first_part..req.payload_length], ring.outbound_base[0..second_part]);
                        self.route(req_type, ring.sandbox_id, temp_payload);
                    }
                } else {
                    // Contiguous payload
                    const payload = ring.outbound_base[payload_pos .. payload_pos + req.payload_length];
                    self.route(req_type, ring.sandbox_id, payload);
                }

                // Advance read index using atomic operations (no mutexes)
                const bytes_processed = req_size + req.payload_length;
                meta.read_index.store(read_idx + bytes_processed, .release);
                processed += 1;
            }
        }
        return processed;
    }

    fn route(self: *RingRouter, req_type: RequestType, sandbox_id: u64, payload: []const u8) void {
        switch (req_type) {
            .net_fetch => self.handlers.z_fetch(sandbox_id, payload),
            .storage_read, .storage_write => self.handlers.browser_db(sandbox_id, payload),
            else => {},
        }
    }
};
