const std = @import("std");
const hw = @import("../hw/mod.zig");
const router = @import("router.zig");

// ============================================================================
// Hajr Arena Layout Manager (Task 1)
// ============================================================================

/// Platform page size (4KB on x86_64 Linux, 16KB on ARM64)
pub const PAGE_SIZE: usize = std.heap.page_size_min;

pub const SegmentInfo = struct { offset: usize, size: usize };

pub const ArenaLayout = struct {
    inbound_size: usize,
    outbound_size: usize,
    js_heap_size: usize,

    pub fn alignToPage(size: usize) usize {
        const mask = PAGE_SIZE - 1;
        return (size + mask) & ~mask;
    }

    pub fn totalSize(self: ArenaLayout) usize {
        return alignToPage(self.inbound_size) +
               alignToPage(self.outbound_size) +
               alignToPage(self.js_heap_size);
    }

    pub fn defaultConfig() ArenaLayout {
        return .{
            .inbound_size = 64 * 1024,
            .outbound_size = 64 * 1024,
            .js_heap_size = 8 * 1024 * 1024,
        };
    }

    pub fn generateSegments(self: ArenaLayout) [3]SegmentInfo {
        const inbound_s = alignToPage(self.inbound_size);
        const outbound_s = alignToPage(self.outbound_size);
        const js_heap_s = alignToPage(self.js_heap_size);
        return [_]SegmentInfo{
            .{ .offset = 0, .size = inbound_s },
            .{ .offset = inbound_s, .size = outbound_s },
            .{ .offset = inbound_s + outbound_s, .size = js_heap_s },
        };
    }
};

pub fn isPageAligned(addr: usize) bool {
    return (addr & (PAGE_SIZE - 1)) == 0;
}

pub const SandboxMemory = struct {
    /// Single contiguous block of memory
    base: [*]align(PAGE_SIZE) u8,
    size: usize,
    layout: ArenaLayout,
    protection_key: u32,
    allocator: std.mem.Allocator,

    /// Allocate deterministic memory layout mapped by OS-agnostic page allocator
    pub fn create(allocator: std.mem.Allocator, layout: ArenaLayout) !*SandboxMemory {
        const total_size = layout.totalSize();

        // 1. Allocate hardware protection key
        const token = try hw.compartment.global_allocator.alloc();
        errdefer hw.compartment.global_allocator.free(token);

        // 2. Allocate memory via OS abstraction
        const mapped = try hw.os.memAlloc(total_size);
        errdefer hw.os.memFree(mapped);

        // 3. Apply hardware protection to the entire region
        try hw.applyProtectionToRegion(mapped.ptr, total_size, token.id);

        const arena = try allocator.create(SandboxMemory);
        arena.* = SandboxMemory{
            .base = @alignCast(mapped.ptr),
            .size = total_size,
            .layout = layout,
            .protection_key = token.id,
            .allocator = allocator,
        };

        return arena;
    }

    pub fn destroy(self: *SandboxMemory) void {
        const slice = self.base[0..self.size];

        // 1. Free hardware protection key
        hw.compartment.global_allocator.free(.{ .id = self.protection_key });

        // 2. Free memory via OS abstraction
        hw.os.memFree(slice);
        self.allocator.destroy(self);
    }
pub const SegmentType = enum {
    inbound_ring,
    outbound_ring,
    js_heap,
};

pub const SegmentBounds = struct {
    pointer: hw.pointer.TaggedPointer(u8),
    size: usize,
};

pub fn getSegmentBounds(self: *const SandboxMemory, segment: SegmentType) SegmentBounds {
    const raw_ptr = switch (segment) {
        .inbound_ring => self.base,
        .outbound_ring => self.getOutboundRingSegment(),
        .js_heap => self.getJsHeapSegment(),
    };
    const size = switch (segment) {
        .inbound_ring => ArenaLayout.alignToPage(self.layout.inbound_size),
        .outbound_ring => ArenaLayout.alignToPage(self.layout.outbound_size),
        .js_heap => ArenaLayout.alignToPage(self.layout.js_heap_size),
    };

    return .{
        .pointer = hw.pointer.TaggedPointer(u8).fromRawWithTag(@ptrCast(raw_ptr), @intCast(self.protection_key & 0xF)),
        .size = size,
    };
}

pub fn getRingMetadata(self: *const SandboxMemory, segment: SegmentType) ?*router.RingMetadata {
    const bounds = self.getSegmentBounds(segment);
    if (segment == .js_heap) return null;
    return @ptrCast(@alignCast(bounds.pointer.toRaw()));
}

pub fn getJsHeapPointer(self: *const SandboxMemory) hw.pointer.TaggedPointer(u8) {
    return hw.pointer.TaggedPointer(u8).fromRawWithTag(@ptrCast(self.getJsHeapSegment()), @intCast(self.protection_key & 0xF));
}

pub fn getJsHeapSize(self: *const SandboxMemory) usize {
    return ArenaLayout.alignToPage(self.layout.js_heap_size);
}

pub fn validatePointer(self: *const SandboxMemory, segment: SegmentType, ptr: [*]const u8, len: usize) bool {
    const bounds = self.getSegmentBounds(segment);
    const start = @intFromPtr(ptr);
    const end = start + len;
    const b_start = @intFromPtr(bounds.pointer.toRaw());
    const b_end = b_start + bounds.size;
    return start >= b_start and end <= b_end;
}

    /// Segment B: Outbound HardenedRingBuffer
    pub fn getOutboundRingSegment(self: *const SandboxMemory) [*]align(PAGE_SIZE) u8 {
        const offset = ArenaLayout.alignToPage(self.layout.inbound_size);
        const ptr: [*]u8 = @ptrFromInt(@intFromPtr(self.base) + offset);
        return @alignCast(ptr);
    }

    /// Segment C: SpiderMonkey JS Heap Arena
    /// Internal pointers passed to FFI strictly bounded to this Segment
    pub fn getJsHeapSegment(self: *const SandboxMemory) [*]align(PAGE_SIZE) u8 {
        const offset = ArenaLayout.alignToPage(self.layout.inbound_size) +
                       ArenaLayout.alignToPage(self.layout.outbound_size);
        const ptr: [*]u8 = @ptrFromInt(@intFromPtr(self.base) + offset);
        return @alignCast(ptr);
    }
};
