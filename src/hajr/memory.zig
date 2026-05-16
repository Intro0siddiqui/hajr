const std = @import("std");
const posix = std.posix;

// ============================================================================
// Hajr Arena Layout Manager (Task 1)
// ============================================================================

pub const PAGE_SIZE: usize = 4096;

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
};

pub const SandboxMemory = struct {
    /// Single contiguous block of memory
    base: [*]align(PAGE_SIZE) u8,
    size: usize,
    layout: ArenaLayout,

    /// Allocate deterministic memory layout mapped by OS-agnostic page allocator
    pub fn create(layout: ArenaLayout) !*SandboxMemory {
        const total_size = layout.totalSize();

        // Use OS-agnostic page allocator to map the single contiguous block directly
        const mapped = try std.heap.page_allocator.alignedAlloc(u8, std.mem.Alignment.fromByteUnits(PAGE_SIZE), total_size);

        const arena = try std.heap.page_allocator.create(SandboxMemory);
        arena.* = SandboxMemory{
            .base = @alignCast(mapped.ptr),
            .size = total_size,
            .layout = layout,
        };

        return arena;
    }

    pub fn destroy(self: *SandboxMemory) void {
        const slice = self.base[0..self.size];
        std.heap.page_allocator.free(slice);
        std.heap.page_allocator.destroy(self);
    }

    /// Segment A: Inbound HardenedRingBuffer
    pub fn getInboundRingSegment(self: *const SandboxMemory) [*]align(PAGE_SIZE) u8 {
        return self.base;
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
