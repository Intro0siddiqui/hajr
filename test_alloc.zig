const std = @import("std");

pub fn main() !void {
    const size = 1024 * 1024;
    const memory = try std.heap.page_allocator.alignedAlloc(u8, std.mem.Alignment.fromByteUnits(4096), size);
    std.debug.print("Allocated {}\n", .{memory.len});
    std.heap.page_allocator.free(memory);
}
