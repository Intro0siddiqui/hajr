const std = @import("std");
pub fn main() void {
    var hm = std.AutoHashMap(u64, u64).init(std.heap.page_allocator);
    _ = hm;
}
