const std = @import("std");
pub fn main() void {
    var list: std.ArrayList(u8) = .empty;
    list.append(std.heap.page_allocator, 5) catch unreachable;
}
