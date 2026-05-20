const std = @import("std");

pub fn main() void {
    std.debug.print("page size: {any}\n", .{std.heap.pageSize()});
    std.debug.print("page size min: {any}\n", .{std.heap.page_size_min});
}
