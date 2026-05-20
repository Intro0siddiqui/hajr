const std = @import("std");

pub fn main() void {
    std.debug.print("page size: {any}\n", .{std.mem.page_size});
}
