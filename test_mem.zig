const std = @import("std");

pub fn main() void {
    // Try different locations for page_size
    // std.mem.page_size was a thing in some versions
    // std.os.page_size
    // std.posix.getPageSize()
    
    // In 0.16.0, let's see what's in std.mem
    // We can use @hasDecl
    if (@hasDecl(std.mem, "page_size")) {
        std.debug.print("std.mem.page_size exists\n", .{});
    } else {
        std.debug.print("std.mem.page_size does NOT exist\n", .{});
    }
}
