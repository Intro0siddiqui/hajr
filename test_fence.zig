const std = @import("std");
pub fn main() !void {
    std.atomic.fence(.release);
}