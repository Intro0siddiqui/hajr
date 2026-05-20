const std = @import("std");
pub fn main() !void {
    var v = std.atomic.Value(u64).init(0);
    _ = v.load(.acquire);
}