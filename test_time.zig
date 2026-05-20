const std = @import("std");
pub fn main() !void {
    const t = std.time.nanoTimestamp();
    std.debug.print("time: {}\n", .{t});
}
