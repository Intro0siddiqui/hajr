const std = @import("std");
const posix = std.posix;
pub fn main() !void {
    const path = "test.txt";
    const fd = try posix.openat(
        posix.AT.FDCWD,
        path,
        posix.O.RDWR | posix.O.CREAT,
        0o644,
    );
    const file = std.fs.File{ .handle = fd };
    const stat_info = try file.stat();
    std.debug.print("size: {}\n", .{stat_info.size});
    posix.close(fd);
}
