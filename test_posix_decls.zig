const std = @import("std");

pub fn main() void {
    _ = std.os.linux.STATX.SIZE;
    _ = std.os.linux.AT.EMPTY_PATH;
    _ = std.os.linux.Statx;
}
