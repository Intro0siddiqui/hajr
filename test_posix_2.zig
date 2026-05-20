const std = @import("std");
const posix = std.posix;
pub fn main() !void {
    _ = posix.IPV6.V6ONLY;
    _ = posix.SOL.SOCKET;
    _ = posix.SO.RCVBUF;
}
