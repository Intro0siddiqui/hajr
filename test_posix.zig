const std = @import("std");
const posix = std.posix;
pub fn main() !void {
    _ = posix.AF.INET6;
    _ = posix.SOCK.DGRAM;
    _ = posix.IPPROTO.UDP;
}
