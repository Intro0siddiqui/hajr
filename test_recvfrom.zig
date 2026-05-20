const std = @import("std");
const posix = std.posix;
pub fn main() !void {
    var src_addr: posix.sockaddr = undefined;
    var src_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    _ = posix.recvfrom(0, &[_]u8{}, 0, &src_addr, &src_addr_len);
}
