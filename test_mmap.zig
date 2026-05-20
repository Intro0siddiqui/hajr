const std = @import("std");
const posix = std.posix;
pub fn main() !void {
    const size = 4096;
    const prot: posix.PROT = .{ .read = true, .write = true };
    const flags: posix.MAP = .{ .type = .private, .anonymous = true };
    const ptr = try posix.mmap(null, size, prot, flags, -1, 0);
    posix.munmap(ptr);
}
