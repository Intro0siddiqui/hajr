const std = @import("std");

pub fn main() !void {
    const cpuid = try std.arch.x86.cpuid(7, 0);
    std.debug.print("EBX: {}\n", .{cpuid.ebx});
}
