const std = @import("std");

pub fn main() !void {
    const cpuid = try std.Target.x86.cpuid(7, 0);
    std.debug.print("EBX: {x}\n", .{cpuid.ebx});
}
