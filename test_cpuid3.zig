const std = @import("std");

pub fn main() !void {
    const cpuid = std.Target.x86.cpuid(7, 0);
    std.debug.print("EBX: {}\n", .{cpuid.ebx});
}
