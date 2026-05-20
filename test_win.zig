const std = @import("std");
const windows = std.os.windows;

pub fn main() void {
    _ = windows.VirtualAlloc;
}
