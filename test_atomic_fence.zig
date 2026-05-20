const std = @import("std");
pub fn main() !void {
    @atomicFence(.release);
}