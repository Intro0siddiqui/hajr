const std = @import("std");
pub fn main() !void {
    @fence(.release);
}