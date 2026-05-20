const std = @import("std");
pub fn main() void {
    inline for (std.meta.fields(std.posix.PROT)) |f| {
        @compileLog(f.name);
    }
}
