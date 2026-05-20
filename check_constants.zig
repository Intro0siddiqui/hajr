const std = @import("std");

pub fn main() !void {
    const linux = std.os.linux;
    if (@hasDecl(linux, "SEGV_PKUERR")) {
        std.debug.print("linux.SEGV_PKUERR: {}\n", .{linux.SEGV_PKUERR});
    } else {
        std.debug.print("linux.SEGV_PKUERR: not found\n", .{});
    }

    if (@hasDecl(linux, "SEGV_MTESERR")) {
        std.debug.print("linux.SEGV_MTESERR: {}\n", .{linux.SEGV_MTESERR});
    } else {
        std.debug.print("linux.SEGV_MTESERR: not found\n", .{});
    }

    if (@hasDecl(linux, "SEGV_MTEAERR")) {
        std.debug.print("linux.SEGV_MTEAERR: {}\n", .{linux.SEGV_MTEAERR});
    } else {
        std.debug.print("linux.SEGV_MTEAERR: not found\n", .{});
    }
}
