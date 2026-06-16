//! Portable POSIX abstractions for Hajr.
//!
//! Wraps raw `posix.system.*` calls with clean, safe, and readable APIs.
//! All functions are fully portable across POSIX systems (Linux, macOS, FreeBSD).

const std = @import("std");
const posix = std.posix;

/// Open a file with read/write access, creating it if it doesn't exist.
/// Uses AT.FDCWD (relative to current working directory).
pub fn fileOpen(path: []const u8) !posix.fd_t {
    return posix.openat(
        posix.AT.FDCWD,
        path,
        .{ .ACCMODE = .RDWR, .CREAT = true },
        0o644,
    );
}

/// Close a file descriptor. Never fails in practice; errors are ignored.
pub fn fileClose(fd: posix.fd_t) void {
    _ = posix.system.close(fd);
}

/// Truncate a file to a given size.
pub fn fileTruncate(fd: posix.fd_t, size: u64) !void {
    const res = posix.system.ftruncate(fd, @as(i64, @intCast(size)));
    if (posix.errno(res) != .SUCCESS) {
        return switch (posix.errno(res)) {
            .BADF => error.InvalidFileDescriptor,
            .INVAL => error.InvalidArgument,
            .IO => error.InputOutput,
            .NOSPC => error.NoSpaceLeft,
            else => error.SystemError,
        };
    }
}

/// Write data to a file at a given offset.
/// Returns the number of bytes written.
pub fn fileWrite(fd: posix.fd_t, data: []const u8, offset: u64) !u64 {
    const bytes = posix.system.pwrite(fd, data.ptr, data.len, @as(i64, @intCast(offset)));
    if (bytes < 0) {
        return switch (posix.errno(bytes)) {
            .BADF => error.InvalidFileDescriptor,
            .INVAL => error.InvalidArgument,
            .IO => error.InputOutput,
            .NOSPC => error.NoSpaceLeft,
            .INTR => error.Interrupted,
            else => error.SystemError,
        };
    }
    return @as(u64, @intCast(bytes));
}

/// Read data from a file at a given offset.
/// Returns the number of bytes read (may be less than buffer.len).
pub fn fileRead(fd: posix.fd_t, buffer: []u8, offset: u64) !u64 {
    const bytes = posix.system.pread(fd, buffer.ptr, buffer.len, @as(i64, @intCast(offset)));
    if (bytes < 0) {
        return switch (posix.errno(bytes)) {
            .BADF => error.InvalidFileDescriptor,
            .INVAL => error.InvalidArgument,
            .IO => error.InputOutput,
            .INTR => error.Interrupted,
            else => error.SystemError,
        };
    }
    return @as(u64, @intCast(bytes));
}

/// Get a monotonic timestamp in nanoseconds.
/// Uses CLOCK_MONOTONIC on POSIX systems.
pub fn monotonicTimestamp() u64 {
    var ts: posix.system.timespec = undefined;
    _ = posix.system.clock_gettime(posix.system.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Portable nanosleep using POSIX nanosleep syscall.
pub fn sleepNs(ns: u64) void {
    const sec: i64 = @intCast(ns / std.time.ns_per_s);
    const nsec: i64 = @intCast(ns % std.time.ns_per_s);
    var ts = posix.system.timespec{ .sec = sec, .nsec = nsec };
    _ = posix.system.nanosleep(&ts, null);
}
