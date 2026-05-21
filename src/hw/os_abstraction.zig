//! Unified OS abstraction layer for Hajr.
//!
//! All OS-specific syscalls (memory mapping, file I/O, timestamps, exception handling)
//! go through this module. This allows the rest of the codebase to be OS-agnostic.
//!
//! On POSIX (Linux, macOS, FreeBSD): wraps std.posix and std.posix.system
//! On Windows: wraps std.os.windows (VirtualAlloc, CreateFileW, AddVectoredExceptionHandler)

const std = @import("std");
const builtin = @import("builtin");
const windows = @import("windows.zig");

// ============================================================================
// OS Handle Type
// ============================================================================

/// Platform-specific handle type.
/// On POSIX: file descriptor (i32)
/// On Windows: HANDLE (opaque pointer)
pub const OsHandle = if (builtin.os.tag == .windows)
    windows.file_io.OsHandle
else
    std.posix.fd_t;

/// Sentinel value for an invalid handle.
pub const INVALID_HANDLE: OsHandle = if (builtin.os.tag == .windows)
    windows.file_io.INVALID_HANDLE
else
    -1;

// ============================================================================
// Memory Management
// ============================================================================

/// Allocate a page-aligned anonymous memory region.
/// Equivalent to: mmap(MAP_PRIVATE | MAP_ANONYMOUS) on POSIX
/// Equivalent to: VirtualAlloc(MEM_COMMIT, PAGE_READWRITE) on Windows
pub fn memAlloc(size: usize) ![]align(4096) u8 {
    if (builtin.os.tag == .windows) {
        return windows.memory.memAlloc(size);
    } else {
        const prot = std.posix.PROT{ .READ = true, .WRITE = true };
        const flags = std.posix.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true };
        const mapped = try std.posix.mmap(null, size, prot, flags, -1, 0);
        return @as([*]align(4096) u8, @ptrCast(@alignCast(mapped.ptr)))[0..mapped.len];
    }
}

/// Free a previously allocated memory region.
/// Equivalent to: munmap on POSIX
/// Equivalent to: VirtualFree(MEM_RELEASE) on Windows
pub fn memFree(region: []align(4096) u8) void {
    if (builtin.os.tag == .windows) {
        windows.memory.memFree(region);
        return;
    } else {
        std.posix.munmap(region);
    }
}

/// Change protection on a memory region.
/// Equivalent to: mprotect on POSIX
/// Equivalent to: VirtualProtect on Windows
pub fn memProtect(ptr: [*]u8, len: usize, read: bool, write: bool) !void {
    if (builtin.os.tag == .windows) {
        return windows.memory.memProtect(ptr, len, read, write);
    } else {
        var prot = std.os.linux.PROT{};
        if (read) prot.READ = true;
        if (write) prot.WRITE = true;
        const rc = std.os.linux.mprotect(ptr, len, prot);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.ProtectionFailed;
    }
}

// ============================================================================
// MPK Management
// ============================================================================

pub const PkeyError = error{
    InvalidArgument,
    NoSpace,
    SystemNotSupported,
    Unexpected,
};

pub const PkeyFreeError = error{
    InvalidArgument,
    SystemNotSupported,
    Unexpected,
};

/// Allocate a hardware memory protection key (PKEY).
pub fn pkeyAlloc(flags: u32, access_rights: u32) PkeyError!i32 {
    if (builtin.os.tag != .linux) return error.SystemNotSupported;

    const res = std.os.linux.syscall2(.pkey_alloc, flags, access_rights);
    
    if (std.os.linux.errno(res) != .SUCCESS) {
        const err = std.os.linux.errno(res);
        return switch (err) {
            .INVAL => error.InvalidArgument,
            .NOSPC => error.NoSpace,
            .NOSYS => error.SystemNotSupported,
            else => error.Unexpected,
        };
    }
    return @intCast(res);
}

/// Free a previously allocated hardware memory protection key (PKEY).
pub fn pkeyFree(pkey: i32) PkeyFreeError!void {
    if (builtin.os.tag != .linux) return error.SystemNotSupported;

    const res = std.os.linux.syscall1(.pkey_free, @as(u64, @intCast(pkey)));
    
    if (std.os.linux.errno(res) != .SUCCESS) {
        const err = std.os.linux.errno(res);
        return switch (err) {
            .INVAL => error.InvalidArgument,
            .NOSYS => error.SystemNotSupported,
            else => error.Unexpected,
        };
    }
}

/// Apply a protection key to a memory region (pkey_mprotect).
pub fn pkeyMprotect(ptr: [*]u8, len: usize, prot: std.os.linux.PROT, key: u32) !void {
    if (builtin.os.tag != .linux) return error.SystemNotSupported;

    const prot_val: u32 = @bitCast(prot);
    const res = std.os.linux.syscall6(
        .pkey_mprotect,
        @intFromPtr(ptr),
        len,
        prot_val,
        key,
        0,
        0,
    );

    if (std.os.linux.errno(res) != .SUCCESS) return error.ProtectionFailed;
}

// ============================================================================
// File I/O
// ============================================================================

/// Open a file with read/write access, creating it if it doesn't exist.
pub fn fileOpen(path: []const u8) !OsHandle {
    if (builtin.os.tag == .windows) {
        return windows.file_io.fileOpen(path);
    } else {
        return try std.posix.openat(
            std.posix.AT.FDCWD,
            path,
            .{ .ACCMODE = .RDWR, .CREAT = true },
            0o644,
        );
    }
}

/// Close a file handle.
pub fn fileClose(handle: OsHandle) void {
    if (builtin.os.tag == .windows) {
        windows.file_io.fileClose(handle);
        return;
    } else {
        _ = std.posix.system.close(handle);
    }
}

/// Truncate a file to a given size.
pub fn fileTruncate(handle: OsHandle, size: u64) !void {
    if (builtin.os.tag == .windows) {
        return windows.file_io.fileTruncate(handle, size);
    } else {
        const res = std.posix.system.ftruncate(handle, @as(i64, @intCast(size)));
        if (std.posix.errno(res) != .SUCCESS) return error.TruncateFailed;
    }
}

/// Write data to a file at a given offset. Returns bytes written.
pub fn fileWrite(handle: OsHandle, data: []const u8, offset: u64) !u64 {
    if (builtin.os.tag == .windows) {
        return windows.file_io.fileWrite(handle, data, offset);
    } else {
        const bytes = std.posix.system.pwrite(handle, data.ptr, data.len, @as(i64, @intCast(offset)));
        if (bytes < 0) return switch (std.posix.errno(bytes)) {
            .BADF => error.InvalidFileDescriptor,
            .INVAL => error.InvalidArgument,
            .IO => error.InputOutput,
            .NOSPC => error.NoSpaceLeft,
            else => error.WriteFailed,
        };
        return @as(u64, @intCast(bytes));
    }
}

/// Read data from a file at a given offset. Returns bytes read.
pub fn fileRead(handle: OsHandle, buffer: []u8, offset: u64) !u64 {
    if (builtin.os.tag == .windows) {
        return windows.file_io.fileRead(handle, buffer, offset);
    } else {
        const bytes = std.posix.system.pread(handle, buffer.ptr, buffer.len, @as(i64, @intCast(offset)));
        if (bytes < 0) return switch (std.posix.errno(bytes)) {
            .BADF => error.InvalidFileDescriptor,
            .INVAL => error.InvalidArgument,
            .IO => error.InputOutput,
            else => error.ReadFailed,
        };
        return @as(u64, @intCast(bytes));
    }
}

// ============================================================================
// Time
// ============================================================================

/// Get a monotonic timestamp in nanoseconds.
pub fn monotonicTimestamp() u64 {
    if (builtin.os.tag == .windows) {
        return windows.time.monotonicTimestamp();
    } else {
        var ts: std.posix.system.timespec = undefined;
        _ = std.posix.system.clock_gettime(std.posix.system.CLOCK.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
    }
}

// ============================================================================
// Fault Handling
// ============================================================================

/// Information about a hardware memory fault.
pub const FaultInfo = struct {
    /// The memory address that caused the fault.
    address: usize,
    /// Whether the fault was caused by a write access.
    is_write: bool,
    /// Whether the fault was caused by an execute access.
    is_exec: bool,
};

/// Callback type for fault handlers.
pub const FaultHandlerFn = *const fn (info: FaultInfo) callconv(.C) void;

/// Register a handler for hardware memory protection faults.
/// On POSIX: registers sigaction for SIGSEGV and SIGBUS.
/// On Windows: registers AddVectoredExceptionHandler for EXCEPTION_ACCESS_VIOLATION.
pub fn registerFaultHandler(handler: FaultHandlerFn) void {
    if (builtin.os.tag == .windows) {
        windows.exception.registerFaultHandler(handler);
    } else {
        const exception = @import("exception.zig");
        exception.registerCallback(handler);
        exception.init();
    }
}

/// Exit the process with a given code.
pub fn exitProcess(code: u8) noreturn {
    if (builtin.os.tag == .windows) {
        windows.time.exitProcess(code);
    } else {
        std.posix.exit(code);
    }
}
