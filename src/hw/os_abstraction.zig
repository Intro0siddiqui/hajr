const std = @import("std");
const builtin = @import("builtin");
const windows = @import("windows.zig");

pub const OsHandle = if (builtin.os.tag == .windows)
    windows.file_io.OsHandle
else
    std.posix.fd_t;

pub const INVALID_HANDLE: OsHandle = if (builtin.os.tag == .windows)
    windows.file_io.INVALID_HANDLE
else
    -1;

const page_size = std.heap.page_size_min;

pub fn memAlloc(size: usize) ![]align(page_size) u8 {
    if (comptime builtin.os.tag == .windows) {
        return windows.memory.memAlloc(size);
    }
    const aligned_size = std.mem.alignForward(usize, size, page_size);
    const prot = std.posix.PROT{ .READ = true, .WRITE = true };
    const flags = std.posix.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    const total = aligned_size + 2 * page_size;
    const mapped = try std.posix.mmap(null, total, prot, flags, -1, 0);
    const guard_flags = std.posix.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = true };
    _ = try std.posix.mmap(mapped.ptr, page_size, std.posix.PROT{}, guard_flags, -1, 0);
    const after: [*]align(page_size) u8 = @alignCast(mapped.ptr + page_size + aligned_size);
    _ = try std.posix.mmap(after, page_size, std.posix.PROT{}, guard_flags, -1, 0);
    const usable: [*]align(page_size) u8 = @alignCast(mapped.ptr + page_size);
    return usable[0..size];
}

pub fn memFree(region: []align(page_size) u8) void {
    if (comptime builtin.os.tag == .windows) {
        windows.memory.memFree(region);
        return;
    }
    const aligned_size = std.mem.alignForward(usize, region.len, page_size);
    const full_base = @as([*]align(page_size) u8, @ptrFromInt(@intFromPtr(region.ptr) - page_size));
    const total = aligned_size + 2 * page_size;
    std.posix.munmap(full_base[0..total]);
}

pub fn memProtect(ptr: [*]u8, len: usize, read: bool, write: bool) !void {
    if (comptime builtin.os.tag == .windows) {
        return windows.memory.memProtect(ptr, len, read, write);
    }
    var prot = std.posix.system.PROT{};
    if (read) prot.READ = true;
    if (write) prot.WRITE = true;
    const rc = std.posix.system.mprotect(@ptrCast(@alignCast(ptr)), len, prot);
    if (std.posix.errno(rc) != .SUCCESS) return error.ProtectionFailed;
}

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

pub fn pkeyAlloc(flags: u32, access_rights: u32) PkeyError!i32 {
    if (comptime builtin.os.tag != .linux) return error.SystemNotSupported;
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

pub fn pkeyFree(pkey: i32) PkeyFreeError!void {
    if (comptime builtin.os.tag != .linux) return error.SystemNotSupported;
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

pub fn pkeyMprotect(ptr: [*]u8, len: usize, prot: std.posix.PROT, key: u32) !void {
    if (comptime builtin.os.tag != .linux) return error.SystemNotSupported;
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

pub fn fileClose(handle: OsHandle) void {
    if (builtin.os.tag == .windows) {
        windows.file_io.fileClose(handle);
        return;
    }
    _ = std.posix.system.close(handle);
}

pub fn fileTruncate(handle: OsHandle, size: u64) !void {
    if (builtin.os.tag == .windows) {
        return windows.file_io.fileTruncate(handle, size);
    }
    const res = std.posix.system.ftruncate(handle, @as(i64, @intCast(size)));
    if (std.posix.errno(res) != .SUCCESS) return error.TruncateFailed;
}

pub fn fileWrite(handle: OsHandle, data: []const u8, offset: u64) !u64 {
    if (builtin.os.tag == .windows) {
        return windows.file_io.fileWrite(handle, data, offset);
    }
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

pub fn fileRead(handle: OsHandle, buffer: []u8, offset: u64) !u64 {
    if (builtin.os.tag == .windows) {
        return windows.file_io.fileRead(handle, buffer, offset);
    }
    const bytes = std.posix.system.pread(handle, buffer.ptr, buffer.len, @as(i64, @intCast(offset)));
    if (bytes < 0) return switch (std.posix.errno(bytes)) {
        .BADF => error.InvalidFileDescriptor,
        .INVAL => error.InvalidArgument,
        .IO => error.InputOutput,
        else => error.ReadFailed,
    };
    return @as(u64, @intCast(bytes));
}

pub fn monotonicTimestamp() u64 {
    if (builtin.os.tag == .windows) {
        return windows.time.monotonicTimestamp();
    }
    var ts: std.posix.system.timespec = undefined;
    _ = std.posix.system.clock_gettime(std.posix.system.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub const FaultInfo = extern struct {
    address: usize,
    is_write: bool,
    is_exec: bool,
};

pub const FaultHandlerFn = *const fn (info: FaultInfo) callconv(.c) void;

pub fn registerFaultHandler(handler: FaultHandlerFn) void {
    if (builtin.os.tag == .windows) {
        windows.exception.registerFaultHandler(handler);
    } else {
        const exception = @import("exception.zig");
        exception.registerCallback(handler);
        exception.init();
    }
}

pub fn exitProcess(code: u8) noreturn {
    if (builtin.os.tag == .windows) {
        windows.time.exitProcess(code);
    } else {
        std.posix.exit(code);
    }
}

// ============================================================================
// OS-Level Process Lockdown
// ============================================================================

/// Errors that can occur during process lockdown.
pub const LockdownError = error{
    UnsupportedPlatform,
    PrctlFailed,
    SeccompFailed,
    LandlockNotSupported,
    LandlockFailed,
    KernelTooOld,
    SandboxInitFailed,
    MitigationPolicyFailed,
};

/// Seal the current process for all future operations.
///
/// After this call:
/// - Linux: seccomp-BPF whitelist allows only essential syscalls;
///          Landlock rules deny all filesystem access.
/// - macOS: Seatbelt profile denies all default operations.
/// - Windows: Mitigation policies disable win32k, enforce strict handles, etc.
///
/// Must be called after all initialization is complete and before
/// processing any untrusted data.
pub fn sealProcess() LockdownError!void {
    switch (builtin.os.tag) {
        .linux => {
            const seccomp = @import("seccomp.zig");
            const landlock = @import("landlock.zig");
            try seccomp.install(.jit_allowed);
            try landlock.denyAllAccess();
        },
        .macos => {
            const seatbelt = @import("seatbelt.zig");
            try seatbelt.apply(.no_write);
        },
        .windows => {
            const mitigations = @import("windows/mitigations.zig");
            try mitigations.apply(.{});
            try mitigations.applyLowIntegrity();
        },
        else => return error.UnsupportedPlatform,
    }
}

pub const FUTEX_WAIT_PRIVATE: u32 = 128; // FUTEX_WAIT (0) | FUTEX_PRIVATE_FLAG (128)
pub const FUTEX_WAKE_PRIVATE: u32 = 129; // FUTEX_WAKE (1) | FUTEX_PRIVATE_FLAG (128)

pub fn futexWait(addr: *volatile u32, expected: u32) void {
    if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.syscall4(
            .futex,
            @intFromPtr(addr),
            FUTEX_WAIT_PRIVATE,
            expected,
            0,
        );
    }
}

pub fn futexWake(addr: *volatile u32, count: u32) void {
    if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.syscall3(
            .futex,
            @intFromPtr(addr),
            FUTEX_WAKE_PRIVATE,
            count,
        );
    }
}

