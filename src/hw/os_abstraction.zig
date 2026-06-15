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

pub fn fileSeek(handle: OsHandle, offset: i64, origin: SeekOrigin) !u64 {
    if (comptime builtin.os.tag == .windows) {
        return windows.file_io.fileSeek(handle, offset, @intFromEnum(origin));
    } else {
        const whence: c_int = switch (origin) {
            .start => @as(c_int, @intCast(std.posix.SEEK.SET)),
            .current => @as(c_int, @intCast(std.posix.SEEK.CUR)),
            .end => @as(c_int, @intCast(std.posix.SEEK.END)),
        };
        const rc = if (comptime std.posix.lfs64_abi)
            std.posix.system.lseek64(handle, offset, whence)
        else
            std.posix.system.lseek(handle, offset, whence);
        const err = std.posix.errno(rc);
        if (err != .SUCCESS) return switch (err) {
            .BADF => error.InvalidFileDescriptor,
            .INVAL => error.InvalidArgument,
            .SPIPE => error.Unseekable,
            .NXIO => error.NoDevice,
            else => error.SeekFailed,
        };
        return @as(u64, @intCast(rc));
    }
}

pub fn fileStat(path: []const u8) !FileInfo {
    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    const io = threaded_io.io();

    const dir = std.Io.Dir.cwd();
    const stat = try dir.statFile(io, path, .{});

    const mtime_sec = @as(i64, @intCast(@divTrunc(stat.mtime.nanoseconds, std.time.ns_per_s)));
    const atime_sec = if (stat.atime) |at|
        @as(i64, @intCast(@divTrunc(at.nanoseconds, std.time.ns_per_s)))
    else
        0;
    const ctime_sec = @as(i64, @intCast(@divTrunc(stat.ctime.nanoseconds, std.time.ns_per_s)));

    return FileInfo{
        .size = stat.size,
        .mtime = mtime_sec,
        .atime = atime_sec,
        .ctime = ctime_sec,
        .is_dir = stat.kind == .directory,
    };
}

pub fn fileAccess(path: []const u8, mode: AccessMode) !bool {
    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    const io = threaded_io.io();

    const dir = std.Io.Dir.cwd();
    const opts = switch (mode) {
        .exists => std.Io.Dir.AccessOptions{},
        .read => std.Io.Dir.AccessOptions{ .read = true },
        .write => std.Io.Dir.AccessOptions{ .write = true },
        .execute => std.Io.Dir.AccessOptions{ .execute = true },
    };
    dir.access(io, path, opts) catch return false;
    return true;
}

pub fn fileUnlink(path: []const u8) !void {
    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    const io = threaded_io.io();

    const dir = std.Io.Dir.cwd();
    try dir.deleteFile(io, path);
}

pub fn fileMkdir(path: []const u8) !void {
    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    const io = threaded_io.io();

    const dir = std.Io.Dir.cwd();
    try dir.createDir(io, path, std.Io.Dir.Permissions.default_dir);
}

pub fn monotonicTimestamp() u64 {
    if (builtin.os.tag == .windows) {
        return windows.time.monotonicTimestamp();
    }
    var ts: std.posix.system.timespec = undefined;
    _ = std.posix.system.clock_gettime(std.posix.system.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn getMonotonicTime() f64 {
    return @as(f64, @floatFromInt(monotonicTimestamp())) / 1e9;
}

pub const SeekOrigin = enum(i32) {
    start = 0,
    current = 1,
    end = 2,
};

pub const FileInfo = extern struct {
    size: u64,
    mtime: i64,
    atime: i64,
    ctime: i64,
    is_dir: bool,
};

pub const AccessMode = enum(u32) {
    exists = 0,
    read = 1,
    write = 2,
    execute = 4,
};


pub const FaultInfo = extern struct {
    address: usize,
    is_write: bool,
    is_exec: bool,
    is_pac_fault: bool = false,
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
        std.process.exit(code);
    }
}

// ============================================================================
// OS-Level Process Lockdown
// ============================================================================

/// Process types for per-process sandboxing.
pub const ProcessType = enum(u32) {
    web = 0,
    network = 1,
    gpu = 2,

    pub fn fromInt(value: u32) ProcessType {
        return @enumFromInt(value);
    }
};

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
    TokenOpenFailed,
    OutOfMemory,
};

/// Per-process Landlock path rules for Linux.
const web_landlock_rules = if (builtin.os.tag == .linux) &[_]@import("landlock.zig").PathRule{
    // Fonts
    .{ .path = "/usr/share/fonts", .read = true },
    .{ .path = "/usr/local/share/fonts", .read = true },
    .{ .path = "/etc/fonts", .read = true },
    // DNS resolution
    .{ .path = "/etc/resolv.conf", .read = true },
    .{ .path = "/etc/hosts", .read = true },
    // Profile + caches
    .{ .path = "/tmp/zawra-profile", .read = true, .write = true },
    .{ .path = "/tmp", .read = true, .write = true },
} else undefined;

const network_landlock_rules = if (builtin.os.tag == .linux) &[_]@import("landlock.zig").PathRule{
    // Profile + caches
    .{ .path = "/tmp/zawra-profile", .read = true, .write = true },
    .{ .path = "/tmp", .read = true, .write = true },
    // DNS resolution
    .{ .path = "/etc/resolv.conf", .read = true },
    .{ .path = "/etc/hosts", .read = true },
    // TLS certificates
    .{ .path = "/etc/ssl", .read = true },
    .{ .path = "/etc/ssl/certs", .read = true },
    .{ .path = "/etc/pki", .read = true },
} else undefined;

const gpu_landlock_rules = if (builtin.os.tag == .linux) &[_]@import("landlock.zig").PathRule{
    // GPU device access
    .{ .path = "/dev/dri", .read = true, .write = true },
    // Profile
    .{ .path = "/tmp/zawra-profile", .read = true, .write = true },
} else undefined;

/// Seal the current process for all future operations.
///
/// After this call:
/// - Linux: seccomp-BPF whitelist allows only essential syscalls;
///          Landlock rules deny unauthorized filesystem access.
/// - macOS: Seatbelt profile denies all default operations.
/// - Windows: Mitigation policies disable win32k, enforce strict handles, etc.
///
/// Must be called after all initialization is complete and before
/// processing any untrusted data.
pub fn sealProcess(process_type: ProcessType, debug: bool) LockdownError!void {
    switch (builtin.os.tag) {
        .linux => {
            const seccomp = @import("seccomp.zig");
            const landlock = @import("landlock.zig");

            const filter_kind: seccomp.FilterKind = if (debug) switch (process_type) {
                .web => .web_process_debug,
                .network => .network_process_debug,
                .gpu => .gpu_process_debug,
            } else switch (process_type) {
                .web => .web_process,
                .network => .network_process,
                .gpu => .gpu_process,
            };
            try seccomp.install(filter_kind);

            const rules = switch (process_type) {
                .web => web_landlock_rules,
                .network => network_landlock_rules,
                .gpu => gpu_landlock_rules,
            };
            try landlock.denyWithExceptions(rules);
        },
        .macos => {
            const seatbelt = @import("seatbelt.zig");
            const profile: seatbelt.Profile = switch (process_type) {
                .web => .web_process,
                .network => .network_process,
                .gpu => .gpu_process,
            };
            try seatbelt.apply(profile);
        },
        .windows => {
            const mitigations = @import("windows/mitigations.zig");
            const profile: mitigations.ProcessMitigationProfile = switch (process_type) {
                .web => .web_process,
                .network => .network_process,
                .gpu => .gpu_process,
            };
            try mitigations.apply(profile.flags());
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

// ============================================================================
// PAC (Pointer Authentication) Linux Helpers
// ============================================================================

/// HWCAP flags for PAC detection (from Linux kernel headers)
pub const HWCAP_PACA: u32 = 1 << 16; // Hardware address authentication
pub const HWCAP_PACG: u32 = 1 << 17; // Hardware generic authentication

/// Read the auxiliary vector (AT_HWCAP) to detect PAC support.
/// Returns 0 on non-Linux platforms.
pub fn getHwcap() u32 {
    if (comptime builtin.os.tag != .linux) return 0;
    return @intCast(std.os.linux.getauxval(std.os.linux.elf.AT_HWCAP));
}

/// prctl option values for PAC key management
const PR_PAC_RESET_KEYS: u32 = 51;
const PR_PAC_APIAKEY: u64 = 1;
const PR_PAC_APIBKEY: u64 = 1 << 1;
const PR_PAC_APDAKEY: u64 = 1 << 2;
const PR_PAC_APDBKEY: u64 = 1 << 3;

pub const PacResetError = error{
    InvalidArgument,
    SystemNotSupported,
    Unexpected,
};

/// Reset all PAC keys to fresh random values (Linux only).
/// Calls: prctl(PR_PAC_RESET_KEYS, mask, 0, 0, 0)
pub fn prctlPacResetKeys(mask: u32) PacResetError!void {
    if (comptime builtin.os.tag != .linux) return error.SystemNotSupported;
    const key_mask: u64 = @as(u64, mask);
    const arg1: u64 = key_mask | PR_PAC_APIAKEY | PR_PAC_APIBKEY | PR_PAC_APDAKEY | PR_PAC_APDBKEY;
    const res = std.os.linux.prctl(@intCast(PR_PAC_RESET_KEYS), arg1, 0, 0, 0);
    if (std.os.linux.errno(res) != .SUCCESS) {
        const err = std.os.linux.errno(res);
        return switch (err) {
            .EINVAL => error.InvalidArgument,
            .NOSYS => error.SystemNotSupported,
            else => error.Unexpected,
        };
    }
}

