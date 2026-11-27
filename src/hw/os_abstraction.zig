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

/// True when the target is Android (Zig models Android as Linux + Android ABI).
pub fn isAndroid() bool {
    return builtin.target.abi.isAndroid();
}

// ARM64 UAPI constants (asm/hwcap.h, linux/prctl.h).
const HWCAP2_MTE: usize = @as(usize, 1) << 18;
const PR_GET_TAGGED_ADDR_CTRL: usize = 56;
const PR_TAGGED_ADDR_ENABLE: usize = @as(usize, 1) << 0;

extern "c" fn sysctlbyname(
    name: [*:0]const u8,
    oldp: ?*anyopaque,
    oldlenp: ?*usize,
    newp: ?*const anyopaque,
    newlen: usize,
) c_int;

// 0 = not probed yet, 1 = supported, 2 = unsupported.
var mte_state: std.atomic.Value(u8) = std.atomic.Value(u8).init(0);

/// Runtime MTE capability probe. Hardware tagging is used when:
/// - Linux: The kernel advertises MTE (AT_HWCAP2) *and* tagged user addresses are enabled (PR_GET_TAGGED_ADDR_CTRL).
/// - Darwin (macOS): Apple Silicon M5+ advertises FEAT_MTE4 (EMTE) or FEAT_MTE via sysctl.
/// Cached; racing probes simply compute the same value.
pub fn detectMte() bool {
    if (comptime builtin.cpu.arch != .aarch64) return false;

    const cached = mte_state.load(.acquire);
    if (cached != 0) return cached == 1;

    var supported = false;

    if (comptime builtin.os.tag == .linux) {
        const hwcap2 = std.os.linux.getauxval(std.elf.AT_HWCAP2);
        const rc = std.os.linux.syscall1(.prctl, PR_GET_TAGGED_ADDR_CTRL);
        supported = (hwcap2 & HWCAP2_MTE) != 0 and
            std.os.linux.errno(rc) == .SUCCESS and
            (rc & PR_TAGGED_ADDR_ENABLE) != 0;
    } else if (comptime builtin.os.tag == .macos) {
        var val: c_int = 0;
        var len: usize = @sizeOf(c_int);
        if (sysctlbyname("hw.optional.arm.FEAT_MTE4", &val, &len, null, 0) == 0 and val == 1) {
            supported = true;
        } else if (sysctlbyname("hw.optional.arm.FEAT_MTE", &val, &len, null, 0) == 0 and val == 1) {
            supported = true;
        }
    }

    mte_state.store(if (supported) 1 else 2, .release);
    return supported;
}

pub fn memAlloc(size: usize) ![]align(page_size) u8 {
    if (comptime builtin.os.tag == .windows) {
        return windows.memory.memAlloc(size);
    }
    const aligned_size = std.mem.alignForward(usize, size, page_size);
    const prot = std.posix.PROT{ .READ = true, .WRITE = true };
    const flags = std.posix.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    const total = aligned_size + 2 * page_size;
    const mapped = try std.posix.mmap(null, total, prot, flags, -1, 0);
    errdefer std.posix.munmap(mapped);
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

/// Create a non-blocking eventfd used for ring wakeups.
/// AArch64 only provides `eventfd2`; x86_64 provides `eventfd` (`eventfd2` is
/// also available but needs the newer syscall number).
pub fn eventfdCreate(flags: u32) !OsHandle {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const res = if (comptime builtin.cpu.arch == .aarch64)
        std.os.linux.syscall2(.eventfd2, 0, flags)
    else
        std.os.linux.syscall2(.eventfd, 0, flags);
    if (std.os.linux.errno(res) != .SUCCESS) return error.EventFdFailed;
    return @intCast(res);
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

pub fn getpid() i32 {
    if (comptime builtin.os.tag == .windows) {
        return 0;
    }
    return @intCast(std.posix.system.getpid());
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
    LandlockRuleFailed,
    PathOpenFailed,
    KernelTooOld,
    SandboxInitFailed,
    MitigationPolicyFailed,
    TokenOpenFailed,
    OutOfMemory,
};

/// Per-process Landlock path rules for Linux.
const web_landlock_rules = if (builtin.os.tag == .linux) &[_]@import("landlock.zig").PathRule{
    // Shared libraries & dlopen (Mesa, injected bundle, codecs)
    .{ .path = "/usr/lib", .read = true },
    .{ .path = "/usr/lib64", .read = true },
    .{ .path = "/lib", .read = true },
    .{ .path = "/home/intro/spectre-enviroment/browser/zawra-browser/webkit/build/lib", .read = true },
    .{ .path = "/home/intro/spectre-enviroment/browser/zawra-browser/webkit/build/bin", .read = true },
    // Fonts and desktop assets
    .{ .path = "/usr/share", .read = true },
    .{ .path = "/usr/local/share", .read = true },
    .{ .path = "/etc/fonts", .read = true },
    // DNS resolution
    .{ .path = "/etc/resolv.conf", .read = true },
    .{ .path = "/etc/hosts", .read = true },
    // Standard devices & shared memory
    .{ .path = "/dev/null", .read = true, .write = true },
    .{ .path = "/dev/urandom", .read = true },
    .{ .path = "/dev/shm", .read = true, .write = true },
    // GPU device access & Mesa/DRM/Vulkan device nodes
    .{ .path = "/dev/dri", .read = true, .write = true },
    .{ .path = "/etc/vulkan", .read = true },
    .{ .path = "/sys/dev/char", .read = true },
    .{ .path = "/sys/devices", .read = true },
    // Audio (PipeWire / PulseAudio Unix domain sockets)
    .{ .path = "/run/user/1000/pipewire-0", .read = true, .write = true },
    .{ .path = "/run/user/1000/pulse", .read = true, .write = true },
    // Profile + caches
    .{ .path = "/home/intro/.zawra", .read = true, .write = true },
    .{ .path = "/tmp/zawra-profile", .read = true, .write = true },
    .{ .path = "/tmp", .read = true, .write = true },
} else undefined;

const network_landlock_rules = if (builtin.os.tag == .linux) &[_]@import("landlock.zig").PathRule{
    // Profile + caches
    .{ .path = "/home/intro/.zawra", .read = true, .write = true },
    .{ .path = "/tmp/zawra-profile", .read = true, .write = true },
    .{ .path = "/tmp", .read = true, .write = true },
    // Standard devices
    .{ .path = "/dev/null", .read = true, .write = true },
    .{ .path = "/dev/urandom", .read = true },
    .{ .path = "/dev/random", .read = true },
    // Assets & system certs
    .{ .path = "/usr/share", .read = true },
    // DNS resolution
    .{ .path = "/etc/resolv.conf", .read = true },
    .{ .path = "/etc/hosts", .read = true },
    // TLS certificates
    .{ .path = "/etc/ssl", .read = true },
    .{ .path = "/etc/ssl/certs", .read = true },
    .{ .path = "/etc/pki", .read = true },
} else undefined;

const gpu_landlock_rules = if (builtin.os.tag == .linux) &[_]@import("landlock.zig").PathRule{
    // GPU device access & shared memory
    .{ .path = "/dev/dri", .read = true, .write = true },
    .{ .path = "/dev/shm", .read = true, .write = true },
    .{ .path = "/dev/null", .read = true, .write = true },
    .{ .path = "/usr/share", .read = true },
    .{ .path = "/etc/vulkan", .read = true },
    // Profile
    .{ .path = "/tmp/zawra-profile", .read = true, .write = true },
    .{ .path = "/tmp", .read = true, .write = true },
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
    // Android apps already run under SELinux / isolatedProcess restrictions.
    // Hajr installs no policy of its own: no Landlock, no desktop Seccomp filter
    // over Bionic/Binder. Report unsupported so the C FFI logs it and isSealed()
    // stays false.
    if (isAndroid()) return error.UnsupportedPlatform;

    switch (builtin.os.tag) {
        .linux => {
            const seccomp = @import("seccomp.zig");
            const landlock = @import("landlock.zig");

            const rules = switch (process_type) {
                .web => web_landlock_rules,
                .network => network_landlock_rules,
                .gpu => gpu_landlock_rules,
            };

            // Apply Landlock first so its ruleset creation and restrictions occur before Seccomp BPF filters engage.
            // A kernel without Landlock support must not abort sealing: fall through to Seccomp.
            landlock.denyWithExceptions(rules) catch |err| switch (err) {
                error.LandlockNotSupported, error.KernelTooOld => {},
                else => {
                    std.debug.print("[HAJR-OS] ERROR: landlock.denyWithExceptions failed: {}\n", .{err});
                    return err;
                },
            };

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

pub fn sleepNs(ns: u64) void {
    if (comptime builtin.os.tag == .windows) {
        windows.time.sleepNs(ns);
    } else {
        const sec: i64 = @intCast(ns / std.time.ns_per_s);
        const nsec: i64 = @intCast(ns % std.time.ns_per_s);
        var ts = std.posix.system.timespec{ .sec = sec, .nsec = nsec };
        _ = std.posix.system.nanosleep(&ts, null);
    }
}

pub const FUTEX_WAIT_PRIVATE: u32 = 128; // FUTEX_WAIT (0) | FUTEX_PRIVATE_FLAG (128)
pub const FUTEX_WAKE_PRIVATE: u32 = 129; // FUTEX_WAKE (1) | FUTEX_PRIVATE_FLAG (128)

const win32_synch = if (builtin.os.tag == .windows) struct {
    pub const INFINITE: std.os.windows.DWORD = 0xFFFFFFFF;

    extern "api-ms-win-core-synch-l1-2-0" fn WaitOnAddress(
        Address: *const anyopaque,
        CompareAddress: *const anyopaque,
        AddressSize: std.os.windows.SIZE_T,
        dwMilliseconds: std.os.windows.DWORD,
    ) callconv(.winapi) std.os.windows.BOOL;

    extern "api-ms-win-core-synch-l1-2-0" fn WakeByAddressSingle(
        Address: *const anyopaque,
    ) callconv(.winapi) void;

    extern "api-ms-win-core-synch-l1-2-0" fn WakeByAddressAll(
        Address: *const anyopaque,
    ) callconv(.winapi) void;
} else struct {};

const darwin_synch = if (builtin.os.tag == .macos) struct {
    pub const UL_COMPARE_AND_WAIT: u32 = 1;
    pub const UL_COMPARE_AND_WAIT_SHARED: u32 = 3;
    pub const ULF_WAKE_ALL: u32 = 0x00000100;

    extern "c" fn __ulock_wait(operation: u32, addr: ?*const anyopaque, value: u64, timeout: u32) callconv(.c) c_int;
    extern "c" fn __ulock_wake(operation: u32, addr: ?*const anyopaque, wake_value: u64) callconv(.c) c_int;
} else struct {};

pub fn futexWait(addr: *volatile u32, expected: u32) void {
    if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.syscall4(
            .futex,
            @intFromPtr(addr),
            FUTEX_WAIT_PRIVATE,
            expected,
            0,
        );
    } else if (comptime builtin.os.tag == .macos) {
        const ptr: ?*const anyopaque = @ptrCast(@volatileCast(addr));
        const res = darwin_synch.__ulock_wait(darwin_synch.UL_COMPARE_AND_WAIT_SHARED, ptr, @as(u64, expected), 0);
        if (res < 0) {
            _ = darwin_synch.__ulock_wait(darwin_synch.UL_COMPARE_AND_WAIT, ptr, @as(u64, expected), 0);
        }
    } else if (comptime builtin.os.tag == .windows) {
        var comp = expected;
        _ = win32_synch.WaitOnAddress(@ptrCast(@volatileCast(addr)), &comp, @sizeOf(u32), win32_synch.INFINITE);
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
    } else if (comptime builtin.os.tag == .macos) {
        const ptr: ?*const anyopaque = @ptrCast(@volatileCast(addr));
        const op: u32 = if (count > 1) (darwin_synch.UL_COMPARE_AND_WAIT_SHARED | darwin_synch.ULF_WAKE_ALL) else darwin_synch.UL_COMPARE_AND_WAIT_SHARED;
        const res = darwin_synch.__ulock_wake(op, ptr, 0);
        if (res < 0) {
            const priv_op: u32 = if (count > 1) (darwin_synch.UL_COMPARE_AND_WAIT | darwin_synch.ULF_WAKE_ALL) else darwin_synch.UL_COMPARE_AND_WAIT;
            _ = darwin_synch.__ulock_wake(priv_op, ptr, 0);
        }
    } else if (comptime builtin.os.tag == .windows) {
        const ptr: *const anyopaque = @ptrCast(@volatileCast(addr));
        if (count == 1) {
            win32_synch.WakeByAddressSingle(ptr);
        } else {
            win32_synch.WakeByAddressAll(ptr);
        }
    }
}

