const std = @import("std");
const hw = @import("../hw/mod.zig");
const sandbox = @import("../core/sandbox.zig");
const process = @import("../core/process.zig");
const lockdown = @import("lockdown.zig");
const builtin = @import("builtin");

comptime {
    _ = lockdown;
}

// ============================================================================
// JavaScriptCore Zero-Copy FFI Bindings (Task 2)
// ============================================================================

pub const RingMetadata = sandbox.RingMetadata;

/// JavaScriptCore External ArrayBuffer representation
pub const JSCExternalBuffer = extern struct {
    data: [*]u8,
    length: usize,
    free_func: ?*const fn ([*]u8, usize, *anyopaque) callconv(.c) void,
    user_data: *anyopaque,
};

pub const FFIConfig = extern struct {
    inbound_base: [*]u8,
    inbound_size: usize,
    inbound_meta: *sandbox.RingMetadata,
    outbound_base: [*]u8,
    outbound_size: usize,
    outbound_meta: *sandbox.RingMetadata,
};

var g_ffi_config: ?*const FFIConfig = null;

export fn __zawra_init_ffi(config: *const FFIConfig) callconv(.c) void {
    g_ffi_config = config;
}

pub fn initFFI(config: *const FFIConfig) void {
    __zawra_init_ffi(config);
}

/// Read a payload from the inbound ring.
/// CRITICAL ZERO-COPY DIRECTIVE: Uses JavaScriptCore's external ArrayBuffer API.
/// Does not copy bytes into JS heap. Passes memory-mapped ring pointer directly.
export fn __zawra_ring_read(out_ext_buf: *JSCExternalBuffer) callconv(.c) i32 {
    const config = g_ffi_config orelse return -1;
    const meta = config.inbound_meta;

    if (meta.poison_bit.load(.acquire)) return -2; // Poisoned

    const read_idx = meta.read_index.load(.acquire);
    const write_idx = meta.write_index.load(.acquire);

    if (read_idx >= write_idx) return 0; // Empty

    const available = write_idx - read_idx;
    const read_pos = read_idx & (config.inbound_size - 1);
    
    // Strict length boundary: Limit to contiguous memory chunk to ensure safe zero-copy mapping
    const contiguous_len = @min(available, config.inbound_size - read_pos);

    // Pass the memory-mapped ring pointer directly to the JS engine.
    const raw_ptr: [*]u8 = @ptrFromInt(@intFromPtr(config.inbound_base) + read_pos);
    
    out_ext_buf.data = raw_ptr;
    out_ext_buf.length = contiguous_len;
    out_ext_buf.free_func = null; 
    out_ext_buf.user_data = @ptrCast(@constCast(config));

    return 1; // Success
}

/// JavaScriptCore calls this after finished processing the external buffer 
export fn __zawra_ring_commit_read(bytes_consumed: u64) callconv(.c) void {
    const config = g_ffi_config orelse return;
    const meta = config.inbound_meta;
    const current = meta.read_index.load(.acquire);
    meta.read_index.store(current + bytes_consumed, .release);
}

// ============================================================================
// General C/C++ FFI Bindings for Multi-Connection IPC
// ============================================================================

pub const C_HardenedRingBuffer = extern struct {
    memory_ptr: [*]u8,
    memory_len: usize,
    metadata_ptr: *RingMetadata,
    data_ptr: [*]u8,
    size: usize,
    key_val: u32,
    tier_val: u8,
    signal_fd: i32,
};

export fn hajr_ring_init(
    buffer: [*]u8,
    buffer_len: usize,
    size: usize,
    key_value: u32,
    tier_value: u8,
) callconv(.c) ?*C_HardenedRingBuffer {
    // Validate size is power-of-two (required for bitwise AND modulo)
    if (size == 0 or (size & (size - 1)) != 0) return null;

    const allocator = std.heap.c_allocator;
    const c_ring = allocator.create(C_HardenedRingBuffer) catch return null;
    
    const metadata = @as(*RingMetadata, @ptrCast(@alignCast(buffer)));
    metadata.write_index.store(0, .release);
    metadata.read_index.store(0, .release);
    metadata.sequence.store(0, .release);
    metadata.poison_bit.store(false, .release);
    metadata.poison_cause.store(0, .release);

    var s_fd: i32 = -1;
    if (comptime builtin.os.tag == .linux) {
        const res = std.os.linux.syscall2(.eventfd, 0, std.os.linux.EFD.CLOEXEC | std.os.linux.EFD.NONBLOCK);
        if (std.os.linux.errno(res) == .SUCCESS) {
            s_fd = @intCast(res);
        }
    } else if (comptime builtin.os.tag == .macos) {
        var fds: [2]i32 = undefined;
        const rc = std.posix.system.pipe(&fds);
        if (rc == 0) {
            s_fd = fds[0];
        }
    }

    c_ring.* = .{
        .memory_ptr = buffer,
        .memory_len = buffer_len,
        .metadata_ptr = metadata,
        .data_ptr = @ptrFromInt(@intFromPtr(buffer) + sandbox.RingConfig.METADATA_SIZE),
        .size = size,
        .key_val = key_value,
        .tier_val = tier_value,
        .signal_fd = s_fd,
    };
    return c_ring;
}

export fn hajr_ring_map(
    buffer: [*]u8,
    buffer_len: usize,
    size: usize,
    key_value: u32,
    tier_value: u8,
) callconv(.c) ?*C_HardenedRingBuffer {
    return hajr_ring_map_with_signal(buffer, buffer_len, size, key_value, tier_value, -1);
}

export fn hajr_ring_map_with_signal(
    buffer: [*]u8,
    buffer_len: usize,
    size: usize,
    key_value: u32,
    tier_value: u8,
    signal_fd: i32,
) callconv(.c) ?*C_HardenedRingBuffer {
    // Validate size is power-of-two (required for bitwise AND modulo)
    if (size == 0 or (size & (size - 1)) != 0) return null;

    const allocator = std.heap.c_allocator;
    const c_ring = allocator.create(C_HardenedRingBuffer) catch return null;
    const metadata = @as(*RingMetadata, @ptrCast(@alignCast(buffer)));
    c_ring.* = .{
        .memory_ptr = buffer,
        .memory_len = buffer_len,
        .metadata_ptr = metadata,
        .data_ptr = @ptrFromInt(@intFromPtr(buffer) + sandbox.RingConfig.METADATA_SIZE),
        .size = size,
        .key_val = key_value,
        .tier_val = tier_value,
        .signal_fd = signal_fd,
    };
    return c_ring;
}


export fn hajr_ring_free(c_ring: ?*C_HardenedRingBuffer) callconv(.c) void {
    if (c_ring) |r| {
        if (r.signal_fd != -1) {
            if (comptime builtin.os.tag != .windows) {
                _ = std.posix.system.close(r.signal_fd);
            }
        }
        std.heap.c_allocator.destroy(r);
    }
}

export fn hajr_ring_write(
    c_ring: ?*C_HardenedRingBuffer,
    data: [*]const u8,
    length: usize,
) callconv(.c) i32 {
    const ring = c_ring orelse return -1;
    const meta = ring.metadata_ptr;

    if (meta.poison_bit.load(.acquire)) return -2;

    const write_idx = meta.write_index.load(.acquire);
    const read_idx = meta.read_index.load(.acquire);

    const used = write_idx -% read_idx;
    const avail = ring.size - used;

    // Diagnostic: log before write
    {
        var diag_buf: [256]u8 = undefined;
        const diag_msg = std.fmt.bufPrint(&diag_buf, "[HAJR-DIAG] hajr_ring_write: len={d} write_idx={d} read_idx={d} used={d} avail={d} size={d}\n", .{ length, write_idx, read_idx, used, avail, ring.size });
        if (diag_msg) |str| {
            _ = std.os.linux.syscall3(.write, 2, @intFromPtr(str.ptr), str.len);
        } else |_| {}
    }

    if (length > avail) {
        // Diagnostic: log full condition
        var diag_buf: [256]u8 = undefined;
        const diag_msg = std.fmt.bufPrint(&diag_buf, "[HAJR-DIAG] hajr_ring_write: FULL! len={d} avail={d} size={d}\n", .{ length, avail, ring.size });
        if (diag_msg) |str| {
            _ = std.os.linux.syscall3(.write, 2, @intFromPtr(str.ptr), str.len);
        } else |_| {}
        return 0; // Full
    }

    const write_pos = write_idx & (ring.size - 1);
    const first_len = @min(length, ring.size - write_pos);
    const second_len = if (first_len < length) length - first_len else 0;

    // Diagnostic: log chunk sizes
    {
        var diag_buf: [256]u8 = undefined;
        const diag_msg = std.fmt.bufPrint(&diag_buf, "[HAJR-DIAG] hajr_ring_write: write_pos={d} first={d} second={d}\n", .{ write_pos, first_len, second_len });
        if (diag_msg) |str| {
            _ = std.os.linux.syscall3(.write, 2, @intFromPtr(str.ptr), str.len);
        } else |_| {}
    }

    // Diagnostic: check for potential overflow
    if (write_pos + first_len > ring.size) {
        var diag_buf: [256]u8 = undefined;
        const diag_msg = std.fmt.bufPrint(&diag_buf, "[HAJR-DIAG] hajr_ring_write: OVERFLOW! write_pos={d} first={d} size={d}\n", .{ write_pos, first_len, ring.size });
        if (diag_msg) |str| {
            _ = std.os.linux.syscall3(.write, 2, @intFromPtr(str.ptr), str.len);
        } else |_| {}
    }
    if (second_len > ring.size) {
        var diag_buf: [256]u8 = undefined;
        const diag_msg = std.fmt.bufPrint(&diag_buf, "[HAJR-DIAG] hajr_ring_write: OVERFLOW2! second={d} size={d}\n", .{ second_len, ring.size });
        if (diag_msg) |str| {
            _ = std.os.linux.syscall3(.write, 2, @intFromPtr(str.ptr), str.len);
        } else |_| {}
    }

    @memcpy(ring.data_ptr[write_pos..write_pos + first_len], data[0..first_len]);

    if (first_len < length) {
        @memcpy(ring.data_ptr[0..second_len], data[first_len..length]);
    }

    meta.write_index.store(write_idx +% length, .release);
    _ = meta.sequence.fetchAdd(1, .acq_rel);

    // Diagnostic: log after write
    {
        const new_write_idx = meta.write_index.load(.acquire);
        var diag_buf: [256]u8 = undefined;
        const diag_msg = std.fmt.bufPrint(&diag_buf, "[HAJR-DIAG] hajr_ring_write: DONE new_write_idx={d}\n", .{new_write_idx});
        if (diag_msg) |str| {
            _ = std.os.linux.syscall3(.write, 2, @intFromPtr(str.ptr), str.len);
        } else |_| {}
    }

    return 1;
}

export fn hajr_ring_read(
    c_ring: ?*C_HardenedRingBuffer,
    buf: [*]u8,
    length: usize,
    bytes_read: *usize,
) callconv(.c) i32 {
    const ring = c_ring orelse return -1;
    const meta = ring.metadata_ptr;

    if (meta.poison_bit.load(.acquire)) return -2;

    const write_idx = meta.write_index.load(.acquire);
    const read_idx = meta.read_index.load(.acquire);

    const avail = write_idx -% read_idx;
    if (avail == 0) {
        bytes_read.* = 0;
        return 1;
    }

    const to_read = @min(@as(usize, @intCast(avail)), length);
    const read_pos = read_idx & (ring.size - 1);
    const first_len = @min(to_read, ring.size - read_pos);
    @memcpy(buf[0..first_len], ring.data_ptr[read_pos..read_pos + first_len]);

    if (first_len < to_read) {
        @memcpy(buf[first_len..to_read], ring.data_ptr[0..to_read - first_len]);
    }

    meta.read_index.store(read_idx +% to_read, .release);
    bytes_read.* = to_read;
    return 1;
}

// ============================================================================
// Sandbox Allocation FFI (Task 3)
// ============================================================================

/// Allocate a sandbox and return its protection key/ID
export fn __zawra_allocate_sandbox(tier: u8) callconv(.c) u32 {
    const sb_tier: sandbox.SandboxTier = if (tier == 0) .trusted else .untrusted;
    const key = sandbox.SandboxTier.getProtectionKey(sb_tier);
    return key.value;
}

/// Free a sandbox
export fn __zawra_free_sandbox(id: u32) callconv(.c) void {
    _ = id;
}

export fn hajr_ring_signal(c_ring: ?*C_HardenedRingBuffer) callconv(.c) i32 {
    const ring = c_ring orelse return -1;
    if (ring.signal_fd != -1) {
        if (comptime builtin.os.tag == .linux) {
            const val: u64 = 1;
            _ = std.os.linux.syscall3(.write, @as(usize, @intCast(ring.signal_fd)), @intFromPtr(&val), 8);
            return 1;
        } else if (comptime builtin.os.tag == .macos) {
            const val: u8 = 1;
            const rc = std.posix.system.write(ring.signal_fd, @ptrCast(&val), 1);
            return if (rc >= 0) 1 else -1;
        }
    }
    const meta = ring.metadata_ptr;
    const addr = @as(*volatile u32, @ptrCast(&meta.write_index));
    hw.os.futexWake(addr, 1);
    return 1;
}

export fn hajr_ring_wait(c_ring: ?*C_HardenedRingBuffer) callconv(.c) i32 {
    const ring = c_ring orelse return -1;
    if (ring.signal_fd != -1) {
        if (comptime builtin.os.tag == .linux) {
            var val: u64 = 0;
            _ = std.os.linux.syscall3(.read, @as(usize, @intCast(ring.signal_fd)), @intFromPtr(&val), 8);
            return 1;
        } else if (comptime builtin.os.tag == .macos) {
            var val: u8 = 0;
            const rc = std.posix.system.read(ring.signal_fd, @ptrCast(&val), 1);
            return if (rc >= 0) 1 else -1;
        }
    }
    const meta = ring.metadata_ptr;
    const current = meta.write_index.load(.acquire);
    const read_idx = meta.read_index.load(.acquire);
    if (current != read_idx) return 1;
    const addr = @as(*volatile u32, @ptrCast(&meta.write_index));
    const expected = @as(u32, @truncate(current));
    hw.os.futexWait(addr, expected);
    return 1;
}

export fn hajr_ring_get_signal_fd(c_ring: ?*C_HardenedRingBuffer) callconv(.c) i32 {
    const ring = c_ring orelse return -1;
    return ring.signal_fd;
}


var g_other_pidfd: i32 = -1;

export fn hajr_ipc_set_other_pidfd(pidfd: i32) callconv(.c) void {
    g_other_pidfd = pidfd;
}

/// Send a file descriptor over the IPC ring.
/// In the pure ring model, we just return the FD number as a handle.
export fn hajr_ipc_send_fd(c_ring: ?*C_HardenedRingBuffer, fd: i32) callconv(.c) i32 {
    _ = c_ring;
    return fd; 
}

/// Receive a file descriptor from the IPC ring.
/// Uses pidfd_getfd to pull the FD from the other process.
export fn hajr_ipc_recv_fd(c_ring: ?*C_HardenedRingBuffer, handle: i32) callconv(.c) i32 {
    _ = c_ring;
    if (comptime builtin.os.tag == .linux) {
        if (g_other_pidfd == -1) return -1;
        const res = std.os.linux.syscall3(.pidfd_getfd, @as(usize, @intCast(g_other_pidfd)), @as(usize, @intCast(handle)), 0);
        if (std.os.linux.errno(res) == .SUCCESS) {
            return @intCast(res);
        }
    } else if (comptime builtin.os.tag == .macos) {
        return handle; 
    }
    return -1;
}



/// Universal Monotonic Clock Bridge
/// CRITICAL: OS-agnostic time-keeping for WebKit/WTF.
export fn Zawra_Hajr_GetMonotonicTime() callconv(.c) f64 {
    return hw.os.getMonotonicTime();
}

// ============================================================================
// Agnostic Threading FFI
// ============================================================================

// Windows thread API declarations
extern "kernel32" fn SetThreadPriority(hThread: ?*anyopaque, nPriority: i32) callconv(.winapi) i32;
extern "kernel32" fn WaitForSingleObject(hHandle: ?*anyopaque, dwMilliseconds: u32) callconv(.winapi) u32;
extern "kernel32" fn CloseHandle(hObject: ?*anyopaque) callconv(.winapi) i32;
const INFINITE: u32 = 0xFFFFFFFF;

export fn hajr_thread_create(
    func: *const fn (?*anyopaque) callconv(.c) ?*anyopaque,
    arg: ?*anyopaque,
) callconv(.c) usize {
    const Wrapper = struct {
        fn entry(f: *const fn (?*anyopaque) callconv(.c) ?*anyopaque, a: ?*anyopaque) void {
            _ = f(a);
        }
    };
    const thread = std.Thread.spawn(.{}, Wrapper.entry, .{ func, arg }) catch {
        return 0;
    };
    if (comptime builtin.os.tag == .windows) {
        return @intFromPtr(thread.impl.thread.thread_handle);
    } else {
        return @intFromPtr(thread.impl.handle);
    }
}

export fn hajr_thread_join(handle: usize) callconv(.c) i32 {
    if (comptime builtin.os.tag == .windows) {
        _ = WaitForSingleObject(@ptrFromInt(handle), INFINITE);
        _ = CloseHandle(@ptrFromInt(handle));
    } else {
        const rc = std.posix.system.pthread_join(@ptrFromInt(handle), null);
        if (rc != .SUCCESS) return -1;
    }
    return 0;
}

export fn hajr_thread_set_priority(handle: usize, priority: u8) callconv(.c) i32 {
    if (comptime builtin.os.tag == .windows) {
        const win_prio: i32 = if (priority < 64)
            @as(i32, -2) // THREAD_PRIORITY_LOWEST
        else if (priority < 128)
            @as(i32, -1) // THREAD_PRIORITY_BELOW_NORMAL
        else if (priority < 192)
            @as(i32, 0)  // THREAD_PRIORITY_NORMAL
        else
            @as(i32, 1); // THREAD_PRIORITY_ABOVE_NORMAL
        if (SetThreadPriority(@ptrFromInt(handle), win_prio) == 0) {
            return -1;
        }
    } else {
        if (@hasDecl(std.posix.system, "pthread_setschedprio")) {
            const rc = std.posix.system.pthread_setschedprio(@ptrFromInt(handle), @intCast(priority / 8));
            if (rc != .SUCCESS) return -1;
        }
    }
    return 0;
}

export fn Zawra_Thread_Create(
    func: *const fn (?*anyopaque) callconv(.c) ?*anyopaque,
    arg: ?*anyopaque,
) callconv(.c) usize {
    return hajr_thread_create(func, arg);
}

export fn Zawra_Hajr_MemAlloc(size: usize) callconv(.c) ?*anyopaque {
    const slice = hw.os.memAlloc(size) catch return null;
    return slice.ptr;
}

export fn Zawra_Hajr_MemProtect(ptr: ?*anyopaque, size: usize, read: bool, write: bool) callconv(.c) i32 {
    const raw_ptr: [*]u8 = @ptrCast(ptr orelse return -1);
    hw.os.memProtect(raw_ptr, size, read, write) catch return -1;
    return 0;
}

export fn __hajr_create_anonymous_ring(data_size: usize) callconv(.c) u64 {
    if (comptime builtin.os.tag == .linux) {
        const name_ptr = @intFromPtr("hajr-ring");
        const fd = std.os.linux.syscall2(.memfd_create, name_ptr, std.os.linux.MFD.CLOEXEC);
        if (fd < 0) return std.math.maxInt(u64);
        // data_size is the ring data portion (must be power-of-two).
        // Total allocation = METADATA_SIZE + data_size.
        const total_size = sandbox.RingConfig.METADATA_SIZE + data_size;
        _ = std.os.linux.syscall2(.ftruncate, @as(usize, @intCast(fd)), total_size);
        return @as(u64, @intCast(fd));
    } else if (comptime builtin.os.tag == .macos) {
        const name = "/hajr-ring-m2-shm"; 
        const oflag = std.posix.O{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true };
        const fd = std.posix.system.open(name, oflag, @as(u32, 0o600));
        if (fd < 0) {
            return @intCast(std.posix.system.open(name, std.posix.O{ .ACCMODE = .RDWR }, @as(u32, 0)));
        }
        const total_size = sandbox.RingConfig.METADATA_SIZE + data_size;
        _ = std.posix.system.ftruncate(fd, @as(i64, @intCast(total_size)));
        return @as(u64, @intCast(fd));
    }
    return std.math.maxInt(u64);
}

export fn __hajr_map_anonymous_ring(id: u64) callconv(.c) ?*anyopaque {
    return __hajr_map_anonymous_ring_ex(id, -1);
}

export fn __hajr_map_anonymous_ring_ex(id: u64, signal_fd: i32) callconv(.c) ?*anyopaque {
    if (comptime builtin.os.tag == .windows) return null;

    const fd: i32 = @intCast(id);
    var buffer_len: usize = 0;
    if (comptime builtin.os.tag == .linux) {
        const rc = std.os.linux.syscall3(.lseek, @as(usize, @intCast(fd)), 0, 2); // SEEK_END
        const lseek_err = std.os.linux.errno(rc);
        {
            var diag_buf: [128]u8 = undefined;
            const diag_msg = std.fmt.bufPrint(&diag_buf, "[HAJR-CHILD] DIAG: lseek fd={d} rc={d} errno={s}\n", .{ fd, @as(isize, @bitCast(rc)), @tagName(lseek_err) });
            if (diag_msg) |str| {
                _ = std.os.linux.syscall3(.write, 2, @intFromPtr(str.ptr), str.len);
            } else |_| {}
        }
        if (lseek_err != .SUCCESS) return null;
        buffer_len = @intCast(rc);
        _ = std.os.linux.syscall3(.lseek, @as(usize, @intCast(fd)), 0, 0); // SEEK_SET
    } else {
        const size = std.posix.system.lseek(fd, 0, 2); // SEEK_END
        if (size < 0) return null;
        buffer_len = @intCast(size);
        _ = std.posix.system.lseek(fd, 0, 0); // SEEK_SET
    }
    
    const prot = std.posix.PROT{ .READ = true, .WRITE = true };
    const mmap_slice = std.posix.mmap(
        null,
        buffer_len,
        prot,
        std.posix.MAP{ .TYPE = .SHARED },
        fd,
        0,
    ) catch |err| {
        var diag_buf: [128]u8 = undefined;
        const diag_msg = std.fmt.bufPrint(&diag_buf, "[HAJR-CHILD] DIAG: mmap failed fd={d} len={d} err={s}\n", .{ fd, buffer_len, @errorName(err) });
        if (diag_msg) |str| {
            _ = std.os.linux.syscall3(.write, 2, @intFromPtr(str.ptr), str.len);
        } else |_| {}
        return null;
    };
    const mmap_ptr: [*]u8 = mmap_slice.ptr;
    
    const ring_size = buffer_len - sandbox.RingConfig.METADATA_SIZE;

    // Validate ring_size is power-of-two (required for bitwise AND modulo)
    if (ring_size == 0 or (ring_size & (ring_size - 1)) != 0) {
        var diag_buf: [128]u8 = undefined;
        const diag_msg = std.fmt.bufPrint(&diag_buf, "[HAJR-CHILD] FATAL: ring_size={d} is not power-of-two!\n", .{ring_size});
        if (diag_msg) |str| {
            _ = std.os.linux.syscall3(.write, 2, @intFromPtr(str.ptr), str.len);
        } else |_| {}
        return null;
    }

    // When no signal_fd is provided (-1), create an eventfd for IPC signaling.
    // Without this, Zawra_Hajr_CreateRingPair would return -1 for both
    // signal FDs, making the child's connection identifier invalid.
    var actual_signal_fd = signal_fd;
    if (actual_signal_fd == -1) {
        if (comptime builtin.os.tag == .linux) {
            const efd = std.os.linux.syscall2(.eventfd, 0, std.os.linux.EFD.CLOEXEC | std.os.linux.EFD.NONBLOCK);
            if (@as(isize, @bitCast(efd)) >= 0) {
                actual_signal_fd = @intCast(efd);
            }
        }
    }
    
    const c_ring = hajr_ring_map_with_signal(
        mmap_ptr,
        buffer_len,
        ring_size,
        0,
        0,
        actual_signal_fd,
    );
    
    return @ptrCast(c_ring);
}

// ============================================================================
// Agnostic FileSystem FFI
// ============================================================================

export fn Zawra_File_Seek(handle: hw.os.OsHandle, offset: i64, origin: i32) callconv(.c) u64 {
    const seek_origin: hw.os.SeekOrigin = @enumFromInt(origin);
    return hw.os.fileSeek(handle, offset, seek_origin) catch 0;
}

export fn Zawra_File_Stat(path: [*:0]const u8, info: *hw.os.FileInfo) callconv(.c) i32 {
    const path_slice = std.mem.span(path);
    const stat = hw.os.fileStat(path_slice) catch return -1;
    info.* = stat;
    return 0;
}

export fn Zawra_File_StatFD(handle: hw.os.OsHandle, info: *hw.os.FileInfo) callconv(.c) i32 {
    if (comptime builtin.os.tag == .linux) {
        const Stat = extern struct {
            dev: u64, ino: u64, nlink: u64, mode: u32, uid: u32, gid: u32, __pad0: u32,
            rdev: u64, size: i64, blksize: i64, blocks: i64, atime: i64, atime_nsec: i64,
            mtime: i64, mtime_nsec: i64, ctime: i64, ctime_nsec: i64, __unused: [3]i64,
        };
        var stat_buf: Stat = undefined;
        const rc = std.os.linux.syscall2(.fstat, @as(usize, @intCast(handle)), @intFromPtr(&stat_buf));
        if (rc != 0) return -1;
        info.* = .{
            .size = @as(u64, @intCast(stat_buf.size)),
            .mtime = stat_buf.mtime,
            .atime = stat_buf.atime,
            .ctime = stat_buf.ctime,
            .is_dir = (stat_buf.mode & 0o170000) == 0o040000,
        };
        return 0;
    } else {
        return -1;
    }
}

export fn Zawra_File_Access(path: [*:0]const u8, mode: u32) callconv(.c) i32 {
    const path_slice = std.mem.span(path);
    const access_mode: hw.os.AccessMode = @enumFromInt(mode);
    return if (hw.os.fileAccess(path_slice, access_mode) catch false) 1 else 0;
}

export fn Zawra_File_Unlink(path: [*:0]const u8) callconv(.c) i32 {
    const path_slice = std.mem.span(path);
    hw.os.fileUnlink(path_slice) catch return -1;
    return 0;
}

export fn Zawra_File_Mkdir(path: [*:0]const u8) callconv(.c) i32 {
    const path_slice = std.mem.span(path);
    hw.os.fileMkdir(path_slice) catch return -1;
    return 0;
}

export fn hajr_spawn_compartment(
    path: [*:0]const u8,
    argv: [*]const ?[*:0]const u8,
    out_socket: *i32,
) callconv(.c) i32 {
    const allocator = std.heap.c_allocator;
    
    var zig_argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer zig_argv.deinit(allocator);
    
    var i: usize = 0;
    while (argv[i]) |arg| : (i += 1) {
        zig_argv.append(allocator, std.mem.span(arg)) catch return -1;
    }
    
    const pid = process.spawnCompartment(allocator, std.mem.span(path), zig_argv.items, out_socket) catch return -1;
    
    if (comptime builtin.os.tag == .linux) {
        const res = std.os.linux.syscall2(.pidfd_open, pid, 0);
        if (std.os.linux.errno(res) == .SUCCESS) {
            g_other_pidfd = @intCast(res);
        }
    }

    return @intCast(pid);
}

// ============================================================================
// CRC32 Checksum FFI for IPC Message Integrity
// ============================================================================

/// CRC32 lookup table (Castagnoli polynomial 0x1EDC6F41)
const crc32_table = blk: {
    @setEvalBranchQuota(10000);
    var table: [256]u32 = undefined;
    const poly: u32 = 0x1EDC6F41; // Castagnoli
    var i: u32 = 0;
    while (i < 256) : (i += 1) {
        var crc = i;
        var j: u32 = 0;
        while (j < 8) : (j += 1) {
            if (crc & 1 != 0) {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    break :blk table;
};

/// Calculate CRC32 checksum of data
pub fn crc32Calculate(data: []const u8) u32 {
    var crc: u32 = 0xFFFFFFFF;
    for (data) |byte| {
        crc = (crc >> 8) ^ crc32_table[(crc ^ byte) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/// C FFI: Calculate CRC32 checksum of a buffer
export fn hajr_crc32(data: [*]const u8, length: usize) callconv(.c) u32 {
    return crc32Calculate(data[0..length]);
}

/// C FFI: Calculate CRC32 of IPC message (header + payload)
export fn hajr_ipc_message_checksum(
    header: [*]const u8,
    header_len: usize,
    payload: [*]const u8,
    payload_len: usize,
) callconv(.c) u32 {
    var crc: u32 = 0xFFFFFFFF;
    
    // Hash header
    for (header[0..header_len]) |byte| {
        crc = (crc >> 8) ^ crc32_table[(crc ^ byte) & 0xFF];
    }
    
    // Hash payload
    for (payload[0..payload_len]) |byte| {
        crc = (crc >> 8) ^ crc32_table[(crc ^ byte) & 0xFF];
    }
    
    return crc ^ 0xFFFFFFFF;
}

/// C FFI: Verify IPC message checksum
export fn hajr_ipc_verify_checksum(
    header: [*]const u8,
    header_len: usize,
    payload: [*]const u8,
    payload_len: usize,
    expected_checksum: u32,
) callconv(.c) bool {
    const actual = hajr_ipc_message_checksum(header, header_len, payload, payload_len);
    return actual == expected_checksum;
}
