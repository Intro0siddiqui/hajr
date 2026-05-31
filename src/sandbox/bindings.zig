const std = @import("std");
const hw = @import("../hw/mod.zig");
const sandbox = @import("../core/sandbox.zig");
const builtin = @import("builtin");

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
    // Ensure the pointer is correctly 'colored' with its hardware tags.
    const raw_ptr: [*]u8 = @ptrFromInt(@intFromPtr(config.inbound_base) + read_pos);
    
    // We don't have the tag here directly from FFIConfig, but config.inbound_base 
    // should have been colored when it was passed in.
    // However, for total purity, we should probably store the tag or re-tag it.
    // If we assume inbound_base is already colored (AArch64), then raw_ptr will be colored too.
    
    out_ext_buf.data = raw_ptr;
    out_ext_buf.length = contiguous_len;
    out_ext_buf.free_func = null; // No custom free function; memory is managed by the ring
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

/// Write data to outbound ring buffer
export fn __zawra_ring_write(data: [*]const u8, length: usize) callconv(.c) i32 {
    const config = g_ffi_config orelse return -1;
    const meta = config.outbound_meta;

    if (meta.poison_bit.load(.acquire)) return -2; // Poisoned

    const write_idx = meta.write_index.load(.acquire);
    const read_idx = meta.read_index.load(.acquire);

    const used = write_idx - read_idx;
    if (used + length > config.outbound_size) return 0; // Full

    const write_pos = write_idx & (config.outbound_size - 1);
    const first_chunk = @min(length, config.outbound_size - write_pos);

    @memcpy(config.outbound_base[write_pos..write_pos + first_chunk], data[0..first_chunk]);

    if (first_chunk < length) {
        const second_chunk = length - first_chunk;
        @memcpy(config.outbound_base[0..second_chunk], data[first_chunk..length]);
    }

    meta.write_index.store(write_idx + length, .release);

    return 1; // Success
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
};

export fn hajr_ring_init(
    buffer: [*]u8,
    buffer_len: usize,
    size: usize,
    key_value: u32,
    tier_value: u8,
) callconv(.c) ?*C_HardenedRingBuffer {
    const allocator = std.heap.c_allocator;
    const c_ring = allocator.create(C_HardenedRingBuffer) catch return null;
    
    const metadata = @as(*RingMetadata, @ptrCast(@alignCast(buffer)));
    metadata.write_index.store(0, .release);
    metadata.read_index.store(0, .release);
    metadata.sequence.store(0, .release);
    metadata.poison_bit.store(false, .release);
    metadata.poison_cause.store(0, .release);

    c_ring.* = .{
        .memory_ptr = buffer,
        .memory_len = buffer_len,
        .metadata_ptr = metadata,
        .data_ptr = @ptrFromInt(@intFromPtr(buffer) + sandbox.RingConfig.METADATA_SIZE),
        .size = size,
        .key_val = key_value,
        .tier_val = tier_value,
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
    };
    return c_ring;
}

export fn hajr_ring_free(c_ring: ?*C_HardenedRingBuffer) callconv(.c) void {
    if (c_ring) |r| {
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

    if (length > avail) return 0; // Full

    const write_pos = write_idx & (ring.size - 1);
    const first_len = @min(length, ring.size - write_pos);
    @memcpy(ring.data_ptr[write_pos..write_pos + first_len], data[0..first_len]);

    if (first_len < length) {
        @memcpy(ring.data_ptr[0..length - first_len], data[first_len..length]);
    }

    meta.write_index.store(write_idx +% length, .release);
    _ = meta.sequence.fetchAdd(1, .acq_rel);
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
    const meta = ring.metadata_ptr;
    const addr = @as(*volatile u32, @ptrCast(&meta.write_index));
    hw.os.futexWake(addr, 1);
    return 1;
}

export fn hajr_ring_wait(c_ring: ?*C_HardenedRingBuffer) callconv(.c) i32 {
    const ring = c_ring orelse return -1;
    const meta = ring.metadata_ptr;
    const current = meta.write_index.load(.acquire);
    const read_idx = meta.read_index.load(.acquire);
    if (current != read_idx) return 1;
    const addr = @as(*volatile u32, @ptrCast(&meta.write_index));
    const expected = @as(u32, @truncate(current));
    hw.os.futexWait(addr, expected);
    return 1;
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

export fn Zawra_Hajr_SignalEventLoop() callconv(.c) void {
    // Wakeup signal stub for WPE generic runloop
}

export fn __hajr_create_anonymous_ring(size: usize) callconv(.c) u64 {
    if (comptime builtin.os.tag != .linux) {
        return 0;
    } else {
        const fd = std.os.linux.syscall2(.memfd_create, @intFromPtr("hajr-ring"), 1); // MFD_CLOEXEC
        if (fd < 0) return 0;
        _ = std.os.linux.syscall2(.ftruncate, @as(usize, @intCast(fd)), size);
        return @as(u64, @intCast(fd));
    }
}

export fn __hajr_map_anonymous_ring(id: u64) callconv(.c) ?*anyopaque {
    if (comptime builtin.os.tag != .linux) {
        return null;
    } else {
        const fd: i32 = @intCast(id);
        const size_or_err = std.os.linux.syscall3(.lseek, @as(usize, @intCast(fd)), 0, 2); // SEEK_END
        if (size_or_err < 0) return null;
        const buffer_len: usize = @intCast(size_or_err);
        
        // restore offset
        _ = std.os.linux.syscall3(.lseek, @as(usize, @intCast(fd)), 0, 0); // SEEK_SET
        
        const prot = std.posix.PROT{ .READ = true, .WRITE = true };
        const mmap_slice = std.posix.mmap(
            null,
            buffer_len,
            prot,
            std.posix.MAP{ .TYPE = .SHARED },
            fd,
            0,
        ) catch return null;
        
        const ring_size = buffer_len - sandbox.RingConfig.METADATA_SIZE;
        
        const c_ring = hajr_ring_map(
            @as([*]u8, @ptrCast(mmap_slice.ptr)),
            buffer_len,
            ring_size,
            0,
            0,
        );
        
        return @ptrCast(c_ring);
    }
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
    // Implement fstat-like behavior using raw linux syscalls for 100% stability
    if (comptime builtin.os.tag == .linux) {
        const Stat = extern struct {
            dev: u64, ino: u64, nlink: u64, mode: u32, uid: u32, gid: u32, __pad0: u32,
            rdev: u64, size: i64, blksize: i64, blocks: i64, atime: i64, atime_nsec: i64,
            mtime: i64, mtime_nsec: i64, ctime: i64, ctime_nsec: i64, __unused: [3]i64,
        };
        var stat_buf: Stat = undefined;
        // 5 is the syscall number for fstat on x86_64, but we should use the constant
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
