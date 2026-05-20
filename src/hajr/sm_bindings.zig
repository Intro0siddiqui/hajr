const hw = @import("../hw/mod.zig");
const sandbox = @import("../core/sandbox.zig");

// ============================================================================
// SpiderMonkey Zero-Copy FFI Bindings (Task 2)
// ============================================================================

pub const RingMetadata = sandbox.RingMetadata;

/// SpiderMonkey External ArrayBuffer representation
pub const SMExternalBuffer = extern struct {
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
/// CRITICAL ZERO-COPY DIRECTIVE: Uses SpiderMonkey's external ArrayBuffer API.
/// Does not copy bytes into JS heap. Passes memory-mapped ring pointer directly.
export fn __zawra_ring_read(out_ext_buf: *SMExternalBuffer) callconv(.c) i32 {
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
    out_ext_buf.user_data = undefined;

    return 1; // Success
}

/// SpiderMonkey calls this after finished processing the external buffer 
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
