const std = @import("std");
const atomic = std.atomic;
const hw = @import("../hw/mod.zig");

pub const consumer = @import("consumer.zig");

pub const TraceEventKind = enum(u8) {
    ring_send = 0x00,
    ring_recv = 0x01,
    ring_try_recv_miss = 0x02,
    ring_full = 0x03,
    ring_empty = 0x04,
    ffi_ring_write = 0x05,
    ffi_ring_read = 0x06,
    router_dispatch = 0x10,
    channel_send = 0x11,
    channel_recv = 0x12,
};

pub const ProcessKind = enum(u8) {
    unknown = 0,
    ui_process = 1,
    web_process = 2,
    net_process = 3,
    gpu_process = 4,
    _,
};

pub const TraceRecord = extern struct {
    timestamp_ns: u64,
    source_id: u64,
    target_id: u64,
    ipc_sequence: u64,
    payload_len: u32,
    msg_type: u32,
    event_kind: u8,
    source_proc: u8,
    target_proc: u8,
    was_dropped: u8,
    source_tier: u8,
    target_tier: u8,
    occupied: u8,
    _pad: [17]u8 = .{0} ** 17,
};

comptime {
    std.debug.assert(@sizeOf(TraceRecord) == 64);
}

pub const TRACE_SLOTS: usize = 1024;
pub const TRACE_BACKPRESSURE_WATERMARK: usize = TRACE_SLOTS * 3 / 4;

pub const TraceRing = struct {
    slots: [TRACE_SLOTS]TraceRecord,
    head: atomic.Value(u64),
    tail: atomic.Value(u64),
    dropped: atomic.Value(u64),
};

pub var global: atomic.Value(?*TraceRing) = atomic.Value(?*TraceRing).init(null);

var init_once: atomic.Value(u32) = atomic.Value(u32).init(0);

pub fn init(allocator: std.mem.Allocator) void {
    if (init_once.swap(1, .acq_rel) != 0) return;

    var found_path: ?[:0]const u8 = null;
    var i: usize = 0;
    while (std.c.environ[i]) |env_ptr| : (i += 1) {
        const entry = std.mem.span(env_ptr);
        if (std.mem.startsWith(u8, entry, "HAJR_TRACE_FILE=")) {
            found_path = entry["HAJR_TRACE_FILE=".len..];
            break;
        }
    }
    const path = found_path orelse return;

    const tr = allocator.create(TraceRing) catch return;
    tr.* = .{
        .slots = undefined,
        .head = atomic.Value(u64).init(0),
        .tail = atomic.Value(u64).init(0),
        .dropped = atomic.Value(u64).init(0),
    };
    for (&tr.slots) |*s| s.* = .{
        .timestamp_ns = 0,
        .source_id = 0,
        .target_id = 0,
        .ipc_sequence = 0,
        .payload_len = 0,
        .msg_type = 0,
        .event_kind = 0,
        .source_proc = 0,
        .target_proc = 0,
        .was_dropped = 0,
        .source_tier = 0,
        .target_tier = 0,
        .occupied = 0,
    };
    global.store(tr, .release);

    const owned_path = allocator.dupeZ(u8, path) catch return;
    _ = std.Thread.spawn(.{}, consumer.drainLoop, .{ tr, owned_path }) catch {};
}

pub fn recordFfi(
    event: TraceEventKind,
    data_len: usize,
    seq: u64,
    ring_key: u32,
    ring_tier: u8,
) void {
    const tr = global.load(.acquire) orelse return;

    const head = tr.head.fetchAdd(1, .acq_rel);
    const used = head -% tr.tail.load(.acquire);
    if (used >= TRACE_BACKPRESSURE_WATERMARK) {
        _ = tr.dropped.fetchAdd(1, .acq_rel);
        std.debug.print("[hajr/trace] WARNING: trace ring at {}% capacity, dropping event\n", .{used * 100 / TRACE_SLOTS});
        return;
    }

    const idx = head % TRACE_SLOTS;
    const slot = &tr.slots[idx];

    var spins: u8 = 0;
    while (@atomicLoad(u8, &slot.occupied, .acquire) != 0) : (spins += 1) {
        if (spins > 64) {
            _ = tr.dropped.fetchAdd(1, .acq_rel);
            return;
        }
        std.atomic.spinLoopHint();
    }

    slot.* = TraceRecord{
        .timestamp_ns = hw.posix_io.monotonicTimestamp(),
        .source_id = ring_key,
        .target_id = 0,
        .ipc_sequence = seq,
        .payload_len = @intCast(data_len),
        .msg_type = 0,
        .event_kind = @intFromEnum(event),
        .source_proc = @intFromEnum(ProcessKind.unknown),
        .target_proc = @intFromEnum(ProcessKind.unknown),
        .was_dropped = 0,
        .source_tier = ring_tier,
        .target_tier = 0,
        .occupied = 1,
    };
}

pub fn recordIpc(
    event: TraceEventKind,
    source_id: u64,
    target_id: u64,
    seq: u64,
    payload_len: u32,
    msg_type: u32,
    source_proc: ProcessKind,
    target_proc: ProcessKind,
    source_tier: u8,
    target_tier: u8,
) void {
    const tr = global.load(.acquire) orelse return;

    const head = tr.head.fetchAdd(1, .acq_rel);
    const used = head -% tr.tail.load(.acquire);
    if (used >= TRACE_BACKPRESSURE_WATERMARK) {
        _ = tr.dropped.fetchAdd(1, .acq_rel);
        std.debug.print("[hajr/trace] WARNING: trace ring at {}% capacity, dropping event\n", .{used * 100 / TRACE_SLOTS});
        return;
    }

    const idx = head % TRACE_SLOTS;
    const slot = &tr.slots[idx];

    var spins: u8 = 0;
    while (@atomicLoad(u8, &slot.occupied, .acquire) != 0) : (spins += 1) {
        if (spins > 64) {
            _ = tr.dropped.fetchAdd(1, .acq_rel);
            return;
        }
        std.atomic.spinLoopHint();
    }

    slot.* = TraceRecord{
        .timestamp_ns = hw.posix_io.monotonicTimestamp(),
        .source_id = source_id,
        .target_id = target_id,
        .ipc_sequence = seq,
        .payload_len = payload_len,
        .msg_type = msg_type,
        .event_kind = @intFromEnum(event),
        .source_proc = @intFromEnum(source_proc),
        .target_proc = @intFromEnum(target_proc),
        .was_dropped = 0,
        .source_tier = source_tier,
        .target_tier = target_tier,
        .occupied = 1,
    };
}
