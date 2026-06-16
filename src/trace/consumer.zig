const std = @import("std");
const hw = @import("../hw/mod.zig");
const trace = @import("trace.zig");

const posix_io = hw.posix_io;

const ProcessKind = trace.ProcessKind;

fn eventKindName(kind: u8) []const u8 {
    const e: trace.TraceEventKind = @enumFromInt(kind);
    return switch (e) {
        .ring_send => "ring_send",
        .ring_recv => "ring_recv",
        .ring_try_recv_miss => "ring_try_recv_miss",
        .ring_full => "ring_full",
        .ring_empty => "ring_empty",
        .ffi_ring_write => "ffi_ring_write",
        .ffi_ring_read => "ffi_ring_read",
        .router_dispatch => "router_dispatch",
        .channel_send => "channel_send",
        .channel_recv => "channel_recv",
    };
}

fn processKindName(proc: u8) []const u8 {
    const p: ProcessKind = @enumFromInt(proc);
    return switch (p) {
        .unknown => "unknown",
        .ui_process => "ui_process",
        .web_process => "web_process",
        .net_process => "net_process",
        .gpu_process => "gpu_process",
        _ => "unknown",
    };
}

pub fn drainLoop(tr: *trace.TraceRing, path: [*:0]const u8) void {
    const path_slice = std.mem.span(path);

    if (path_slice.len == 0) {
        drainToStderr(tr);
        return;
    }

    const fd = posix_io.fileOpen(path_slice) catch {
        std.debug.print("[hajr/trace] failed to open trace file\n", .{});
        return;
    };
    posix_io.fileTruncate(fd, 0) catch {};
    defer posix_io.fileClose(fd);

    var offset: u64 = 0;
    const writeAll = struct {
        fn write(f: std.posix.fd_t, data: []const u8, off: *u64) void {
            var written: u64 = 0;
            while (written < data.len) {
                const n = posix_io.fileWrite(f, data[written..], off.*) catch return;
                written += n;
                off.* += n;
            }
        }
    };

    writeAll.write(fd, "[\n", &offset);

    var first: bool = true;
    var idle_count: u32 = 0;

    while (true) {
        const tail = tr.tail.load(.acquire);
        const head = tr.head.load(.acquire);

        if (tail == head) {
            idle_count += 1;
            const ns: u64 = if (idle_count > 1000) 1_000_000 else 100_000;
            posix_io.sleepNs(ns);
            continue;
        }
        idle_count = 0;

        const idx = tail % trace.TRACE_SLOTS;
        const slot = &tr.slots[idx];

        if (@atomicLoad(u8, &slot.occupied, .acquire) == 0) {
            tr.tail.store(tail + 1, .release);
            continue;
        }

        const rec = slot.*;

        @atomicStore(u8, &slot.occupied, 0, .release);
        tr.tail.store(tail + 1, .release);

        if (!first) {
            writeAll.write(fd, ",\n", &offset);
        }
        first = false;

        var buf: [256]u8 = undefined;
        const event_name = eventKindName(rec.event_kind);
        const src_name = processKindName(rec.source_proc);
        const dst_name = processKindName(rec.target_proc);
        const line = std.fmt.bufPrint(
            &buf,
            "  {{\"ph\":\"i\",\"ts\":{d},\"name\":\"{s}\",\"args\":{{\"seq\":{d},\"src\":\"{s}\",\"dst\":\"{s}\",\"len\":{d},\"tier_src\":{d},\"tier_dst\":{d}}}}}",
            .{
                rec.timestamp_ns / 1000,
                event_name,
                rec.ipc_sequence,
                src_name,
                dst_name,
                rec.payload_len,
                rec.source_tier,
                rec.target_tier,
            },
        ) catch continue;

        writeAll.write(fd, line, &offset);
    }
}

fn drainToStderr(tr: *trace.TraceRing) void {
    const stderr: std.posix.fd_t = 2;
    var offset: u64 = 0;

    while (true) {
        const tail = tr.tail.load(.acquire);
        const head = tr.head.load(.acquire);

        if (tail == head) {
            posix_io.sleepNs(1_000_000);
            continue;
        }

        const idx = tail % trace.TRACE_SLOTS;
        const slot = &tr.slots[idx];

        if (@atomicLoad(u8, &slot.occupied, .acquire) == 0) {
            tr.tail.store(tail + 1, .release);
            continue;
        }

        const rec = slot.*;
        @atomicStore(u8, &slot.occupied, 0, .release);
        tr.tail.store(tail + 1, .release);

        var buf: [512]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &buf,
            "[hajr/trace] ts={d} event={s} src={s} dst={s} seq={d} len={d}\n",
            .{
                rec.timestamp_ns,
                eventKindName(rec.event_kind),
                processKindName(rec.source_proc),
                processKindName(rec.target_proc),
                rec.ipc_sequence,
                rec.payload_len,
            },
        ) catch continue;

        _ = posix_io.fileWrite(stderr, msg, offset) catch 0;
        offset = 0;
    }
}
