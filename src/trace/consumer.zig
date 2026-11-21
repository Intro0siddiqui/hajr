const std = @import("std");
const builtin = @import("builtin");
const hw = @import("../hw/mod.zig");
const trace = @import("trace.zig");

const posix_io = hw.posix_io;
const windows = hw.windows;

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
        .ipc_send => "ipc_send",
        .ipc_recv => "ipc_recv",
        .policy_event => "policy_event",
        _ => "unknown",
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

    if (path_slice.len == 0 or std.mem.eql(u8, path_slice, "stderr")) {
        drainToStderr(tr);
        return;
    }

    const pid = posix_io.getpid();
    var kind = trace.getProcessKind();
    if (kind == .unknown) {
        var wait_spins: u8 = 0;
        while (wait_spins < 50 and trace.getProcessKind() == .unknown) : (wait_spins += 1) {
            posix_io.sleepNs(1_000_000);
        }
        kind = trace.getProcessKind();
    }
    const kind_tag: []const u8 = switch (kind) {
        .ui_process => "ui",
        .web_process => "web",
        .net_process => "net",
        .gpu_process => "gpu",
        .unknown => "unknown",
        _ => "unknown",
    };

    var resolved_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var resolved_path: []const u8 = undefined;

    if (std.mem.indexOf(u8, path_slice, "%d")) |idx| {
        resolved_path = std.fmt.bufPrint(&resolved_path_buf, "{s}{s}.{d}{s}", .{ path_slice[0..idx], kind_tag, pid, path_slice[idx + 2..] }) catch path_slice;
    } else if (std.mem.lastIndexOfScalar(u8, path_slice, '.')) |dot_idx| {
        resolved_path = std.fmt.bufPrint(&resolved_path_buf, "{s}.{s}.{d}{s}", .{ path_slice[0..dot_idx], kind_tag, pid, path_slice[dot_idx..] }) catch path_slice;
    } else {
        resolved_path = std.fmt.bufPrint(&resolved_path_buf, "{s}.{s}.{d}", .{ path_slice, kind_tag, pid }) catch path_slice;
    }

    const fd = posix_io.fileOpen(resolved_path) catch {
        std.debug.print("[hajr/trace] failed to open trace file: {s}\n", .{resolved_path});
        return;
    };
    posix_io.fileTruncate(fd, 0) catch {};
    defer posix_io.fileClose(fd);

    const is_binary = std.mem.endsWith(u8, resolved_path, ".bin");
    std.debug.print("[hajr/trace] Active -> {s} (pid {d}, format: {s})\n", .{ resolved_path, pid, if (is_binary) "binary" else "chrome_trace_json" });

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

    if (is_binary) {
        const header = "HAJR_TRACE\x01\x00\x00\x00\x00\x00";
        writeAll.write(fd, header, &offset);
    } else {
        writeAll.write(fd, "[\n", &offset);
    }

    var first: bool = true;
    var idle_count: u32 = 0;

    while (true) {
        const tail = tr.tail.load(.acquire);
        const head = tr.head.load(.acquire);

        if (tail == head) {
            idle_count += 1;
            const ns: u64 = if (idle_count > 100) 500_000 else 10_000;
            posix_io.sleepNs(ns);
            continue;
        }
        idle_count = 0;

        const dropped = tr.dropped.swap(0, .acq_rel);
        if (dropped > 0) {
            std.debug.print("[hajr/trace] NOTE: drained ring, {} events dropped under burst\n", .{dropped});
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

        if (is_binary) {
            const raw_rec_bytes = std.mem.asBytes(&rec);
            writeAll.write(fd, raw_rec_bytes, &offset);
        } else {
            if (!first) {
                writeAll.write(fd, ",\n", &offset);
            }
            first = false;

            var buf: [512]u8 = undefined;
            const event_name = eventKindName(rec.event_kind);
            const src_name = processKindName(rec.source_proc);
            const dst_name = processKindName(rec.target_proc);
            const msg_name_opt = trace.getMsgName(rec.msg_type);
            const line = if (rec.event_kind == @intFromEnum(trace.TraceEventKind.policy_event))
                std.fmt.bufPrint(
                    &buf,
                    "  {{\"ph\":\"i\",\"s\":\"p\",\"ts\":{d},\"pid\":{d},\"tid\":{d},\"name\":\"policy_event\",\"args\":{{\"req\":{d},\"action\":{d},\"reason\":{d},\"proc\":\"{s}\"}}}}",
                    .{
                        rec.timestamp_ns / 1000,
                        pid,
                        rec.source_id,
                        rec.source_id,
                        rec.payload_len,
                        rec.msg_type,
                        src_name,
                    },
                ) catch continue
            else if (msg_name_opt) |msg_name|
                std.fmt.bufPrint(
                    &buf,
                    "  {{\"ph\":\"i\",\"s\":\"p\",\"ts\":{d},\"pid\":{d},\"tid\":{d},\"name\":\"{s}\",\"args\":{{\"seq\":{d},\"src\":\"{s}\",\"dst\":\"{s}\",\"len\":{d},\"msg_name\":\"{s}\",\"msg_id\":{d},\"target_id\":{d},\"tier_src\":{d},\"tier_dst\":{d}}}}}",
                    .{
                        rec.timestamp_ns / 1000,
                        pid,
                        rec.source_id,
                        event_name,
                        rec.ipc_sequence,
                        src_name,
                        dst_name,
                        rec.payload_len,
                        msg_name,
                        rec.msg_type,
                        rec.target_id,
                        rec.source_tier,
                        rec.target_tier,
                    },
                ) catch continue
            else
                std.fmt.bufPrint(
                    &buf,
                    "  {{\"ph\":\"i\",\"s\":\"p\",\"ts\":{d},\"pid\":{d},\"tid\":{d},\"name\":\"{s}\",\"args\":{{\"seq\":{d},\"src\":\"{s}\",\"dst\":\"{s}\",\"len\":{d},\"msg_id\":{d},\"target_id\":{d},\"tier_src\":{d},\"tier_dst\":{d}}}}}",
                    .{
                        rec.timestamp_ns / 1000,
                        pid,
                        rec.source_id,
                        event_name,
                        rec.ipc_sequence,
                        src_name,
                        dst_name,
                        rec.payload_len,
                        rec.msg_type,
                        rec.target_id,
                        rec.source_tier,
                        rec.target_tier,
                    },
                ) catch continue;

            writeAll.write(fd, line, &offset);
        }
    }
}

fn drainToStderr(tr: *trace.TraceRing) void {
    const stderr: hw.os.OsHandle = if (builtin.os.tag == .windows)
        windows.GetStdHandle(windows.STD_ERROR_HANDLE)
    else
        2;
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
        const msg_name_opt = trace.getMsgName(rec.msg_type);
        const msg = if (rec.event_kind == @intFromEnum(trace.TraceEventKind.policy_event))
            std.fmt.bufPrint(
                &buf,
                "[hajr/trace] ts={d} event=policy_event req={d} action={d} reason={d} proc={s}\n",
                .{
                    rec.timestamp_ns,
                    rec.source_id,
                    rec.payload_len,
                    rec.msg_type,
                    processKindName(rec.source_proc),
                },
            ) catch continue
        else if (msg_name_opt) |msg_name|
            std.fmt.bufPrint(
                &buf,
                "[hajr/trace] ts={d} event={s} src={s} dst={s} seq={d} len={d} msg={s}({d})\n",
                .{
                    rec.timestamp_ns,
                    eventKindName(rec.event_kind),
                    processKindName(rec.source_proc),
                    processKindName(rec.target_proc),
                    rec.ipc_sequence,
                    rec.payload_len,
                    msg_name,
                    rec.msg_type,
                },
            ) catch continue
        else
            std.fmt.bufPrint(
                &buf,
                "[hajr/trace] ts={d} event={s} src={s} dst={s} seq={d} len={d} msg_id={d}\n",
                .{
                    rec.timestamp_ns,
                    eventKindName(rec.event_kind),
                    processKindName(rec.source_proc),
                    processKindName(rec.target_proc),
                    rec.ipc_sequence,
                    rec.payload_len,
                    rec.msg_type,
                },
            ) catch continue;

        _ = posix_io.fileWrite(stderr, msg, offset) catch 0;
        offset = 0;
    }
}
