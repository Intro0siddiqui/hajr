const std = @import("std");
const hajr = @import("hajr");
const hw = hajr.hw;
const ipc = hajr.ipc;

/// Cross-thread IPC ping-pong benchmark.
/// Uses two rings: Ring A (main->worker) and Ring B (worker->main).
/// Worker spins on Ring A and echoes back on Ring B.
/// Main measures round-trip latency.
pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const ring_req = try ipc.IpcRing.create(ipc.RING_SLOTS, .{ .value = 1, .tier = 1, .is_dynamic = false }, .trusted, .untrusted);
    defer ring_req.destroy();
    const ring_resp = try ipc.IpcRing.create(ipc.RING_SLOTS, .{ .value = 2, .tier = 2, .is_dynamic = false }, .untrusted, .trusted);
    defer ring_resp.destroy();

    const warmup_iters: u64 = 10_000;
    const bench_iters: u64 = 100_000;

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    var worker_ready = std.atomic.Value(bool).init(false);
    var worker_done = std.atomic.Value(bool).init(false);

    // Worker: recv on req ring, echo back on resp ring
    const worker = try std.Thread.spawn(.{}, struct {
        fn run(req: *ipc.IpcRing, resp: *ipc.IpcRing, ready: *std.atomic.Value(bool), done: *std.atomic.Value(bool)) void {
            var b: std.ArrayListUnmanaged(u8) = .empty;
            defer b.deinit(std.heap.page_allocator);
            ready.store(true, .release);
            while (!done.load(.acquire)) {
                if (req.tryRecv(std.heap.page_allocator, &b)) |hdr| {
                    resp.send(@as(ipc.IpcMessageType, @enumFromInt(hdr.msg_type)), 2, 1, b.items) catch {};
                }
            }
        }
    }.run, .{ ring_req, ring_resp, &worker_ready, &worker_done });
    defer {
        worker_done.store(true, .release);
        worker.join();
    }

    // Wait for worker to start
    while (!worker_ready.load(.acquire)) {
        std.atomic.spinLoopHint();
    }

    std.debug.print("Cross-Thread IPC Latency Benchmark\n", .{});
    std.debug.print("==================================\n", .{});
    std.debug.print("Warm-up: {d} iterations\n", .{warmup_iters});

    // Warm-up
    for (0..warmup_iters) |_| {
        try ring_req.send(.heartbeat, 1, 2, "");
        while (ring_resp.tryRecv(allocator, &buf) == null) {
            std.atomic.spinLoopHint();
        }
    }

    std.debug.print("Benchmark: {d} iterations\n\n", .{bench_iters});

    // Measure timer overhead
    var timer_total: u128 = 0;
    for (0..bench_iters) |_| {
        const t0 = hw.os.monotonicTimestamp();
        const t1 = hw.os.monotonicTimestamp();
        timer_total += (t1 - t0);
    }
    const timer_overhead = @as(f64, @floatFromInt(timer_total)) / @as(f64, @floatFromInt(bench_iters));

    const latencies = try allocator.alloc(u64, @as(usize, @intCast(bench_iters)));
    defer allocator.free(latencies);

    var total_ns: u128 = 0;
    var min_ns: u64 = std.math.maxInt(u64);
    var max_ns: u64 = 0;

    // Benchmark: round-trip IPC (send request + spin-wait for response)
    for (0..@as(usize, @intCast(bench_iters))) |i| {
        const start = hw.os.monotonicTimestamp();

        try ring_req.send(.heartbeat, 1, 2, "");
        while (ring_resp.tryRecv(allocator, &buf) == null) {
            std.atomic.spinLoopHint();
        }

        const end = hw.os.monotonicTimestamp();

        const diff = end - start;
        latencies[i] = @as(u64, @intCast(diff));
        total_ns += diff;
        if (diff < min_ns) min_ns = @as(u64, @intCast(diff));
        if (diff > max_ns) max_ns = @as(u64, @intCast(diff));
    }

    // Sort for percentile
    std.mem.sort(u64, latencies, {}, struct {
        fn lessThan(_: void, lhs: u64, rhs: u64) bool {
            return lhs < rhs;
        }
    }.lessThan);

    const avg_roundtrip = @as(f64, @floatFromInt(total_ns)) / @as(f64, @floatFromInt(bench_iters));
    const pure_roundtrip = avg_roundtrip - timer_overhead;
    const one_way = pure_roundtrip / 2.0;
    const p99_latency = latencies[@as(usize, @intCast(bench_iters * 99 / 100))];

    std.debug.print("Results (Round-Trip = send req + recv resp):\n", .{});
    std.debug.print("--------------------------------------------\n", .{});
    std.debug.print("Average Round-Trip:    {d:.2} ns\n", .{avg_roundtrip});
    std.debug.print("Timer Overhead:        {d:.2} ns\n", .{timer_overhead});
    std.debug.print("Pure Round-Trip:       {d:.2} ns\n", .{pure_roundtrip});
    std.debug.print("Est. One-Way Latency:  {d:.2} ns\n", .{one_way});
    std.debug.print("99th Percentile (RTT): {d} ns\n", .{p99_latency});
    std.debug.print("Minimum (RTT):         {d} ns\n", .{min_ns});
    std.debug.print("Maximum (RTT):         {d} ns\n", .{max_ns});

    std.debug.print("\nNote: This measures lock-free ring buffer IPC between\n", .{});
    std.debug.print("two threads on the same core. Real cross-sandbox IPC\n", .{});
    std.debug.print("would add PKRU domain switching and cross-core latency.\n", .{});
}
