const std = @import("std");
const hajr = @import("hajr");
const hw = hajr.hw;
const ipc = hajr.ipc;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Initialize two IpcRing buffers (Producer -> Consumer)
    // We create two as requested, although we focus on one-way latency for precise measurement.
    const ring1 = try ipc.IpcRing.create(ipc.RING_SLOTS, 1, .trusted, .untrusted);
    defer ring1.destroy();
    const ring2 = try ipc.IpcRing.create(ipc.RING_SLOTS, 2, .untrusted, .trusted);
    defer ring2.destroy();

    const warmup_iters = 10_000;
    const bench_iters = 1_000_000;

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    std.debug.print("Starting IPC Latency Benchmark...\n", .{});
    std.debug.print("Warm-up: {d} iterations\n", .{warmup_iters});

    // Warm-up to JIT/cache the code paths
    for (0..warmup_iters) |_| {
        try ring1.send(.heartbeat, 1, 2, "");
        _ = try ring1.recv(allocator, &buf);
    }

    std.debug.print("Benchmark: {d} iterations\n", .{bench_iters});

    // Measure timing overhead
    var timer_total: u128 = 0;
    for (0..bench_iters) |_| {
        const t0 = hw.os.monotonicTimestamp();
        const t1 = hw.os.monotonicTimestamp();
        timer_total += (t1 - t0);
    }
    const timer_overhead = @as(f64, @floatFromInt(timer_total)) / @as(f64, @floatFromInt(bench_iters));

    const latencies = try allocator.alloc(u64, bench_iters);
    defer allocator.free(latencies);

    var total_ns: u128 = 0;
    var min_ns: u64 = std.math.maxInt(u64);
    var max_ns: u64 = 0;

    // Run the benchmark
    for (0..bench_iters) |i| {
        const start = hw.os.monotonicTimestamp();
        
        // One-way IPC operation: Send + Receive
        try ring1.send(.heartbeat, 1, 2, "");
        _ = try ring1.recv(allocator, &buf);
        
        const end = hw.os.monotonicTimestamp();
        
        const diff = end - start;
        latencies[i] = diff;
        total_ns += diff;
        if (diff < min_ns) min_ns = diff;
        if (diff > max_ns) max_ns = diff;
    }

    // Sort latencies for percentile calculation
    std.mem.sort(u64, latencies, {}, struct {
        fn lessThan(_: void, lhs: u64, rhs: u64) bool {
            return lhs < rhs;
        }
    }.lessThan);

    const avg_latency = @as(f64, @floatFromInt(total_ns)) / @as(f64, @floatFromInt(bench_iters));
    const pure_logic_latency = avg_latency - timer_overhead;
    const p99_latency = latencies[bench_iters * 99 / 100];

    std.debug.print("\nBenchmark Results:\n", .{});
    std.debug.print("------------------\n", .{});
    std.debug.print("Average Measured:   {d:.2} ns\n", .{avg_latency});
    std.debug.print("Timer Overhead:     {d:.2} ns\n", .{timer_overhead});
    std.debug.print("Est. Pure Logic:    {d:.2} ns (Send + Recv)\n", .{pure_logic_latency});
    const overhead_per_op = pure_logic_latency / 2.0; 
    std.debug.print("Est. Per-Op Latency: {d:.2} ns\n", .{overhead_per_op});
    std.debug.print("99th Percentile:    {d} ns\n", .{p99_latency});
    std.debug.print("Minimum Latency:    {d} ns\n", .{min_ns});
    std.debug.print("Maximum Latency:    {d} ns\n", .{max_ns});

    if (overhead_per_op < 5.0) {
        std.debug.print("\nSuccess: IPC overhead is truly sub-5ns ({d:.2} ns per op)!\n", .{overhead_per_op});
    } else {
        std.debug.print("\nNote: Estimated IPC overhead is {d:.2} ns per op.\n", .{overhead_per_op});
    }
}
