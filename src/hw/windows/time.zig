//! Windows time and process exit for Hajr.
//!
//! Wraps QueryPerformanceCounter, QueryPerformanceFrequency, and ExitProcess.

const std = @import("std");
const windows = std.os.windows;

/// Get a monotonic timestamp in nanoseconds.
pub fn monotonicTimestamp() u64 {
    var freq: windows.LARGE_INTEGER = undefined;
    _ = windows.QueryPerformanceFrequency(&freq);
    var counter: windows.LARGE_INTEGER = undefined;
    _ = windows.QueryPerformanceCounter(&counter);
    const seconds: u64 = @intCast(counter / freq);
    const remainder: u64 = @intCast(counter % freq);
    return seconds * std.time.ns_per_s + (remainder * std.time.ns_per_s) / @as(u64, @intCast(freq));
}

/// Exit the process with a given code.
pub fn exitProcess(code: u8) noreturn {
    windows.ExitProcess(code);
}
