//! Windows time and process exit for Hajr.
//!
//! Wraps QueryPerformanceCounter, QueryPerformanceFrequency, and ExitProcess.

const std = @import("std");
const windows = std.os.windows;

// Win32 API Functions
extern "kernel32" fn QueryPerformanceFrequency(lpFrequency: *windows.LARGE_INTEGER) callconv(.winapi) windows.BOOL;
extern "kernel32" fn QueryPerformanceCounter(lpPerformanceCount: *windows.LARGE_INTEGER) callconv(.winapi) windows.BOOL;
extern "kernel32" fn ExitProcess(uExitCode: windows.UINT) callconv(.winapi) noreturn;

/// Get a monotonic timestamp in nanoseconds.
pub fn monotonicTimestamp() u64 {
    var freq: windows.LARGE_INTEGER = undefined;
    _ = QueryPerformanceFrequency(&freq);
    var counter: windows.LARGE_INTEGER = undefined;
    _ = QueryPerformanceCounter(&counter);
    const seconds: u64 = @intCast(@divTrunc(counter, freq));
    const remainder: u64 = @intCast(@mod(counter, freq));
    return seconds * std.time.ns_per_s + (remainder * std.time.ns_per_s) / @as(u64, @intCast(freq));
}

/// Exit the process with a given code.
pub fn exitProcess(code: u8) noreturn {
    ExitProcess(code);
}
