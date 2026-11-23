//! Windows-specific implementations for Hajr.

const std = @import("std");

pub const memory = @import("windows/memory.zig");
pub const file_io = @import("windows/file_io.zig");
pub const time = @import("windows/time.zig");
pub const exception = @import("windows/exception.zig");
pub const mitigations = @import("windows/mitigations.zig");

pub const STD_ERROR_HANDLE: std.os.windows.DWORD = @bitCast(@as(i32, -12));
pub extern "kernel32" fn GetStdHandle(nStdHandle: std.os.windows.DWORD) callconv(.winapi) std.os.windows.HANDLE;
pub extern "kernel32" fn GetProcessId(Process: std.os.windows.HANDLE) callconv(.winapi) std.os.windows.DWORD;
