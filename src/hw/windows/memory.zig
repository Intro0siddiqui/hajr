//! Windows memory management for Hajr.
//!
//! Wraps VirtualAlloc, VirtualFree, and VirtualProtect for page-aligned
//! anonymous memory allocation and protection.

const std = @import("std");
const windows = std.os.windows;

/// Allocate a page-aligned anonymous memory region.
/// Equivalent to: VirtualAlloc(MEM_COMMIT, PAGE_READWRITE)
pub fn memAlloc(size: usize) ![]align(4096) u8 {
    const ptr = windows.VirtualAlloc(
        null,
        size,
        windows.MEM_COMMIT,
        windows.PAGE_READWRITE,
    ) orelse return error.AllocationFailed;
    return @as([*]align(4096) u8, @ptrCast(@alignCast(ptr)))[0..size];
}

/// Free a previously allocated memory region.
/// Equivalent to: VirtualFree(MEM_RELEASE)
pub fn memFree(region: []align(4096) u8) void {
    _ = windows.VirtualFree(region.ptr, 0, windows.MEM_RELEASE);
}

/// Change protection on a memory region.
/// Equivalent to: VirtualProtect
pub fn memProtect(ptr: [*]u8, len: usize, read: bool, write: bool) !void {
    var old_protect: windows.DWORD = undefined;
    const protect = if (!read and !write)
        windows.PAGE_NOACCESS
    else if (read and !write)
        windows.PAGE_READONLY
    else
        windows.PAGE_READWRITE;
    const ok = windows.VirtualProtect(ptr, len, protect, &old_protect);
    if (!ok) return error.ProtectionFailed;
}
