//! Windows memory management for Hajr.
//!
//! Wraps VirtualAlloc, VirtualFree, and VirtualProtect for page-aligned
//! anonymous memory allocation and protection.

const std = @import("std");
const windows = std.os.windows;

const page_size = std.heap.page_size_min;

// Win32 Constants
const MEM_COMMIT = 0x00001000;
const MEM_RELEASE = 0x00008000;
const PAGE_NOACCESS = 0x00000001;
const PAGE_READONLY = 0x00000002;
const PAGE_READWRITE = 0x00000004;

// Win32 API Functions
extern "kernel32" fn VirtualAlloc(
    lpAddress: ?windows.LPVOID,
    dwSize: windows.SIZE_T,
    flAllocationType: windows.DWORD,
    flProtect: windows.DWORD,
) callconv(.winapi) ?windows.LPVOID;

extern "kernel32" fn VirtualFree(
    lpAddress: windows.LPVOID,
    dwSize: windows.SIZE_T,
    dwFreeType: windows.DWORD,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn VirtualProtect(
    lpAddress: windows.LPVOID,
    dwSize: windows.SIZE_T,
    flNewProtect: windows.DWORD,
    lpflOldProtect: *windows.DWORD,
) callconv(.winapi) windows.BOOL;

/// Allocate a page-aligned anonymous memory region.
/// Equivalent to: VirtualAlloc(MEM_COMMIT, PAGE_READWRITE)
pub fn memAlloc(size: usize) ![]align(page_size) u8 {
    const ptr = VirtualAlloc(
        null,
        size,
        MEM_COMMIT,
        PAGE_READWRITE,
    ) orelse return error.AllocationFailed;
    return @as([*]align(page_size) u8, @ptrCast(@alignCast(ptr)))[0..size];
}

/// Free a previously allocated memory region.
/// Equivalent to: VirtualFree(MEM_RELEASE)
pub fn memFree(region: []align(page_size) u8) void {
    _ = VirtualFree(region.ptr, 0, MEM_RELEASE);
}

/// Change protection on a memory region.
/// Equivalent to: VirtualProtect
pub fn memProtect(ptr: [*]u8, len: usize, read: bool, write: bool) !void {
    var old_protect: windows.DWORD = undefined;
    const protect = if (!read and !write)
        PAGE_NOACCESS
    else if (read and !write)
        PAGE_READONLY
    else
        PAGE_READWRITE;
    const ok = VirtualProtect(ptr, len, protect, &old_protect);
    if (!ok) return error.ProtectionFailed;
}
