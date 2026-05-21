//! Windows file I/O for Hajr.
//!
//! Wraps CreateFileW, CloseHandle, SetFilePointerEx, WriteFile, ReadFile, SetEndOfFile.
//! All paths are converted from UTF-8 to UTF-16LE for Windows API compatibility.

const std = @import("std");
const windows = std.os.windows;

/// Platform-specific handle type.
pub const OsHandle = windows.HANDLE;

/// Sentinel value for an invalid handle.
pub const INVALID_HANDLE: OsHandle = windows.INVALID_HANDLE_VALUE;

/// Open a file with read/write access, creating it if it doesn't exist.
pub fn fileOpen(path: []const u8) !OsHandle {
    const path_w = try std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, path);
    defer std.heap.page_allocator.free(path_w);
    const handle = windows.CreateFileW(
        path_w,
        windows.GENERIC_READ | windows.GENERIC_WRITE,
        windows.FILE_SHARE_READ,
        null,
        windows.OPEN_ALWAYS,
        windows.FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (handle == windows.INVALID_HANDLE_VALUE) return error.FileOpenFailed;
    return handle;
}

/// Close a file handle.
pub fn fileClose(handle: OsHandle) void {
    _ = windows.CloseHandle(handle);
}

/// Truncate a file to a given size.
pub fn fileTruncate(handle: OsHandle, size: u64) !void {
    const distance: windows.LARGE_INTEGER = @intCast(size);
    _ = windows.SetFilePointerEx(handle, distance, null, windows.FILE_BEGIN);
    const ok = windows.SetEndOfFile(handle);
    if (!ok) return error.TruncateFailed;
}

/// Write data to a file at a given offset. Returns bytes written.
pub fn fileWrite(handle: OsHandle, data: []const u8, offset: u64) !u64 {
    const distance: windows.LARGE_INTEGER = @intCast(offset);
    _ = windows.SetFilePointerEx(handle, distance, null, windows.FILE_BEGIN);
    var written: windows.DWORD = 0;
    const ok = windows.WriteFile(handle, data, &written, null);
    if (!ok) return error.WriteFailed;
    return written;
}

/// Read data from a file at a given offset. Returns bytes read.
pub fn fileRead(handle: OsHandle, buffer: []u8, offset: u64) !u64 {
    const distance: windows.LARGE_INTEGER = @intCast(offset);
    _ = windows.SetFilePointerEx(handle, distance, null, windows.FILE_BEGIN);
    var read: windows.DWORD = 0;
    const ok = windows.ReadFile(handle, buffer, &read, null);
    if (!ok) return error.ReadFailed;
    return read;
}
