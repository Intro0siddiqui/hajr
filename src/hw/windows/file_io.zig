//! Windows file I/O for Hajr.
//!
//! Wraps CreateFileW, CloseHandle, SetFilePointerEx, WriteFile, ReadFile, SetEndOfFile.
//! All paths are converted from UTF-8 to UTF-16LE for Windows API compatibility.

const std = @import("std");
const windows = std.os.windows;

// Win32 Constants
const GENERIC_READ: windows.DWORD = 0x80000000;
const GENERIC_WRITE: windows.DWORD = 0x40000000;
const FILE_SHARE_READ: windows.DWORD = 0x00000001;
const OPEN_ALWAYS: windows.DWORD = 4;
const FILE_ATTRIBUTE_NORMAL: windows.DWORD = 0x00000080;
const FILE_BEGIN: windows.DWORD = 0;
const FILE_CURRENT: windows.DWORD = 1;
const FILE_END: windows.DWORD = 2;

// Win32 API Functions
extern "kernel32" fn CreateFileW(
    lpFileName: windows.LPCWSTR,
    dwDesiredAccess: windows.DWORD,
    dwShareMode: windows.DWORD,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: windows.DWORD,
    dwFlagsAndAttributes: windows.DWORD,
    hTemplateFile: ?windows.HANDLE,
) callconv(.winapi) windows.HANDLE;

extern "kernel32" fn CloseHandle(
    hObject: windows.HANDLE,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn SetFilePointerEx(
    hFile: windows.HANDLE,
    liDistanceToMove: windows.LARGE_INTEGER,
    lpNewFilePointer: ?*windows.LARGE_INTEGER,
    dwMoveMethod: windows.DWORD,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn WriteFile(
    hFile: windows.HANDLE,
    lpBuffer: [*]const u8,
    nNumberOfBytesToWrite: windows.DWORD,
    lpNumberOfBytesWritten: ?*windows.DWORD,
    lpOverlapped: ?*anyopaque,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn ReadFile(
    hFile: windows.HANDLE,
    lpBuffer: [*]u8,
    nNumberOfBytesToRead: windows.DWORD,
    lpNumberOfBytesRead: ?*windows.DWORD,
    lpOverlapped: ?*anyopaque,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn SetEndOfFile(
    hFile: windows.HANDLE,
) callconv(.winapi) windows.BOOL;

/// Platform-specific handle type.
pub const OsHandle = windows.HANDLE;

/// Sentinel value for an invalid handle.
pub const INVALID_HANDLE: OsHandle = windows.INVALID_HANDLE_VALUE;

/// Open a file with read/write access, creating it if it doesn't exist.
pub fn fileOpen(path: []const u8) !OsHandle {
    const path_w = try std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, path);
    defer std.heap.page_allocator.free(path_w);
    const handle = CreateFileW(
        path_w,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        null,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (handle == INVALID_HANDLE) return error.FileOpenFailed;
    return handle;
}

/// Close a file handle.
pub fn fileClose(handle: OsHandle) void {
    _ = CloseHandle(handle);
}

/// Truncate a file to a given size.
pub fn fileTruncate(handle: OsHandle, size: u64) !void {
    const distance: windows.LARGE_INTEGER = @intCast(size);
    _ = SetFilePointerEx(handle, distance, null, FILE_BEGIN);
    const ok = SetEndOfFile(handle);
    if (!ok) return error.TruncateFailed;
}

/// Write data to a file at a given offset. Returns bytes written.
pub fn fileWrite(handle: OsHandle, data: []const u8, offset: u64) !u64 {
    const distance: windows.LARGE_INTEGER = @intCast(offset);
    _ = SetFilePointerEx(handle, distance, null, FILE_BEGIN);
    var written: windows.DWORD = 0;
    const ok = WriteFile(handle, data.ptr, @intCast(data.len), &written, null);
    if (!ok) return error.WriteFailed;
    return written;
}

/// Read data from a file at a given offset. Returns bytes read.
pub fn fileRead(handle: OsHandle, buffer: []u8, offset: u64) !u64 {
    const distance: windows.LARGE_INTEGER = @intCast(offset);
    _ = SetFilePointerEx(handle, distance, null, FILE_BEGIN);
    var read: windows.DWORD = 0;
    const ok = ReadFile(handle, buffer.ptr, @intCast(buffer.len), &read, null);
    if (!ok) return error.ReadFailed;
    return read;
}

/// Seek to a position in a file. Returns the new offset.
pub fn fileSeek(handle: OsHandle, offset: i64, origin: i32) !u64 {
    const move_method: windows.DWORD = switch (origin) {
        0 => FILE_BEGIN,
        1 => FILE_CURRENT,
        2 => FILE_END,
        else => return error.InvalidArgument,
    };
    var new_pos: windows.LARGE_INTEGER = 0;
    const ok = SetFilePointerEx(handle, offset, &new_pos, move_method);
    if (!ok) return error.SeekFailed;
    return @intCast(new_pos);
}
