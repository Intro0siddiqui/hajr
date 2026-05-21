//! Windows exception handler using Vectored Exception Handling (VEH).
//!
//! Equivalent to POSIX sigaction(SIGSEGV/SIGBUS). Uses AddVectoredExceptionHandler
//! to catch EXCEPTION_ACCESS_VIOLATION (hardware memory protection faults).

const std = @import("std");
const windows = std.os.windows;

/// Information about a hardware memory fault.
pub const FaultInfo = struct {
    /// The memory address that caused the fault.
    address: usize,
    /// Whether the fault was caused by a write access.
    is_write: bool,
    /// Whether the fault was caused by an execute access.
    is_exec: bool,
};

/// Callback type for fault handlers.
pub const FaultHandlerFn = *const fn (info: FaultInfo) callconv(.C) void;

var registered_handler: ?FaultHandlerFn = null;

/// Register a handler for hardware memory protection faults.
/// Uses AddVectoredExceptionHandler to catch EXCEPTION_ACCESS_VIOLATION.
pub fn registerFaultHandler(handler: FaultHandlerFn) void {
    registered_handler = handler;
    _ = windows.AddVectoredExceptionHandler(1, @ptrCast(vehAdapter));
}

/// VEH adapter function. Called by Windows when any exception occurs.
/// Filters for EXCEPTION_ACCESS_VIOLATION (memory protection faults).
fn vehAdapter(exception_info: *windows.EXCEPTION_POINTERS) callconv(.C) windows.LONG {
    const record = exception_info.ExceptionRecord;
    if (record.ExceptionCode != windows.STATUS_ACCESS_VIOLATION) {
        return windows.EXCEPTION_CONTINUE_SEARCH;
    }
    const info = FaultInfo{
        .address = @intFromPtr(record.ExceptionInformation[1]),
        .is_write = record.ExceptionInformation[0] == 1,
        .is_exec = record.ExceptionInformation[0] == 8,
    };
    if (registered_handler) |h| {
        h(info);
        return windows.EXCEPTION_CONTINUE_EXECUTION;
    }
    windows.ExitProcess(1);
}
