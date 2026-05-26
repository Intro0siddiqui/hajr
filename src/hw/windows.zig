//! Windows-specific implementations for Hajr.

pub const memory = @import("windows/memory.zig");
pub const file_io = @import("windows/file_io.zig");
pub const time = @import("windows/time.zig");
pub const exception = @import("windows/exception.zig");
pub const mitigations = @import("windows/mitigations.zig");
