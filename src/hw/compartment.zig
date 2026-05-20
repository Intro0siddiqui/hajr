const std = @import("std");
const builtin = @import("builtin");

/// A unified token representing a hardware compartment (PKEY on x86, MTE Tag on ARM)
pub const CompartmentToken = struct {
    id: u32,
};

/// Cross-platform compartment allocator
pub const CompartmentAllocator = struct {
    used_mask: u16 = 0,
    mpk_supported: ?bool = null,

    pub fn init() CompartmentAllocator {
        return .{};
    }

    pub fn detectMpk(self: *CompartmentAllocator) bool {
        if (self.mpk_supported) |supported| return supported;
        if (comptime builtin.cpu.arch == .x86_64 and builtin.os.tag == .linux) {
            const pkey = pkey_alloc(0, 0) catch {
                self.mpk_supported = false;
                return false;
            };
            _ = pkey_free(pkey) catch {};
            self.mpk_supported = true;
            return true;
        }
        self.mpk_supported = false;
        return false;
    }

    /// Allocates a new compartment token.
    /// On Linux/x86_64, this uses the pkey_alloc syscall.
    /// On AArch64, this implements a logical tag allocator (0-15).
    pub fn alloc(self: *CompartmentAllocator) !CompartmentToken {
        if (self.detectMpk()) {
            const pkey = try pkey_alloc(0, 0);
            const id: u32 = @intCast(pkey);
            // Track used key (0-15)
            self.used_mask |= (@as(u16, 1) << @intCast(id & 0xF));
            return CompartmentToken{ .id = id };
        } else {
            // AArch64 or Fallback: Logical Tag Allocator (0-15)
            for (0..16) |i| {
                const mask = @as(u16, 1) << @intCast(i);
                if (self.used_mask & mask == 0) {
                    self.used_mask |= mask;
                    return CompartmentToken{ .id = @intCast(i) };
                }
            }
            return if (builtin.cpu.arch == .aarch64) error.NoAvailableTags else error.NoAvailableKeys;
        }
    }

    /// Frees a compartment token.
    pub fn free(self: *CompartmentAllocator, token: CompartmentToken) void {
        const mask = @as(u16, 1) << @intCast(token.id & 0xF);
        if (self.used_mask & mask != 0) {
            if (self.detectMpk()) {
                _ = pkey_free(@intCast(token.id)) catch {};
            }
            self.used_mask &= ~mask;
        }
    }
};

/// Global compartment allocator for the system.
pub var global_allocator = CompartmentAllocator.init();

pub const PkeyError = error{
    InvalidArgument,
    NoSpace,
    SystemNotSupported,
    Unexpected,
};

pub const PkeyFreeError = error{
    InvalidArgument,
    SystemNotSupported,
    Unexpected,
};

/// Wrapper for pkey_alloc syscall on Linux
fn pkey_alloc(flags: u32, access_rights: u32) PkeyError!i32 {
    if (builtin.os.tag != .linux) @compileError("pkey_alloc is Linux-only");

    const res = std.os.linux.syscall2(.pkey_alloc, flags, access_rights);
    const signed_res = @as(isize, @bitCast(res));
    
    // Check for error (Linux returns -errno)
    if (signed_res < 0 and signed_res > -4096) {
        const err = -signed_res;
        return switch (err) {
            22 => error.InvalidArgument, // EINVAL
            28 => error.NoSpace,        // ENOSPC
            38 => error.SystemNotSupported, // ENOSYS
            else => error.Unexpected,
        };
    }
    return @intCast(res);
}

/// Wrapper for pkey_free syscall on Linux
fn pkey_free(pkey: i32) PkeyFreeError!void {
    if (builtin.os.tag != .linux) @compileError("pkey_free is Linux-only");

    const res = std.os.linux.syscall1(.pkey_free, @as(u64, @intCast(pkey)));
    const signed_res = @as(isize, @bitCast(res));
    
    if (signed_res < 0 and signed_res > -4096) {
        const err = -signed_res;
        return switch (err) {
            22 => error.InvalidArgument, // EINVAL
            38 => error.SystemNotSupported, // ENOSYS
            else => error.Unexpected,
        };
    }
}
