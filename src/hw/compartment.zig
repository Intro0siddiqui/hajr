const std = @import("std");
const builtin = @import("builtin");
const os_abs = @import("os_abstraction.zig");

/// A unified token representing a hardware compartment (PKEY on x86, MTE Tag on ARM)
pub const CompartmentToken = struct {
    id: u32,
};

/// Cross-platform compartment allocator
pub const CompartmentAllocator = struct {
    used_mask: u16 = 0,
    mpk_supported: ?bool = null,
    pac_supported: ?bool = null,

    pub fn init() CompartmentAllocator {
        return .{};
    }

    pub fn detectMpk(self: *CompartmentAllocator) bool {
        if (self.mpk_supported) |supported| return supported;
        if (comptime builtin.cpu.arch == .x86_64 and builtin.os.tag == .linux) {
            const pkey = os_abs.pkeyAlloc(0, 0) catch {
                self.mpk_supported = false;
                return false;
            };
            _ = os_abs.pkeyFree(pkey) catch {};
            self.mpk_supported = true;
            return true;
        }
        self.mpk_supported = false;
        return false;
    }

    pub fn detectPac(self: *CompartmentAllocator) bool {
        if (self.pac_supported) |supported| return supported;
        if (comptime builtin.cpu.arch == .aarch64) {
            if (builtin.os.tag == .macos) {
                self.pac_supported = true;
                return true;
            }
            if (builtin.os.tag == .linux) {
                const os = @import("os_abstraction.zig");
                const hwcap = os.getHwcap();
                const supported = (hwcap & 0x10000) != 0; // HWCAP_PACA
                self.pac_supported = supported;
                return supported;
            }
        }
        self.pac_supported = false;
        return false;
    }

    /// Allocates a new compartment token.
    /// On Linux/x86_64, this uses the pkey_alloc syscall.
    /// On AArch64, this implements a logical tag allocator (0-15).
    pub fn alloc(self: *CompartmentAllocator) !CompartmentToken {
        if (self.detectMpk()) {
            const pkey = try os_abs.pkeyAlloc(0, 0);
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
                _ = os_abs.pkeyFree(@intCast(token.id)) catch {};
            }
            self.used_mask &= ~mask;
        }
    }
};

/// Global compartment allocator for the system.
pub var global_allocator = CompartmentAllocator.init();
