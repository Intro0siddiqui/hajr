const std = @import("std");
const builtin = @import("builtin");
const sandbox = @import("../core/sandbox.zig");

pub const Permission = enum {
    none,
    read_only,
    read_write,
};

/// Unified interface for hardware-assisted memory protection
pub const ProtectionProvider = struct {
    pub const Impl = if (builtin.os.tag == .linux and builtin.cpu.arch == .x86_64)
        X86LinuxProvider
    else if (builtin.os.tag == .macos)
        MacOSProvider
    else
        GenericProvider;

    pub fn setProtection(key: u32, perm: Permission) void {
        Impl.setProtection(key, perm);
    }

    pub fn applyToRegion(ptr: [*]u8, len: usize, key: u32) !void {
        return Impl.applyToRegion(ptr, len, key);
    }
};

/// Implementation for Linux x86_64 using Intel MPK
const X86LinuxProvider = struct {
    fn setProtection(key: u32, perm: Permission) void {
        switch (perm) {
            .none => sandbox.MPK.wrpkru.disableAccess(key),
            .read_only => sandbox.MPK.wrpkru.enableReadOnly(key),
            .read_write => sandbox.MPK.wrpkru.enableFullAccess(key),
        }
    }

    fn applyToRegion(ptr: [*]u8, len: usize, key: u32) !void {
        // pkey_mprotect syscall
        const SYS_pkey_mprotect = 329;
        const PROT_READ = 0x1;
        const PROT_WRITE = 0x2;
        const res = std.os.linux.syscall6(
            SYS_pkey_mprotect,
            @intFromPtr(ptr),
            len,
            PROT_READ | PROT_WRITE,
            key,
            0,
            0
        );
        if (res != 0) return error.ProtectionFailed;
    }
};

/// Implementation for macOS (Fallback to mprotect)
const MacOSProvider = struct {
    fn setProtection(key: u32, perm: Permission) void {
        // macOS doesn't support user-space PKRU.
        // We track the 'intended' state here or use it to trigger mprotect calls.
        _ = key;
        _ = perm;
    }

    fn applyToRegion(ptr: [*]u8, len: usize, key: u32) !void {
        _ = key;
        // Fallback to standard POSIX mprotect
        const PROT_READ = 0x1;
        const PROT_WRITE = 0x2;
        // In a real implementation, we would map the 'key' to specific mprotect flags
        // For now, we ensure it's at least accessible.
        const res = std.posix.mprotect(ptr[0..len], PROT_READ | PROT_WRITE);
        _ = res catch return error.ProtectionFailed;
    }
};

/// Generic fallback for other platforms
const GenericProvider = struct {
    fn setProtection(key: u32, perm: Permission) void {
        _ = key;
        _ = perm;
    }

    fn applyToRegion(ptr: [*]u8, len: usize, key: u32) !void {
        _ = ptr;
        _ = len;
        _ = key;
        return; // No-op
    }
};
