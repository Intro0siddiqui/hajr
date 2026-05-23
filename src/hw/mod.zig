//! Hardware primitives for memory protection (MPK, MTE)
//!
//! This module provides a unified interface for hardware-assisted memory protection
//! across different architectures, including Intel MPK (x86_64) and ARM MTE (AArch64).

const std = @import("std");
const builtin = @import("builtin");

pub const pointer = @import("pointer.zig");
pub const compartment = @import("compartment.zig");
pub const exception = @import("exception.zig");
pub const posix_io = if (builtin.os.tag == .windows) @import("os_abstraction.zig") else @import("posix.zig");
pub const os = @import("os_abstraction.zig");
pub const windows = @import("windows.zig");

extern fn haj_wrpkru(value: u32) callconv(.c) void;
extern fn haj_rdpkru() callconv(.c) u32;

/// Memory protection permissions
pub const Permission = enum {
    none,
    read_only,
    read_write,
};

/// Architecture-specific implementation selection
const arch_impl = if (builtin.cpu.arch == .x86_64)
    if (builtin.os.tag == .linux) X86_64_Linux else X86_64_Portable
else if (builtin.cpu.arch == .aarch64)
    if (builtin.os.tag == .linux) AArch64_Linux else AArch64_Portable
else
    Fallback;

/// Writes the hardware protection key rights (e.g., PKRU register on x86_64)
pub fn writeProtectionKey(value: u32) void {
    arch_impl.writeProtectionKey(value);
}

/// Reads the hardware protection key rights
pub fn readProtectionKey() u32 {
    return arch_impl.readProtectionKey();
}

/// Applies a protection key to a specific memory region.
/// This typically uses system calls like pkey_mprotect (Linux) or tagging (MTE).
pub fn applyProtectionToRegion(ptr: [*]u8, len: usize, key: u32) !void {
    return arch_impl.applyProtectionToRegion(ptr, len, key);
}

/// Sets the permissions for a specific protection key.
/// On x86_64, this modifies the PKRU register.
pub fn setKeyPermission(key: u32, perm: Permission) void {
    arch_impl.setKeyPermission(key, perm);
}

/// x86_64 Linux Implementation using Intel MPK (Memory Protection Keys)
const X86_64_Linux = struct {
    pub fn writeProtectionKey(value: u32) void {
        if (!compartment.global_allocator.detectMpk()) return;
        haj_wrpkru(value);
    }

    pub fn readProtectionKey() u32 {
        if (!compartment.global_allocator.detectMpk()) return 0;
        return haj_rdpkru();
    }

    pub fn setKeyPermission(key: u32, perm: Permission) void {
        if (!compartment.global_allocator.detectMpk()) return;
        var pkru = @This().readProtectionKey();
        const shift: u5 = @intCast(key * 2);
        
        switch (perm) {
            .none => {
                // Disable all access for a key (AD=1, WD=1)
                pkru |= (@as(u32, 0b11) << shift);
            },
            .read_only => {
                // Enable read-only access for a key (AD=0, WD=1)
                pkru &= ~(@as(u32, 0b01) << shift); // Clear AD
                pkru |= (@as(u32, 0b10) << shift);  // Set WD
            },
            .read_write => {
                // Enable full access for a key (AD=0, WD=0)
                pkru &= ~(@as(u32, 0b11) << shift); // Clear AD and WD
            },
        }
        @This().writeProtectionKey(pkru);
    }

    pub fn applyProtectionToRegion(ptr: [*]u8, len: usize, key: u32) !void {
        if (compartment.global_allocator.detectMpk()) {
            const prot = std.posix.PROT{ .READ = true, .WRITE = true };
            try os.pkeyMprotect(ptr, len, prot, key);
        } else {
            return Fallback.applyProtectionToRegion(ptr, len, key);
        }
    }
};

/// x86_64 Portable Implementation (macOS, FreeBSD, etc.) — no MPK support
const X86_64_Portable = struct {
    pub fn writeProtectionKey(value: u32) void {
        if (!compartment.global_allocator.detectMpk()) return;
        haj_wrpkru(value);
    }

    pub fn readProtectionKey() u32 {
        if (!compartment.global_allocator.detectMpk()) return 0;
        return haj_rdpkru();
    }

    pub fn setKeyPermission(key: u32, perm: Permission) void {
        if (!compartment.global_allocator.detectMpk()) return;
        var pkru = @This().readProtectionKey();
        const shift: u5 = @intCast(key * 2);
        
        switch (perm) {
            .none => {
                pkru |= (@as(u32, 0b11) << shift);
            },
            .read_only => {
                pkru &= ~(@as(u32, 0b01) << shift);
                pkru |= (@as(u32, 0b10) << shift);
            },
            .read_write => {
                pkru &= ~(@as(u32, 0b11) << shift);
            },
        }
        @This().writeProtectionKey(pkru);
    }

    pub fn applyProtectionToRegion(ptr: [*]u8, len: usize, key: u32) !void {
        return Fallback.applyProtectionToRegion(ptr, len, key);
    }
};

/// AArch64 Linux Implementation using ARM MTE (Memory Tagging Extension)
const AArch64_Linux = struct {
    /// MTE uses pointer tagging rather than a single global register like PKRU.
    /// The TCO (Tag Check Override) register can be used to globally disable checks.
    pub fn writeProtectionKey(value: u32) void {
        asm volatile (
            \\msr tco, %[val]
            :
            : [val] "r" (@as(u64, value))
            : "memory"
        );
    }

    pub fn readProtectionKey() u32 {
        var value: u64 = undefined;
        asm volatile (
            \\mrs %[ret], tco
            : [ret] "=r" (value)
        );
        return @as(u32, @intCast(value));
    }

    pub fn setKeyPermission(key: u32, perm: Permission) void {
        _ = key;
        _ = perm;
        // MTE uses per-allocation pointer tags, not a global PKRU-style register.
        // Permission changes require re-tagging the allocated granules via the
        // pointer tag stored in bits [59:56], not a global permission register.
        // This is a no-op because the caller uses the key+perm interface designed
        // for x86_64 MPK; on AArch64, permissions are set at allocation time
        // via applyProtectionToRegion (which passes PROT_MTE to mprotect).
    }

    pub fn applyProtectionToRegion(ptr: [*]u8, len: usize, key: u32) !void {
        // 1. Set standard memory protection via os layer
        try os.memProtect(ptr, len, true, true);
        // 2. Apply MTE tag to memory granules
        // MTE granule is 16 bytes. The tag is stored in bits [59:56] of the pointer.
        var addr = @intFromPtr(ptr);
        const end_addr = addr + len;
        const tag = @as(u64, key & 0xF) << 56;

        while (addr < end_addr) {
            // Combine address with tag
            const tagged_addr = (addr & 0x00FFFFFFFFFFFFFF) | tag;
            asm volatile (
                \\stg %[addr], [%[addr]]
                :
                : [addr] "r" (tagged_addr)
                : "memory"
            );
            addr += 16;
        }
    }
};

/// AArch64 Portable Implementation (macOS, FreeBSD, etc.) — no MTE support
const AArch64_Portable = struct {
    pub fn writeProtectionKey(value: u32) void {
        _ = value;
        // No-op: Apple Silicon CPUs do not implement MTE.
        // The tco (Tag Check Override) register used on AArch64 Linux
        // is not available, and there is no PKRU equivalent on AArch64.
    }

    pub fn readProtectionKey() u32 {
        return 0;
    }

    pub fn setKeyPermission(key: u32, perm: Permission) void {
        _ = key;
        _ = perm;
        // AArch64 Portable no-op: MTE is not available outside Linux.
    }

    pub fn applyProtectionToRegion(ptr: [*]u8, len: usize, key: u32) !void {
        return Fallback.applyProtectionToRegion(ptr, len, key);
    }
};

/// Software fallback for unsupported architectures or platforms
const Fallback = struct {
    pub fn writeProtectionKey(value: u32) void {
        _ = value;
    }

    pub fn readProtectionKey() u32 {
        return 0;
    }

    pub fn setKeyPermission(key: u32, perm: Permission) void {
        _ = key;
        _ = perm;
        // Software fallback no-op: no hardware permission mechanism exists.
        // The key+perm interface is specific to x86_64 MPK; on systems
        // without MPK/MTE, global permission changes are not supported.
    }

    pub fn applyProtectionToRegion(ptr: [*]u8, len: usize, key: u32) !void {
        _ = key;
        try os.memProtect(ptr, len, true, true);
    }
};
