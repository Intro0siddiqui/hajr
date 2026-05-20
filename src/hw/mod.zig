//! Hardware primitives for memory protection (MPK, MTE)
//!
//! This module provides a unified interface for hardware-assisted memory protection
//! across different architectures, including Intel MPK (x86_64) and ARM MTE (AArch64).

const std = @import("std");
const builtin = @import("builtin");

pub const pointer = @import("pointer.zig");
pub const compartment = @import("compartment.zig");
pub const exception = @import("exception.zig");
pub const posix_io = @import("posix.zig");

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
    /// Write to PKRU register using WRPKRU instruction.
    /// WRPKRU requires EAX = value, ECX = 0, EDX = 0.
    pub fn writeProtectionKey(value: u32) void {
        if (!compartment.global_allocator.detectMpk()) return;
        asm volatile (
            \\xorl %%ecx, %%ecx
            \\xorl %%edx, %%edx
            \\wrpkru
            :
            : [val] "{eax}" (value)
            : .{ .ecx = true, .edx = true, .memory = true }
        );
    }

    /// Read from PKRU register using RDPKRU instruction.
    /// RDPKRU requires ECX = 0, returns value in EAX (and 0 in EDX).
    pub fn readProtectionKey() u32 {
        if (!compartment.global_allocator.detectMpk()) return 0;
        var value: u32 = undefined;
        asm volatile (
            \\xorl %%ecx, %%ecx
            \\rdpkru
            : [ret] "={eax}" (value)
            :
            : .{ .ecx = true, .edx = true }
        );
        return value;
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
            // pkey_mprotect(void *addr, size_t len, int prot, int pkey)
            const prot = @as(u32, @bitCast(std.os.linux.PROT{ .READ = true, .WRITE = true }));
            
            const res = std.os.linux.syscall6(
                .pkey_mprotect,
                @intFromPtr(ptr),
                len,
                prot,
                key,
                0,
                0
            );
            if (res != 0) return error.ProtectionFailed;
        } else {
            // Fallback to standard memory protection (mprotect) without key
            return Fallback.applyProtectionToRegion(ptr, len, key);
        }
    }
};

/// x86_64 Portable Implementation (macOS, FreeBSD, etc.) — no MPK support
const X86_64_Portable = struct {
    pub fn writeProtectionKey(value: u32) void {
        if (!compartment.global_allocator.detectMpk()) return;
        asm volatile (
            \\xorl %%ecx, %%ecx
            \\xorl %%edx, %%edx
            \\wrpkru
            :
            : [val] "{eax}" (value)
            : .{ .ecx = true, .edx = true, .memory = true }
        );
    }

    pub fn readProtectionKey() u32 {
        if (!compartment.global_allocator.detectMpk()) return 0;
        var value: u32 = undefined;
        asm volatile (
            \\xorl %%ecx, %%ecx
            \\rdpkru
            : [ret] "={eax}" (value)
            :
            : .{ .ecx = true, .edx = true }
        );
        return value;
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
        // MTE does not use a global register like PKRU for individual keys.
        // Instead, it uses pointer tags.
    }

    pub fn applyProtectionToRegion(ptr: [*]u8, len: usize, key: u32) !void {
        const prot_base = @as(u32, @bitCast(std.os.linux.PROT{ .READ = true, .WRITE = true }));
        const PROT_MTE = 0x20;

        // 1. Enable MTE on the region
        const res = std.os.linux.syscall3(
            .mprotect,
            @intFromPtr(ptr),
            len,
            prot_base | PROT_MTE,
        );
        if (res != 0) return error.ProtectionFailed;

        // 2. Tag the memory granules
        // MTE granule is 16 bytes. The tag is stored in bits [59:56] of the pointer.
        var addr = @intFromPtr(ptr);
        const end_addr = addr + len;
        const tag = @as(u64, key & 0xF) << 56;

        while (addr < end_addr) {
            // Combine address with tag (keeping top-byte-ignore bits if any, but usually we just set the tag)
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
    }

    pub fn applyProtectionToRegion(ptr: [*]u8, len: usize, key: u32) !void {
        _ = key;

        if (@hasDecl(std.posix, "mprotect")) {
            const prot = std.posix.PROT.READ | std.posix.PROT.WRITE;
            try std.posix.mprotect(ptr[0..len], prot);
        }
    }
};
