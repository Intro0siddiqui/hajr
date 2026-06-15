//! ARM Pointer Authentication (PAC) instruction wrappers.
//!
//! PAC computes a cryptographic MAC over a pointer value and stores it in the
//! unused upper bits of the pointer. On dereference, the MAC is recomputed and
//! compared — if it doesn't match, the pointer is poisoned and the process crashes.
//!
//! Supported targets:
//! - AArch64 Linux: full PAC support via inline assembly + getauxval detection
//! - AArch64 macOS (Apple Silicon): full PAC support (arm64e ABI)
//! - x86_64 / other: no-op fallbacks

const std = @import("std");
const builtin = @import("builtin");

/// PAC hardware keys (128-bit each, managed by kernel)
pub const PacKey = enum {
    /// Instruction key A — return addresses, function pointers
    ia,
    /// Instruction key B — alternate instruction auth
    ib,
    /// Data key A — data pointer authentication
    da,
    /// Data key B — alternate data auth
    db,
    /// Generic key — PACGA instruction (32-bit hash)
    ga,
};

/// PAC-related errors
pub const PacError = error{
    AuthFailed,
    NotSupported,
};

/// Runtime PAC feature detection result
pub const PacSupport = struct {
    address_auth: bool,
    generic_auth: bool,
};

// ============================================================================
// Architecture-specific implementation
// ============================================================================

const arch_impl = if (builtin.cpu.arch == .aarch64)
    if (builtin.os.tag == .linux) AArch64_Linux else AArch64_Apple
else
    NoPAC;

// ============================================================================
// Public API (facade)
// ============================================================================

/// Sign the link register (X30) using PACIASP (IA key + SP context).
/// This is the most common PAC operation — compiler-inserted for return address protection.
pub fn signLR() void {
    arch_impl.signLR();
}

/// Authenticate the link register (X30) using AUTIASP.
/// On failure, X30 is poisoned and the process crashes on return.
pub fn authLR() void {
    arch_impl.authLR();
}

/// Sign a pointer with a specific key and modifier.
/// The modifier provides context (e.g., SP, or a different pointer) for diversity.
pub fn sign(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
    return arch_impl.sign(ptr, modifier, key);
}

/// Authenticate a pointer with a specific key and modifier.
/// Returns error.AuthFailed if the pointer is forged.
pub fn auth(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
    return arch_impl.auth(ptr, modifier, key);
}

/// Strip PAC bits from an instruction pointer (XPACI).
/// Useful for pointer comparison/logging when the PAC bits are present.
pub fn stripInstruction(ptr: usize) usize {
    return arch_impl.stripInstruction(ptr);
}

/// Strip PAC bits from a data pointer (XPACD).
pub fn stripData(ptr: usize) usize {
    return arch_impl.stripData(ptr);
}

/// Check if PAC address authentication is supported.
pub fn hasPacAddressAuth() bool {
    return arch_impl.hasPacAddressAuth();
}

/// Check if PAC generic authentication is supported.
pub fn hasPacGenericAuth() bool {
    return arch_impl.hasPacGenericAuth();
}

/// Check if any PAC feature is supported.
pub fn isSupported() bool {
    return arch_impl.hasPacAddressAuth() or arch_impl.hasPacGenericAuth();
}

/// Reset all PAC keys to fresh random values (Linux only, no-op on macOS).
pub fn resetKeys() void {
    arch_impl.resetKeys();
}

// ============================================================================
// AArch64 Linux Implementation
// ============================================================================

const AArch64_Linux = struct {
    var hwcap_cache: ?u32 = null;

    fn getHwcap() u32 {
        if (hwcap_cache) |cap| return cap;
        const os = @import("os_abstraction.zig");
        hwcap_cache = os.getHwcap();
        return hwcap_cache.?;
    }

    pub fn signLR() void {
        asm volatile ("paciasp"
            :
            :
            : "cc"
        );
    }

    pub fn authLR() void {
        asm volatile ("autiasp"
            :
            :
            : "cc"
        );
    }

    pub fn sign(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
        var p: usize = ptr;
        return switch (key) {
            .ia => asm volatile (
                \\pacia %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .ib => asm volatile (
                \\pacib %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .da => asm volatile (
                \\pacda %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .db => asm volatile (
                \\pacdb %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .ga => ptr,
        };
    }

    pub fn auth(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
        var p: usize = ptr;
        const result = switch (key) {
            .ia => asm volatile (
                \\autia %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .ib => asm volatile (
                \\autib %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .da => asm volatile (
                \\autda %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .db => asm volatile (
                \\autdb %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .ga => ptr,
        };
        if (key == .ga) return result;
        const top_bits = result >> 56;
        if (top_bits == 0xFF) return error.AuthFailed;
        return result;
    }

    pub fn stripInstruction(ptr: usize) usize {
        var p: usize = ptr;
        return asm volatile (
            \\xpaci %[p]
            : [p] "={x0}" (p)
            :
            : "cc"
        );
    }

    pub fn stripData(ptr: usize) usize {
        var p: usize = ptr;
        return asm volatile (
            \\xpacd %[p]
            : [p] "={x0}" (p)
            :
            : "cc"
        );
    }

    pub fn hasPacAddressAuth() bool {
        return (getHwcap() & 0x10000) != 0; // HWCAP_PACA = bit 16
    }

    pub fn hasPacGenericAuth() bool {
        return (getHwcap() & 0x20000) != 0; // HWCAP_PACG = bit 17
    }

    pub fn resetKeys() void {
        const os = @import("os_abstraction.zig");
        os.prctlPacResetKeys(0xF) catch {}; // Reset all 4 keys, ignore errors
    }
};

// ============================================================================
// AArch64 Apple Silicon Implementation
// ============================================================================

const AArch64_Apple = struct {
    pub fn signLR() void {
        asm volatile ("paciasp"
            :
            :
            : "cc"
        );
    }

    pub fn authLR() void {
        asm volatile ("autiasp"
            :
            :
            : "cc"
        );
    }

    pub fn sign(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
        var p: usize = ptr;
        return switch (key) {
            .ia => asm volatile (
                \\pacia %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .ib => asm volatile (
                \\pacib %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .da => asm volatile (
                \\pacda %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .db => asm volatile (
                \\pacdb %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .ga => ptr,
        };
    }

    pub fn auth(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
        var p: usize = ptr;
        const result = switch (key) {
            .ia => asm volatile (
                \\autia %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .ib => asm volatile (
                \\autib %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .da => asm volatile (
                \\autda %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .db => asm volatile (
                \\autdb %[p], %[m]
                : [p] "={x0}" (p),
                : [m] "r" (modifier)
                : "cc"
            ),
            .ga => ptr,
        };
        if (key == .ga) return result;
        const top_bits = result >> 56;
        if (top_bits == 0xFF) return error.AuthFailed;
        return result;
    }

    pub fn stripInstruction(ptr: usize) usize {
        var p: usize = ptr;
        return asm volatile (
            \\xpaci %[p]
            : [p] "={x0}" (p)
            :
            : "cc"
        );
    }

    pub fn stripData(ptr: usize) usize {
        var p: usize = ptr;
        return asm volatile (
            \\xpacd %[p]
            : [p] "={x0}" (p)
            :
            : "cc"
        );
    }

    pub fn hasPacAddressAuth() bool {
        return true; // Apple Silicon always has PAC (arm64e ABI)
    }

    pub fn hasPacGenericAuth() bool {
        return true;
    }

    pub fn resetKeys() void {
        // No-op: Apple Silicon PAC keys are managed by kernel + EL3
        // User space cannot reset them
    }
};

// ============================================================================
// No-PAC Fallback (x86_64, unsupported ARM)
// ============================================================================

const NoPAC = struct {
    pub fn signLR() void {}
    pub fn authLR() void {}

    pub fn sign(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
        _ = modifier;
        _ = key;
        return ptr;
    }

    pub fn auth(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
        _ = modifier;
        _ = key;
        return ptr;
    }

    pub fn stripInstruction(ptr: usize) usize {
        return ptr;
    }

    pub fn stripData(ptr: usize) usize {
        return ptr;
    }

    pub fn hasPacAddressAuth() bool {
        return false;
    }

    pub fn hasPacGenericAuth() bool {
        return false;
    }

    pub fn resetKeys() void {}
};

// ============================================================================
// Tests
// ============================================================================

test "PAC isSupported returns a value without crashing" {
    _ = isSupported();
}

test "PAC hasPacAddressAuth returns a value without crashing" {
    _ = hasPacAddressAuth();
}

test "PAC hasPacGenericAuth returns a value without crashing" {
    _ = hasPacGenericAuth();
}

test "PAC sign/auth no-op on non-ARM (compile test)" {
    if (builtin.cpu.arch != .aarch64) {
        var x: u32 = 42;
        const ptr = @intFromPtr(&x);
        const signed = try sign(ptr, 0, .ia);
        const authed = try auth(signed, 0, .ia);
        try std.testing.expectEqual(ptr, authed);
    }
}
