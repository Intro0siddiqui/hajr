const std = @import("std");
const builtin = @import("builtin");

pub const PacKey = enum { ia, ib, da, db, ga };

pub const PacError = error{
    AuthFailed,
    NotSupported,
};

pub const PacSupport = struct {
    address_auth: bool,
    generic_auth: bool,
};

const arch_impl = if (builtin.cpu.arch == .aarch64)
    if (builtin.os.tag == .linux) AArch64_Linux else AArch64_Apple
else
    NoPAC;

pub fn signLR() void {
    arch_impl.signLR();
}

pub fn authLR() void {
    arch_impl.authLR();
}

pub fn sign(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
    return arch_impl.sign(ptr, modifier, key);
}

pub fn auth(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
    return arch_impl.auth(ptr, modifier, key);
}

pub fn stripInstruction(ptr: usize) usize {
    return arch_impl.stripInstruction(ptr);
}

pub fn stripData(ptr: usize) usize {
    return arch_impl.stripData(ptr);
}

pub fn hasPacAddressAuth() bool {
    return arch_impl.hasPacAddressAuth();
}

pub fn hasPacGenericAuth() bool {
    return arch_impl.hasPacGenericAuth();
}

pub fn isSupported() bool {
    return arch_impl.hasPacAddressAuth() or arch_impl.hasPacGenericAuth();
}

pub fn resetKeys() void {
    arch_impl.resetKeys();
}

const AArch64_Linux = struct {
    var hwcap_cache: ?u32 = null;

    fn getHwcap() u32 {
        if (hwcap_cache) |cap| return cap;
        const os = @import("os_abstraction.zig");
        hwcap_cache = os.getHwcap();
        return hwcap_cache.?;
    }

    pub fn signLR() void {
        asm volatile ("paciasp" ::: .{});
    }

    pub fn authLR() void {
        asm volatile ("autiasp" ::: .{});
    }

    pub fn sign(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
        var p: usize = ptr;
        switch (key) {
            .ia => asm volatile (
                \\pacia %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .ib => asm volatile (
                \\pacib %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .da => asm volatile (
                \\pacda %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .db => asm volatile (
                \\pacdb %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .ga => {},
        }
        return p;
    }

    pub fn auth(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
        var p: usize = ptr;
        switch (key) {
            .ia => asm volatile (
                \\autia %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .ib => asm volatile (
                \\autib %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .da => asm volatile (
                \\autda %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .db => asm volatile (
                \\autdb %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .ga => {},
        }
        if (key == .ga) return p;
        const top_bits = p >> 56;
        if (top_bits == 0xFF) return error.AuthFailed;
        return p;
    }

    pub fn stripInstruction(ptr: usize) usize {
        var p: usize = ptr;
        asm volatile (
            \\xpaci %[p]
            : [p] "+{x0}" (p),
            : [_] "r" (@as(usize, 0)),
            : .{}
        );
        return p;
    }

    pub fn stripData(ptr: usize) usize {
        var p: usize = ptr;
        asm volatile (
            \\xpacd %[p]
            : [p] "+{x0}" (p),
            : [_] "r" (@as(usize, 0)),
            : .{}
        );
        return p;
    }

    pub fn hasPacAddressAuth() bool {
        return (getHwcap() & 0x10000) != 0;
    }

    pub fn hasPacGenericAuth() bool {
        return (getHwcap() & 0x20000) != 0;
    }

    pub fn resetKeys() void {
        const os = @import("os_abstraction.zig");
        os.prctlPacResetKeys(0xF) catch {};
    }
};

const AArch64_Apple = struct {
    pub fn signLR() void {
        asm volatile ("paciasp" ::: .{});
    }

    pub fn authLR() void {
        asm volatile ("autiasp" ::: .{});
    }

    pub fn sign(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
        var p: usize = ptr;
        switch (key) {
            .ia => asm volatile (
                \\pacia %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .ib => asm volatile (
                \\pacib %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .da => asm volatile (
                \\pacda %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .db => asm volatile (
                \\pacdb %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .ga => {},
        }
        return p;
    }

    pub fn auth(ptr: usize, modifier: usize, key: PacKey) PacError!usize {
        var p: usize = ptr;
        switch (key) {
            .ia => asm volatile (
                \\autia %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .ib => asm volatile (
                \\autib %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .da => asm volatile (
                \\autda %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .db => asm volatile (
                \\autdb %[p], %[m]
                : [p] "+{x0}" (p),
                : [m] "r" (modifier),
                : .{}
            ),
            .ga => {},
        }
        if (key == .ga) return p;
        const top_bits = p >> 56;
        if (top_bits == 0xFF) return error.AuthFailed;
        return p;
    }

    pub fn stripInstruction(ptr: usize) usize {
        var p: usize = ptr;
        asm volatile (
            \\xpaci %[p]
            : [p] "+{x0}" (p),
            : [_] "r" (@as(usize, 0)),
            : .{}
        );
        return p;
    }

    pub fn stripData(ptr: usize) usize {
        var p: usize = ptr;
        asm volatile (
            \\xpacd %[p]
            : [p] "+{x0}" (p),
            : [_] "r" (@as(usize, 0)),
            : .{}
        );
        return p;
    }

    pub fn hasPacAddressAuth() bool {
        return true;
    }

    pub fn hasPacGenericAuth() bool {
        return true;
    }

    pub fn resetKeys() void {}
};

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
