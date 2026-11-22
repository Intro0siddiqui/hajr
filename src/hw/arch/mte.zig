//! Raw ARM Memory Tagging Extension instructions (HAL hardware layer).
//!
//! Kept separate from the `hw` facade so baseline ARMv8-A cross-compiles do not
//! need the `memtag` architecture extension enabled globally. Each asm block
//! enables it locally with `.arch_extension memtag`.

const builtin = @import("builtin");

comptime {
    if (builtin.cpu.arch != .aarch64) @compileError("mte.zig is AArch64-only");
}

/// Write the Tag Check Override (TCO) register.
pub fn writeTco(value: u32) void {
    asm volatile (
        \\.arch_extension memtag
        \\msr tco, %[val]
        :
        : [val] "r" (@as(u64, value)),
        : "memory");
}

/// Read the Tag Check Override (TCO) register.
pub fn readTco() u32 {
    var value: u64 = undefined;
    asm volatile (
        \\.arch_extension memtag
        \\mrs %[ret], tco
        : [ret] "=r" (value),
    );
    return @as(u32, @intCast(value));
}

/// Tag every 16-byte granule of `ptr[0..len]` with the given key.
pub fn tagRange(ptr: [*]u8, len: usize, key: u32) void {
    var addr = @intFromPtr(ptr);
    const end_addr = addr + len;
    const tag = @as(u64, key & 0xF) << 56;

    while (addr < end_addr) : (addr += 16) {
        const tagged_addr = (addr & 0x00FFFFFFFFFFFFFF) | tag;
        asm volatile (
            \\.arch_extension memtag
            \\stg %[addr], [%[addr]]
            :
            : [addr] "r" (tagged_addr),
            : "memory");
    }
}
