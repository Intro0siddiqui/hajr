//! Hardware-abstracted pointer tagging logic.
//!
//! This module provides utilities for pointer tagging, which is essential for
//! ARM MTE (Memory Tagging Extension) parity. On AArch64, it uses Top Byte
//! Ignore (TBI) to embed tags. On x86_64, it provides a zero-cost passthrough.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

/// A hardware-abstracted tagged pointer.
/// 
/// On AArch64, this utilizes Top Byte Ignore (TBI) to store a 4-bit MTE tag
/// directly in the pointer bits 56-59.
/// 
/// On x86_64, this is a zero-cost passthrough where the tag is stored
/// in a separate field for parity but ignored by hardware.
pub fn TaggedPointer(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Internal representation varies by architecture.
        /// On AArch64, the tag is embedded in the pointer itself.
        /// On other architectures, we store it separately to maintain the API.
        inner: if (builtin.cpu.arch == .aarch64)
            *T
        else
            struct {
                raw: *T,
                tag: u4,
            },

        /// Create a tagged pointer from a raw pointer and a 4-bit tag.
        ///
        /// @param ptr The canonical raw pointer.
        /// @param tag A 4-bit identifier (0-15).
        pub fn fromRawWithTag(ptr: *T, tag: u4) Self {
            if (builtin.cpu.arch == .aarch64) {
                const addr = @intFromPtr(ptr);
                // ARM MTE uses 4 bits (56-59). Bits 56-63 are ignored by TBI.
                const tagged_addr = addr | (@as(usize, tag) << 56);
                return .{ .inner = @ptrFromInt(tagged_addr) };
            } else {
                return .{
                    .inner = .{
                        .raw = ptr,
                        .tag = tag,
                    },
                };
            }
        }

        /// Extract the canonical raw pointer (tag bits cleared).
        /// This is useful for system calls that do not support tagged pointers.
        pub fn toRaw(self: Self) *T {
            if (builtin.cpu.arch == .aarch64) {
                const addr = @intFromPtr(self.inner);
                // Clear the top byte (bits 56-63) to get the canonical address.
                const mask: usize = 0x00FFFFFFFFFFFFFF;
                return @ptrFromInt(addr & mask);
            } else {
                return self.inner.raw;
            }
        }

        /// Returns the pointer with the tag embedded (if supported by hardware).
        /// On AArch64, this is the pointer used for MTE-checked memory accesses.
        /// On x86_64, this returns the original raw pointer.
        pub fn toTagged(self: Self) *T {
            if (builtin.cpu.arch == .aarch64) {
                return self.inner;
            } else {
                return self.inner.raw;
            }
        }

        /// Retrieves the 4-bit tag associated with this pointer.
        pub fn getTag(self: Self) u4 {
            if (builtin.cpu.arch == .aarch64) {
                const addr = @intFromPtr(self.inner);
                return @intCast((addr >> 56) & 0xF);
            } else {
                return self.inner.tag;
            }
        }
    };
}

test "TaggedPointer basic functionality" {
    var x: u32 = 42;
    const ptr = &x;
    const tag: u4 = 0xA;

    const tagged = TaggedPointer(u32).fromRawWithTag(ptr, tag);
    
    try testing.expectEqual(ptr, tagged.toRaw());
    try testing.expectEqual(tag, tagged.getTag());
    
    if (builtin.cpu.arch == .aarch64) {
        const tagged_addr = @intFromPtr(tagged.toTagged());
        const raw_addr = @intFromPtr(ptr);
        try testing.expect(tagged_addr != raw_addr);
        // Verify bit 56 is set (part of 0xA shift)
        try testing.expectEqual(tagged_addr, raw_addr | (@as(usize, 0xA) << 56));
    } else {
        try testing.expectEqual(ptr, tagged.toTagged());
    }
}
