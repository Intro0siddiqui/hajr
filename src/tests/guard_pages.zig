const std = @import("std");
const builtin = @import("builtin");
const os_abs = @import("../hw/os_abstraction.zig");

const testing = std.testing;

fn probeGuardPage(addr: usize) bool {
    if (builtin.os.tag != .linux) return false;
    const page_size = std.heap.page_size_min;
    const prot = std.os.linux.PROT{ .READ = true };
    const rc = std.os.linux.mprotect(@as([*]u8, @ptrFromInt(addr)), page_size, prot);
    return std.os.linux.errno(rc) == .SUCCESS;
}

fn restoreGuardPage(addr: usize) void {
    if (builtin.os.tag != .linux) return;
    const page_size = std.heap.page_size_min;
    _ = std.os.linux.mprotect(@as([*]u8, @ptrFromInt(addr)), page_size, std.os.linux.PROT{});
}

test "Guard pages: memory allocation has guard pages around usable region" {
    if (builtin.os.tag != .linux) return error.Skip;

    const page_size = std.heap.page_size_min;
    const region = try os_abs.memAlloc(page_size * 4);
    defer os_abs.memFree(region);

    try testing.expectEqual(@as(usize, 0), @intFromPtr(region.ptr) & (page_size - 1));

    const guard_before = @intFromPtr(region.ptr) - page_size;
    const guard_after = @intFromPtr(region.ptr) + region.len;

    const before_ok = probeGuardPage(guard_before);
    const after_ok = probeGuardPage(guard_after);

    restoreGuardPage(guard_before);
    restoreGuardPage(guard_after);

    try testing.expect(before_ok);
    try testing.expect(after_ok);
}

test "Guard pages: usable region is fully readable and writable" {
    if (builtin.os.tag == .windows) return error.Skip;

    const page_size = std.heap.page_size_min;
    const region = try os_abs.memAlloc(page_size * 2);
    defer os_abs.memFree(region);

    for (0..region.len) |i| region[i] = @intCast(i & 0xFF);
    for (0..region.len) |i| try testing.expectEqual(@as(u8, @intCast(i & 0xFF)), region[i]);
}

test "Guard pages: memFree on guarded region doesn't fault" {
    if (builtin.os.tag == .windows) return error.Skip;

    const page_size = std.heap.page_size_min;
    const region = try os_abs.memAlloc(page_size);
    region[0] = 0xAB;
    region[page_size - 1] = 0xCD;
    os_abs.memFree(region);

    const region2 = try os_abs.memAlloc(page_size * 8);
    defer os_abs.memFree(region2);
    region2[0] = 0xEF;
    try testing.expectEqual(@as(u8, 0xEF), region2[0]);
}

test "Guard pages: multiple allocations don't interfere" {
    if (builtin.os.tag == .windows) return error.Skip;

    const page_size = std.heap.page_size_min;
    var regions: [5][]align(page_size) u8 = undefined;

    for (&regions, 0..) |*r, i| {
        r.* = try os_abs.memAlloc(page_size);
        for (0..page_size) |j| r.*[j] = @intCast((i + j) & 0xFF);
    }
    for (regions, 0..) |r, i| {
        for (0..page_size) |j| try testing.expectEqual(@as(u8, @intCast((i + j) & 0xFF)), r[j]);
    }
    for (regions) |r| os_abs.memFree(r);
}

test "Guard pages: small allocation (1 byte) still gets guard pages" {
    if (builtin.os.tag == .windows) return error.Skip;

    const region = try os_abs.memAlloc(1);
    defer os_abs.memFree(region);

    try testing.expectEqual(@as(usize, 1), region.len);
    region[0] = 0x42;
    try testing.expectEqual(@as(u8, 0x42), region[0]);
}

test "Guard pages: memProtect on usable region doesn't affect guard pages" {
    if (builtin.os.tag == .windows) return error.Skip;

    const page_size = std.heap.page_size_min;
    const region = try os_abs.memAlloc(page_size);
    defer os_abs.memFree(region);

    try os_abs.memProtect(region.ptr, region.len, true, false);
    _ = region[0];
    try os_abs.memProtect(region.ptr, region.len, true, true);
    region[0] = 0xFF;
    try testing.expectEqual(@as(u8, 0xFF), region[0]);

    const guard_before = @intFromPtr(region.ptr) - page_size;
    const before_ok = probeGuardPage(guard_before);
    restoreGuardPage(guard_before);
    try testing.expect(before_ok);
}
