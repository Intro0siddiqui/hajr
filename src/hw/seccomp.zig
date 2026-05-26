const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .linux) @compileError("seccomp is Linux-specific");
}

const sock_filter = extern struct { code: u16, jt: u8, jf: u8, k: u32 };
const sock_fprog = extern struct { len: u16, filter: [*]const sock_filter };

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_KILL: u32 = 0x00000000;
const SECCOMP_SET_MODE_FILTER: u64 = 1;
const SECCOMP_FILTER_FLAG_TSYNC: u64 = 1;
const PR_SET_NO_NEW_PRIVS: u64 = 38;

const native_arch: u32 = switch (builtin.cpu.arch) {
    .x86_64 => 0xC000003E,
    .aarch64 => 0xC00000B7,
    else => @compileError("unsupported architecture"),
};

const is_64: bool = builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64;

const SYS_READ: u32 = if (is_64) 0 else 3;
const SYS_WRITE: u32 = if (is_64) 1 else 4;
const SYS_MMAP: u32 = if (is_64) 9 else 192;
const SYS_MUNMAP: u32 = if (is_64) 11 else 91;
const SYS_MPROTECT: u32 = if (is_64) 10 else 125;
const SYS_BRK: u32 = if (is_64) 12 else 45;
const SYS_RT_SIGRETURN: u32 = if (is_64) 15 else 173;
const SYS_RT_SIGACTION: u32 = if (is_64) 13 else 174;
const SYS_EXIT_GROUP: u32 = if (is_64) 231 else 248;
const SYS_EXIT: u32 = if (is_64) 60 else 1;
const SYS_FUTEX: u32 = if (is_64) 202 else 240;
const SYS_CLOCK_GETTIME: u32 = if (is_64) 228 else 263;
const SYS_GETRANDOM: u32 = if (is_64) 318 else 355;
const SYS_NANOSLEEP: u32 = if (is_64) 35 else 162;
const SYS_SCHED_YIELD: u32 = if (is_64) 24 else 158;
const SYS_MADVISE: u32 = if (is_64) 28 else 220;
const SYS_PKEY_ALLOC: u32 = if (is_64) 330 else 0;
const SYS_PKEY_FREE: u32 = if (is_64) 331 else 0;
const SYS_PKEY_MPROTECT: u32 = if (is_64) 329 else 0;

fn load(offset: u32) sock_filter {
    return .{ .code = BPF_LD | BPF_W | BPF_ABS, .jt = 0, .jf = 0, .k = offset };
}

fn check(val: u32, jt: u8, jf: u8) sock_filter {
    return .{ .code = BPF_JMP | BPF_JEQ | BPF_K, .jt = jt, .jf = jf, .k = val };
}

fn ret(code: u32) sock_filter {
    return .{ .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = code };
}

fn buildFilter(comptime nrs: []const u32) [5 + nrs.len]sock_filter {
    const N = nrs.len;
    var prog: [5 + N]sock_filter = undefined;
    prog[0] = load(4);
    prog[1] = check(native_arch, 0, @as(u8, @intCast(N + 1)));
    prog[2] = load(0);
    for (nrs, 0..) |nr, i| {
        prog[3 + i] = check(nr, @as(u8, @intCast(N - i)), 0);
    }
    prog[3 + N] = ret(SECCOMP_RET_KILL);
    prog[4 + N] = ret(SECCOMP_RET_ALLOW);
    return prog;
}

const jit_allowed_filter = buildFilter(&[_]u32{
    SYS_READ, SYS_WRITE, SYS_MMAP, SYS_MUNMAP, SYS_MPROTECT,
    SYS_BRK, SYS_RT_SIGRETURN, SYS_RT_SIGACTION, SYS_EXIT_GROUP, SYS_EXIT,
    SYS_FUTEX, SYS_CLOCK_GETTIME, SYS_GETRANDOM, SYS_NANOSLEEP, SYS_SCHED_YIELD,
    SYS_MADVISE, SYS_PKEY_ALLOC, SYS_PKEY_FREE, SYS_PKEY_MPROTECT,
});

const jit_denied_filter = buildFilter(&[_]u32{
    SYS_READ, SYS_WRITE, SYS_MMAP, SYS_MUNMAP, SYS_MPROTECT,
    SYS_BRK, SYS_RT_SIGRETURN, SYS_RT_SIGACTION, SYS_EXIT_GROUP,
    SYS_FUTEX, SYS_CLOCK_GETTIME, SYS_GETRANDOM, SYS_MADVISE,
});

const minimal_filter = buildFilter(&[_]u32{
    SYS_READ, SYS_WRITE, SYS_EXIT_GROUP, SYS_RT_SIGRETURN, SYS_FUTEX, SYS_CLOCK_GETTIME,
});

pub const FilterKind = enum {
    jit_allowed,
    jit_denied,
    minimal,
};

pub fn install(kind: FilterKind) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    const rc = std.os.linux.syscall5(.prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (std.os.linux.errno(rc) != .SUCCESS) return error.PrctlFailed;

    const filter: []const sock_filter = switch (kind) {
        .jit_allowed => &jit_allowed_filter,
        .jit_denied => &jit_denied_filter,
        .minimal => &minimal_filter,
    };

    const fprog = sock_fprog{
        .len = @as(u16, @intCast(filter.len)),
        .filter = @ptrCast(filter.ptr),
    };

    const res = std.os.linux.syscall4(.seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, @intFromPtr(&fprog), 0);
    if (std.os.linux.errno(res) != .SUCCESS) return error.SeccompFailed;
}

test "seccomp filter layout" {
    try std.testing.expect(jit_allowed_filter.len > 0);
    try std.testing.expect(jit_allowed_filter[jit_allowed_filter.len - 1].k == SECCOMP_RET_ALLOW);
    try std.testing.expect(jit_allowed_filter[jit_allowed_filter.len - 2].k == SECCOMP_RET_KILL);
    try std.testing.expectEqual(@as(u8, 0), jit_allowed_filter[1].jt);
}
