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
const SECCOMP_RET_LOG: u32 = 0x00050000; // Allow + log to audit (for debugging)
const SECCOMP_SET_MODE_FILTER: u64 = 1;
const SECCOMP_FILTER_FLAG_TSYNC: u64 = 1;
const PR_SET_NO_NEW_PRIVS: u64 = 38;

const native_arch: u32 = switch (builtin.cpu.arch) {
    .x86_64 => 0xC000003E,
    .aarch64 => 0xC00000B7,
    else => @compileError("unsupported architecture"),
};

const is_64: bool = builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64;

// ============================================================================
// Syscall number constants — x86_64 (64-bit) and aarch64
// ============================================================================

// --- Basic I/O ---
const SYS_READ: u32 = if (is_64) 0 else 3;
const SYS_WRITE: u32 = if (is_64) 1 else 4;
const SYS_OPEN: u32 = if (is_64) 2 else 5;
const SYS_CLOSE: u32 = if (is_64) 3 else 6;
const SYS_FSTAT: u32 = if (is_64) 5 else 197;
const SYS_LSEEK: u32 = if (is_64) 8 else 199;
const SYS_MMAP: u32 = if (is_64) 9 else 192;
const SYS_MPROTECT: u32 = if (is_64) 10 else 125;
const SYS_MUNMAP: u32 = if (is_64) 11 else 91;
const SYS_BRK: u32 = if (is_64) 12 else 45;
const SYS_IOCTL: u32 = if (is_64) 16 else 54;
const SYS_ACCESS: u32 = if (is_64) 21 else 33;
const SYS_PIPE: u32 = if (is_64) 22 else 42;
const SYS_DUP2: u32 = if (is_64) 33 else 90;
const SYS_USLEEP: u32 = if (is_64) 35 else 158; // maps to nanosleep on 64-bit
const SYS_NANOSLEEP: u32 = if (is_64) 35 else 162;
const SYS_GETPID: u32 = if (is_64) 39 else 20;
const SYS_SOCKET: u32 = if (is_64) 41 else 97;
const SYS_CONNECT: u32 = if (is_64) 42 else 98;
const SYS_ACCEPT: u32 = if (is_64) 43 else 30;
const SYS_SENDTO: u32 = if (is_64) 44 else 133;
const SYS_RECVFROM: u32 = if (is_64) 45 else 125;
const SYS_SENDMSG: u32 = if (is_64) 46 else 146;
const SYS_RECVMSG: u32 = if (is_64) 47 else 147;
const SYS_SHUTDOWN: u32 = if (is_64) 48 else 137;
const SYS_BIND: u32 = if (is_64) 49 else 104;
const SYS_LISTEN: u32 = if (is_64) 50 else 106;
const SYS_GETSOCKNAME: u32 = if (is_64) 51 else 118;
const SYS_GETPEERNAME: u32 = if (is_64) 52 else 119;
const SYS_SOCKETPAIR: u32 = if (is_64) 53 else 135;
const SYS_SETSOCKOPT: u32 = if (is_64) 54 else 105;
const SYS_GETSOCKOPT: u32 = if (is_64) 55 else 118;
const SYS_CLONE: u32 = if (is_64) 56 else 120;
const SYS_FORK: u32 = if (is_64) 57 else 2;
const SYS_VFORK: u32 = if (is_64) 58 else 190;
const SYS_EXECVE: u32 = if (is_64) 59 else 11;
const SYS_EXIT: u32 = if (is_64) 60 else 1;
const SYS_WAIT4: u32 = if (is_64) 61 else 114;
const SYS_KILL: u32 = if (is_64) 62 else 37;
const SYS_UNAME: u32 = if (is_64) 63 else 122;
const SYS_FCNTL: u32 = if (is_64) 72 else 92;
const SYS_FLOCK: u32 = if (is_64) 73 else 195;
const SYS_FSYNC: u32 = if (is_64) 74 else 118;
const SYS_FDATASYNC: u32 = if (is_64) 75 else 120;
const SYS_TRUNCATE: u32 = if (is_64) 76 else 193;
const SYS_FTRUNCATE: u32 = if (is_64) 77 else 194;
const SYS_GETDENTS: u32 = if (is_64) 78 else 141;
const SYS_GETCWD: u32 = if (is_64) 79 else 183;
const SYS_CHDIR: u32 = if (is_64) 80 else 12;
const SYS_FCHDIR: u32 = if (is_64) 81 else 133;
const SYS_RENAME: u32 = if (is_64) 82 else 38;
const SYS_MKDIR: u32 = if (is_64) 83 else 39;
const SYS_RMDIR: u32 = if (is_64) 84 else 40;
const SYS_CREAT: u32 = if (is_64) 85 else 8;
const SYS_UNLINK: u32 = if (is_64) 87 else 10;
const SYS_READLINK: u32 = if (is_64) 89 else 165;
const SYS_CHMOD: u32 = if (is_64) 90 else 15;
const SYS_FCHMOD: u32 = if (is_64) 91 else 124;
const SYS_CHOWN: u32 = if (is_64) 92 else 182;
const SYS_UMASK: u32 = if (is_64) 95 else 60;
const SYS_GETTIMEOFDAY: u32 = if (is_64) 96 else 169;
const SYS_GETUID: u32 = if (is_64) 102 else 24;
const SYS_GETGID: u32 = if (is_64) 104 else 47;
const SYS_GETEUID: u32 = if (is_64) 107 else 31;
const SYS_GETEGID: u32 = if (is_64) 108 else 49;
const SYS_SETUID: u32 = if (is_64) 105 else 23;
const SYS_SETGID: u32 = if (is_64) 106 else 46;
const SYS_GETPGID: u32 = if (is_64) 121 else 45;
const SYS_SETPGID: u32 = if (is_64) 109 else 39;
const SYS_SETSID: u32 = if (is_64) 112 else 66;
const SYS_GETPPID: u32 = if (is_64) 110 else 64;
const SYS_SETFSUID: u32 = if (is_64) 138 else 138;
const SYS_SETFSGID: u32 = if (is_64) 139 else 139;
const SYS_GETTID: u32 = if (is_64) 186 else 207;
const SYS_TGKILL: u32 = if (is_64) 234 else 240;
const SYS_TKILL: u32 = if (is_64) 200 else 238;
const SYS_FUTEX: u32 = if (is_64) 202 else 240;
const SYS_SET_TID_ADDRESS: u32 = if (is_64) 218 else 230;
const SYS_SET_ROBUST_LIST: u32 = if (is_64) 300 else 231;
const SYS_GETEVENTFD: u32 = if (is_64) 280 else 0; // aarch64 doesn't have eventfd directly
const SYS_CLOCK_GETTIME: u32 = if (is_64) 228 else 263;
const SYS_CLOCK_GETRES: u32 = if (is_64) 229 else 264;
const SYS_CLOCK_NANOSLEEP: u32 = if (is_64) 230 else 267;
const SYS_EXIT_GROUP: u32 = if (is_64) 231 else 248;
const SYS_EPOLL_WAIT: u32 = if (is_64) 232 else 252;
const SYS_EPOLL_CTL: u32 = if (is_64) 233 else 251;
const SYS_TGKILL2: u32 = if (is_64) 234 else 240;
const SYS_OPENAT: u32 = if (is_64) 257 else 286;
const SYS_MKDIRAT: u32 = if (is_64) 258 else 287;
const SYS_NEWFSTATAT: u32 = if (is_64) 262 else 271;
const SYS_UNLINKAT: u32 = if (is_64) 263 else 292;
const SYS_RENAMEAT: u32 = if (is_64) 264 else 302;
const SYS_READLINKAT: u32 = if (is_64) 265 else 296;
const SYS_FCHMODAT: u32 = if (is_64) 268 else 299;
const SYS_FCHOWNAT: u32 = if (is_64) 260 else 290;
const SYS_OPENAT2: u32 = if (is_64) 437 else 0; // arm64 may not have this
const SYS_CLOSE_RANGE: u32 = if (is_64) 436 else 0;
const SYS_PIPE2: u32 = if (is_64) 293 else 0;
const SYS_DUP3: u32 = if (is_64) 292 else 0;
const SYS_EPOLL_CREATE1: u32 = if (is_64) 291 else 20;
const SYS_ACCEPT4: u32 = if (is_64) 288 else 20;
const SYS_EVENTFD2: u32 = if (is_64) 290 else 20;
const SYS_GETDENTS64: u32 = if (is_64) 217 else 217;
const SYS_PREAD64: u32 = if (is_64) 17 else 180;
const SYS_PWRITE64: u32 = if (is_64) 18 else 181;
const SYS_READV: u32 = if (is_64) 19 else 145;
const SYS_WRITEV: u32 = if (is_64) 20 else 146;
const SYS_PREADV: u32 = if (is_64) 295 else 265;
const SYS_PWRITEV: u32 = if (is_64) 296 else 266;
const SYS_DUP: u32 = if (is_64) 32 else 41;
const SYS_MADVISE: u32 = if (is_64) 28 else 220;
const SYS_MREMAP: u32 = if (is_64) 25 else 163;
const SYS_MSYNC: u32 = if (is_64) 26 else 144;
const SYS_MLOCK: u32 = if (is_64) 149 else 221;
const SYS_MUNLOCK: u32 = if (is_64) 150 else 222;
const SYS_MLOCKALL: u32 = if (is_64) 151 else 223;
const SYS_MUNLOCKALL: u32 = if (is_64) 152 else 224;
const SYS_MINCORE: u32 = if (is_64) 27 else 218;
const SYS_MMAP2: u32 = if (is_64) 0 else 192; // aarch64 uses mmap directly

// --- Signals ---
const SYS_RT_SIGRETURN: u32 = if (is_64) 15 else 139;
const SYS_RT_SIGACTION: u32 = if (is_64) 13 else 134;
const SYS_RT_SIGPROCMASK: u32 = if (is_64) 14 else 126;
const SYS_RT_SIGPENDING: u32 = if (is_64) 127 else 127;
const SYS_RT_SIGTIMEDWAIT: u32 = if (is_64) 220 else 177;
const SYS_SIGALTSTACK: u32 = if (is_64) 131 else 185;

// --- Process ---
const SYS_SETRLIMIT: u32 = if (is_64) 160 else 164;
const SYS_GETRLIMIT: u32 = if (is_64) 158 else 191;
const SYS_GETRUSAGE: u32 = if (is_64) 165 else 176;
const SYS_PRCTL: u32 = if (is_64) 156 else 172;
const SYS_SET_MEMPOLICY: u32 = if (is_64) 236 else 260;
const SYS_ARCH_PRCTL: u32 = if (is_64) 158 else 0; // x86_64 only

// --- Misc ---
const SYS_GETRANDOM: u32 = if (is_64) 318 else 278;
const SYS_SCHED_YIELD: u32 = if (is_64) 24 else 158;
const SYS_RESTART_SYSCALL: u32 = if (is_64) 219 else 0;
const SYS_RSEQ: u32 = if (is_64) 334 else 293;

// --- MPK (Memory Protection Keys) ---
const SYS_PKEY_ALLOC: u32 = if (is_64) 330 else 0;
const SYS_PKEY_FREE: u32 = if (is_64) 331 else 0;
const SYS_PKEY_MPROTECT: u32 = if (is_64) 329 else 0;

// --- Stat variants ---
const SYS_STAT: u32 = if (is_64) 4 else 189;
const SYS_LSTAT: u32 = if (is_64) 6 else 190;

// ============================================================================
// BPF instruction helpers
// ============================================================================

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
    return buildFilterWithAction(nrs, SECCOMP_RET_KILL);
}

fn buildFilterWithAction(comptime nrs: []const u32, deny_action: u32) [5 + nrs.len]sock_filter {
    const N = nrs.len;
    var prog: [5 + N]sock_filter = undefined;
    prog[0] = load(4);
    prog[1] = check(native_arch, 0, @as(u8, @intCast(N + 1)));
    prog[2] = load(0);
    for (nrs, 0..) |nr, i| {
        prog[3 + i] = check(nr, @as(u8, @intCast(N - i)), 0);
    }
    prog[3 + N] = ret(deny_action);
    prog[4 + N] = ret(SECCOMP_RET_ALLOW);
    return prog;
}

// ============================================================================
// Per-process syscall allowlists
// ============================================================================

/// WebProcess (renderer): memory + IPC + filesystem + threads
const web_process_filter = buildFilter(&[_]u32{
    // Memory management
    SYS_MMAP, SYS_MUNMAP, SYS_MPROTECT, SYS_BRK, SYS_MADVISE,
    SYS_MREMAP, SYS_MSYNC, SYS_MLOCK, SYS_MUNLOCK,

    // Basic I/O
    SYS_READ, SYS_WRITE, SYS_CLOSE, SYS_OPENAT, SYS_FSTAT,
    SYS_NEWFSTATAT, SYS_READLINKAT, SYS_GETDENTS64, SYS_LSEEK,
    SYS_PREAD64, SYS_PWRITE64, SYS_READV, SYS_WRITEV,
    SYS_PREADV, SYS_PWRITEV, SYS_DUP, SYS_DUP2,

    // IPC / event loop
    SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_WAIT,
    SYS_PIPE2, SYS_FCNTL, SYS_IOCTL, SYS_EVENTFD2,
    SYS_SOCKETPAIR,

    // Thread management
    SYS_CLONE, SYS_SET_TID_ADDRESS, SYS_SET_ROBUST_LIST,
    SYS_FUTEX, SYS_GETTID, SYS_TGKILL, SYS_TKILL,

    // Signals
    SYS_RT_SIGRETURN, SYS_RT_SIGACTION, SYS_RT_SIGPROCMASK,
    SYS_SIGALTSTACK,

    // Time
    SYS_CLOCK_GETTIME, SYS_GETTIMEOFDAY, SYS_CLOCK_NANOSLEEP,

    // Process
    SYS_GETPID, SYS_GETPPID, SYS_GETUID, SYS_GETGID,
    SYS_GETEUID, SYS_GETEGID, SYS_EXIT_GROUP, SYS_EXIT,
    SYS_PRCTL, SYS_ARCH_PRCTL,

    // Misc
    SYS_GETRANDOM, SYS_SCHED_YIELD, SYS_RSEQ, SYS_RESTART_SYSCALL,
    SYS_ACCESS, SYS_UMASK,
    SYS_GETCWD, SYS_CHDIR, SYS_GETRUSAGE,

    // MPK (JIT support — conditional on jit_enabled)
    SYS_PKEY_ALLOC, SYS_PKEY_FREE, SYS_PKEY_MPROTECT,
});

/// NetworkProcess: all of web + full networking stack
const network_process_filter = buildFilter(&[_]u32{
    // === All of web process syscalls ===
    // Memory management
    SYS_MMAP, SYS_MUNMAP, SYS_MPROTECT, SYS_BRK, SYS_MADVISE,
    SYS_MREMAP, SYS_MSYNC, SYS_MLOCK, SYS_MUNLOCK,

    // Basic I/O
    SYS_READ, SYS_WRITE, SYS_CLOSE, SYS_OPENAT, SYS_FSTAT,
    SYS_NEWFSTATAT, SYS_READLINKAT, SYS_GETDENTS64, SYS_LSEEK,
    SYS_PREAD64, SYS_PWRITE64, SYS_READV, SYS_WRITEV,
    SYS_PREADV, SYS_PWRITEV, SYS_DUP, SYS_DUP2,

    // IPC / event loop
    SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_WAIT,
    SYS_PIPE2, SYS_FCNTL, SYS_IOCTL, SYS_EVENTFD2,
    SYS_SOCKETPAIR,

    // Thread management
    SYS_CLONE, SYS_SET_TID_ADDRESS, SYS_SET_ROBUST_LIST,
    SYS_FUTEX, SYS_GETTID, SYS_TGKILL, SYS_TKILL,

    // Signals
    SYS_RT_SIGRETURN, SYS_RT_SIGACTION, SYS_RT_SIGPROCMASK,
    SYS_SIGALTSTACK,

    // Time
    SYS_CLOCK_GETTIME, SYS_GETTIMEOFDAY, SYS_CLOCK_NANOSLEEP,

    // Process
    SYS_GETPID, SYS_GETPPID, SYS_GETUID, SYS_GETGID,
    SYS_GETEUID, SYS_GETEGID, SYS_EXIT_GROUP, SYS_EXIT,
    SYS_PRCTL, SYS_ARCH_PRCTL,

    // Misc
    SYS_GETRANDOM, SYS_SCHED_YIELD, SYS_RSEQ, SYS_RESTART_SYSCALL,
    SYS_ACCESS, SYS_UMASK,
    SYS_GETCWD, SYS_CHDIR, SYS_GETRUSAGE,

    // MPK
    SYS_PKEY_ALLOC, SYS_PKEY_FREE, SYS_PKEY_MPROTECT,

    // === Networking (additional) ===
    SYS_SOCKET, SYS_CONNECT, SYS_BIND, SYS_LISTEN,
    SYS_ACCEPT, SYS_ACCEPT4, SYS_SENDTO, SYS_RECVFROM,
    SYS_SENDMSG, SYS_RECVMSG, SYS_SHUTDOWN,
    SYS_GETSOCKNAME, SYS_GETPEERNAME,
    SYS_SETSOCKOPT, SYS_GETSOCKOPT,
});

/// GPUProcess: minimal — memory + IPC only (closest to original jit_allowed)
const gpu_process_filter = buildFilter(&[_]u32{
    // Memory management
    SYS_MMAP, SYS_MUNMAP, SYS_MPROTECT, SYS_BRK, SYS_MADVISE,

    // Basic I/O (for /dev/dri access)
    SYS_READ, SYS_WRITE, SYS_CLOSE, SYS_OPENAT, SYS_FSTAT,
    SYS_IOCTL,

    // IPC / event loop
    SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_WAIT,
    SYS_PIPE2, SYS_FCNTL,

    // Thread management
    SYS_CLONE, SYS_SET_TID_ADDRESS,
    SYS_FUTEX, SYS_GETTID,

    // Signals
    SYS_RT_SIGRETURN, SYS_RT_SIGACTION,
    SYS_RT_SIGPROCMASK, SYS_SIGALTSTACK,

    // Time
    SYS_CLOCK_GETTIME,

    // Process
    SYS_GETPID, SYS_EXIT_GROUP,
    SYS_PRCTL, SYS_ARCH_PRCTL,
    SYS_GETCWD, SYS_CHDIR, SYS_GETRUSAGE,

    // Misc
    SYS_GETRANDOM,
});

// ============================================================================
// Legacy filters (backward compat)
// ============================================================================

const jit_allowed_filter = web_process_filter;

const minimal_filter = buildFilter(&[_]u32{
    SYS_READ, SYS_WRITE, SYS_EXIT_GROUP, SYS_RT_SIGRETURN, SYS_FUTEX, SYS_CLOCK_GETTIME,
});

// ============================================================================
// Debug variants (SECCOMP_RET_LOG instead of SECCOMP_RET_KILL)
// These log denied syscalls to the audit log instead of killing the process.
// Use during development to discover missing syscall allowlist entries.
// ============================================================================

const web_process_debug_filter = buildFilterWithAction(&[_]u32{
    SYS_MMAP, SYS_MUNMAP, SYS_MPROTECT, SYS_BRK, SYS_MADVISE,
    SYS_MREMAP, SYS_MSYNC, SYS_MLOCK, SYS_MUNLOCK,
    SYS_READ, SYS_WRITE, SYS_CLOSE, SYS_OPENAT, SYS_FSTAT,
    SYS_NEWFSTATAT, SYS_READLINKAT, SYS_GETDENTS64, SYS_LSEEK,
    SYS_PREAD64, SYS_PWRITE64, SYS_READV, SYS_WRITEV,
    SYS_PREADV, SYS_PWRITEV, SYS_DUP, SYS_DUP2,
    SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_WAIT,
    SYS_PIPE2, SYS_FCNTL, SYS_IOCTL, SYS_EVENTFD2,
    SYS_SOCKETPAIR,
    SYS_CLONE, SYS_SET_TID_ADDRESS, SYS_SET_ROBUST_LIST,
    SYS_FUTEX, SYS_GETTID, SYS_TGKILL, SYS_TKILL,
    SYS_RT_SIGRETURN, SYS_RT_SIGACTION, SYS_RT_SIGPROCMASK,
    SYS_SIGALTSTACK,
    SYS_CLOCK_GETTIME, SYS_GETTIMEOFDAY, SYS_CLOCK_NANOSLEEP,
    SYS_GETPID, SYS_GETPPID, SYS_GETUID, SYS_GETGID,
    SYS_GETEUID, SYS_GETEGID, SYS_EXIT_GROUP, SYS_EXIT,
    SYS_PRCTL, SYS_ARCH_PRCTL,
    SYS_GETRANDOM, SYS_SCHED_YIELD, SYS_RSEQ, SYS_RESTART_SYSCALL,
    SYS_ACCESS, SYS_UMASK,
    SYS_GETCWD, SYS_CHDIR, SYS_GETRUSAGE,
    SYS_PKEY_ALLOC, SYS_PKEY_FREE, SYS_PKEY_MPROTECT,
}, SECCOMP_RET_LOG);

const network_process_debug_filter = buildFilterWithAction(&[_]u32{
    SYS_MMAP, SYS_MUNMAP, SYS_MPROTECT, SYS_BRK, SYS_MADVISE,
    SYS_MREMAP, SYS_MSYNC, SYS_MLOCK, SYS_MUNLOCK,
    SYS_READ, SYS_WRITE, SYS_CLOSE, SYS_OPENAT, SYS_FSTAT,
    SYS_NEWFSTATAT, SYS_READLINKAT, SYS_GETDENTS64, SYS_LSEEK,
    SYS_PREAD64, SYS_PWRITE64, SYS_READV, SYS_WRITEV,
    SYS_PREADV, SYS_PWRITEV, SYS_DUP, SYS_DUP2,
    SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_WAIT,
    SYS_PIPE2, SYS_FCNTL, SYS_IOCTL, SYS_EVENTFD2,
    SYS_SOCKETPAIR,
    SYS_CLONE, SYS_SET_TID_ADDRESS, SYS_SET_ROBUST_LIST,
    SYS_FUTEX, SYS_GETTID, SYS_TGKILL, SYS_TKILL,
    SYS_RT_SIGRETURN, SYS_RT_SIGACTION, SYS_RT_SIGPROCMASK,
    SYS_SIGALTSTACK,
    SYS_CLOCK_GETTIME, SYS_GETTIMEOFDAY, SYS_CLOCK_NANOSLEEP,
    SYS_GETPID, SYS_GETPPID, SYS_GETUID, SYS_GETGID,
    SYS_GETEUID, SYS_GETEGID, SYS_EXIT_GROUP, SYS_EXIT,
    SYS_PRCTL, SYS_ARCH_PRCTL,
    SYS_GETRANDOM, SYS_SCHED_YIELD, SYS_RSEQ, SYS_RESTART_SYSCALL,
    SYS_ACCESS, SYS_UMASK,
    SYS_GETCWD, SYS_CHDIR, SYS_GETRUSAGE,
    SYS_PKEY_ALLOC, SYS_PKEY_FREE, SYS_PKEY_MPROTECT,
    SYS_SOCKET, SYS_CONNECT, SYS_BIND, SYS_LISTEN,
    SYS_ACCEPT, SYS_ACCEPT4, SYS_SENDTO, SYS_RECVFROM,
    SYS_SENDMSG, SYS_RECVMSG, SYS_SHUTDOWN,
    SYS_GETSOCKNAME, SYS_GETPEERNAME,
    SYS_SETSOCKOPT, SYS_GETSOCKOPT,
}, SECCOMP_RET_LOG);

const gpu_process_debug_filter = buildFilterWithAction(&[_]u32{
    SYS_MMAP, SYS_MUNMAP, SYS_MPROTECT, SYS_BRK, SYS_MADVISE,
    SYS_READ, SYS_WRITE, SYS_CLOSE, SYS_OPENAT, SYS_FSTAT,
    SYS_IOCTL,
    SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_WAIT,
    SYS_PIPE2, SYS_FCNTL,
    SYS_CLONE, SYS_SET_TID_ADDRESS,
    SYS_FUTEX, SYS_GETTID,
    SYS_RT_SIGRETURN, SYS_RT_SIGACTION,
    SYS_RT_SIGPROCMASK, SYS_SIGALTSTACK,
    SYS_CLOCK_GETTIME,
    SYS_GETPID, SYS_EXIT_GROUP,
    SYS_PRCTL, SYS_ARCH_PRCTL,
    SYS_GETCWD, SYS_CHDIR, SYS_GETRUSAGE,
    SYS_GETRANDOM,
}, SECCOMP_RET_LOG);

// ============================================================================
// Public API
// ============================================================================

pub const FilterKind = enum {
    web_process,
    network_process,
    gpu_process,
    web_process_debug,
    network_process_debug,
    gpu_process_debug,
    jit_allowed,
    minimal,
};

pub fn install(kind: FilterKind) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    const rc = std.os.linux.syscall5(.prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (std.os.linux.errno(rc) != .SUCCESS) return error.PrctlFailed;

    const filter: []const sock_filter = switch (kind) {
        .web_process => &web_process_filter,
        .network_process => &network_process_filter,
        .gpu_process => &gpu_process_filter,
        .web_process_debug => &web_process_debug_filter,
        .network_process_debug => &network_process_debug_filter,
        .gpu_process_debug => &gpu_process_debug_filter,
        .jit_allowed => &jit_allowed_filter,
        .minimal => &minimal_filter,
    };

    const fprog = sock_fprog{
        .len = @as(u16, @intCast(filter.len)),
        .filter = @ptrCast(filter.ptr),
    };

    const res = std.os.linux.syscall4(.seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, @intFromPtr(&fprog), 0);
    if (std.os.linux.errno(res) != .SUCCESS) return error.SeccompFailed;
}

// ============================================================================
// Tests
// ============================================================================

test "seccomp filter layout — web process" {
    try std.testing.expect(web_process_filter.len > 0);
    try std.testing.expect(web_process_filter[web_process_filter.len - 1].k == SECCOMP_RET_ALLOW);
    try std.testing.expect(web_process_filter[web_process_filter.len - 2].k == SECCOMP_RET_KILL);
    try std.testing.expectEqual(@as(u8, 0), web_process_filter[1].jt);
}

test "seccomp filter layout — network process" {
    try std.testing.expect(network_process_filter.len > web_process_filter.len);
}

test "seccomp filter layout — gpu process" {
    try std.testing.expect(gpu_process_filter.len < web_process_filter.len);
    try std.testing.expect(gpu_process_filter.len > minimal_filter.len);
}

test "seccomp filter layout — minimal" {
    try std.testing.expect(minimal_filter.len > 0);
}
