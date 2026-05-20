# Portability Audit: Hajr Sandbox

This document tracks components that are currently coupled to specific operating systems or hardware architectures. The Hajr project aims for high-performance hardware-assisted isolation, which inherently relies on platform-specific primitives.

## OS-Dependent Components (Linux-Only)
These files utilize raw Linux system calls (`pkey_alloc`, `pkey_mprotect`, `mmap` specific flags) that are not currently abstracted for other platforms.

*   `src/hw/mod.zig`: Uses Linux-specific syscalls for MPK/MTE protection.
*   `src/hw/compartment.zig`: Contains raw Linux syscall numbers (330, 331) for PKEY management.
*   `src/hw/exception.zig`: Relies on POSIX-specific signal handling (`SIGSEGV`, `SIGBUS`, `sigaction`).
*   `src/ipc/ipc.zig`: Uses `std.os.linux.clock_gettime` for high-precision timing.
*   `src/storage/storage.zig`: Uses `openat`, `ftruncate`, and `pwrite/pread` which are heavily POSIX-centric.
*   `src/core/sandbox.zig`: Uses `mmap` and `munmap` direct syscalls with Linux-specific flags.
*   `src/hajr/poison.zig`: Uses POSIX signal handling for crash recovery.

## Hardware-Dependent Components (x86_64 / AArch64)
*   `src/hw/mod.zig`: Contains architecture-specific assembly (`wrpkru`, `rdpkru`, `stg`) for x86_64 and AArch64.
*   `src/core/sandbox.zig`: Uses `std.arch.x86.cpuid` for feature detection.

## Truly OS-Agnostic Components (Cross-Platform)
The following modules are successfully abstracted and portable:

*   `src/hajr/router.zig`: High-level event routing.
*   `src/hajr/memory.zig`: Deterministic memory arena management.
*   `src/hajr/sm_bindings.zig`: Zero-copy FFI interfaces.
*   `src/hw/pointer.zig`: Tagged pointer logic with software fallbacks.

## Roadmap for Portability
1.  **Abstraction Layer:** Introduce a unified `OS` interface for memory protection and signal handling.
2.  **Fallback Implementation:** Replace Linux-specific syscalls in `src/hw/` with generic `std.posix` implementations or no-op fallbacks.
3.  **Cross-Platform CI:** Integrate build checks for non-Linux targets to prevent regression.
