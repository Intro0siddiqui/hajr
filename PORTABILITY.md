# Hajr Platform Portability Matrix

This document details the cross-platform architecture of the Hajr sandbox and IPC layer, specifying target status, OS abstractions, page-size alignment standards, and libc decoupling policies.

---

## 1. Platform Support Matrix

Hajr is designed to execute across multiple operating systems and CPU architectures. Depending on the capabilities of the platform, it uses either **Hardware-Enforced Sandboxing** or **Software-Fallback Sandboxing**.

| OS | Architecture | Protection Mechanism | Description |
| :--- | :--- | :--- | :--- |
| **Linux** | `x86_64` | **Hardware (Intel MPK)** | Uses protection keys via raw `wrpkru`/`rdpkru` assembly and `pkey_mprotect` syscalls. |
| **Linux** | `aarch64` | **Hardware (ARM MTE)** | Uses memory tagging via `stg` instructions and Linux-specific MTE socket options/permissions. |
| **Android** | `aarch64` | **Conditional MTE / mprotect** | MTE only when `AT_HWCAP2 & HWCAP2_MTE` and `PR_GET_TAGGED_ADDR_CTRL` both permit it; otherwise page-level `mprotect`. App sandbox (SELinux/isolatedProcess) is the enforcement boundary. |
| **Android** | `x86_64` | **Software Fallback** | No MPK/MTE on the Android emulator target; page-level `mprotect` isolation. |
| **Windows** | `x86_64` | **Software Fallback** | Uses `VirtualAlloc`/`VirtualProtect` for page-level guards and Vectored Exception Handling (VEH) for fault recovery. |
| **macOS** | `x86_64` | **Software Fallback** | Uses POSIX `mmap`/`mprotect` for page-level guards and `sigaction` handlers for fault recovery. |
| **macOS** | `aarch64` | **Hardware (Apple M5+ FEAT_MTE4) / Software Fallback** | Uses hardware memory tagging via `stg`/`tco` when `hw.optional.arm.FEAT_MTE4` is present; otherwise POSIX `mmap`/`mprotect` with dynamic 16KB alignment and guard pages. |

---

## 2. Hardware vs. Fallback Isolation

### A. Hardware-Assisted (Linux & macOS Apple M5+)
On compatible CPUs, Hajr enforces sub-process memory compartments without process context switches:
* **Intel MPK (Linux x86_64)**: Compartments are assigned keys `0-15`. Access permissions are modified instantly by updating the thread's `PKRU` register via assembly.
* **ARM MTE (Linux & macOS M5+ AArch64)**: Memory is tagged at 16-byte granules. Pointers hold tags in bits `[59:56]`. On Linux, capability is verified via `AT_HWCAP2` & `PR_GET_TAGGED_ADDR_CTRL`; on macOS, via Darwin `hw.optional.arm.FEAT_MTE4` (Memory Integrity Enforcement / EMTE). Faults are thrown immediately if a tagged pointer attempts to access mismatched memory.

On Android, Hajr never installs its own syscall/filesystem policy: `sealProcess()`
returns `error.UnsupportedPlatform` (logged by the C FFI) and `isSealed()` stays
false. Multi-process isolation uses `isolatedProcess` Services; rings are attached
with `hajr_ring_map_with_signal()` using FDs passed via Binder/SCM_RIGHTS.
`pidfd_getfd` is disabled because SELinux blocks it.

### B. Software Fallback (Windows, macOS & Android)
On platforms where user-space hardware protection is unavailable or restricted by the OS:
* **Memory Protection**: Fallback code relies on standard OS page permissions (`PAGE_NOACCESS`, `PAGE_READONLY`, `PAGE_READWRITE`).
* **Compartment Isolation**: Tiers are kept separate using page-level protection changes.
* **Fault Recovery**: Hardware exceptions (Access Violations or Segmentation Faults) are handled via platform-native exception pipelines:
  - **Windows**: AddVectoredExceptionHandler (VEH) captures `STATUS_ACCESS_VIOLATION` to identify ring out-of-bounds access.
  - **macOS/POSIX**: Sigaction registers handlers for `SIGSEGV` and `SIGBUS`, extracting the faulting address directly from `siginfo_t.si_addr`.

---

## 3. Win32 API Abstractions (Zig 0.16.0 Compatibility)

Zig `0.16.0`'s `std.os.windows` does not expose memory protection, Vectored Exception Handling, or performance-counter APIs. To support Windows without external dependencies, Hajr hand-declares these symbols directly under `src/hw/windows/` using `.winapi` calling conventions linked to `kernel32`:

```zig
// Example from src/hw/windows/memory.zig
extern "kernel32" fn VirtualAlloc(
    lpAddress: ?windows.LPVOID,
    dwSize: windows.SIZE_T,
    flAllocationType: windows.DWORD,
    flProtect: windows.DWORD,
) callconv(.winapi) ?windows.LPVOID;
```

These definitions prevent compile-time symbol resolution failures and keep cross-compilation target code fully self-contained.

---

## 4. Page Size & Alignment Rules

Memory allocation and guard boundaries must be mapped onto hardware page boundaries.
> [!IMPORTANT]
> Apple Silicon macOS utilizes **16KB page sizes**, whereas Linux, Android and Windows x86_64 target **4KB page sizes**.

### Rules:
1. **Never Hardcode Alignments**: Never write `align(4096)`. Always use `align(std.heap.page_size_min)`.
2. **Page Boundaries**: Round up all memory-mapped arena allocations to multiples of `std.heap.page_size_min` (using `std.mem.alignForward`).
3. **Pointers**: Cast dynamically using `std.heap.page_size_min` to ensure safe pointer arithmetic.

---

## 5. Libc Strategy

On Android, Zig does not provide Bionic: cross-builds need an NDK sysroot and a
libc config generated with `zig libc` (see `README.md`). Only the libraries are
built for Android; the host-only executables are skipped because the NDK has no
static `libc.a`.

Hajr's library and FFI shared library targets do not link libc.
However, test binaries **do link libc** (`link_libc` is enabled on the test step in `build.zig`) because `std.c.mprotect` is used for guard page probing — `std.posix.system.mprotect` does not exist in Zig 0.16's POSIX wrapper.

### Guard Page Probing in Tests:
* Tests that verify guard page security probe page permissions via `hw.os.memProtect` (the unified HAL API).
* This abstracts away the platform-specific implementation: `std.c.mprotect` on macOS/POSIX, `std.os.linux.mprotect` on Linux, `VirtualProtect` on Windows.
* There is never a need to call raw `mprotect` outside the `hw` module.
