# Hajr Platform Portability Matrix

This document details the cross-platform architecture of the Hajr sandbox and IPC layer, specifying target status, OS abstractions, page-size alignment standards, and libc decoupling policies.

---

## 1. Platform Support Matrix

Hajr is designed to execute across multiple operating systems and CPU architectures. Depending on the capabilities of the platform, it uses either **Hardware-Enforced Sandboxing** or **Software-Fallback Sandboxing**.

| OS | Architecture | Protection Mechanism | Description |
| :--- | :--- | :--- | :--- |
| **Linux** | `x86_64` | **Hardware (Intel MPK)** | Uses protection keys via raw `wrpkru`/`rdpkru` assembly and `pkey_mprotect` syscalls. |
| **Linux** | `aarch64` | **Hardware (ARM MTE)** | Uses memory tagging via `stg` instructions and Linux-specific MTE socket options/permissions. |
| **Windows** | `x86_64` | **Software Fallback** | Uses `VirtualAlloc`/`VirtualProtect` for page-level guards and Vectored Exception Handling (VEH) for fault recovery. |
| **macOS** | `x86_64` | **Software Fallback** | Uses POSIX `mmap`/`mprotect` for page-level guards and `sigaction` handlers for fault recovery. |
| **macOS** | `aarch64` | **Software Fallback** | Uses POSIX `mmap`/`mprotect` with dynamic `std.heap.page_size_min` (16KB page alignment) and `sigaction` handlers. |

---

## 2. Hardware vs. Fallback Isolation

### A. Hardware-Assisted (Linux-Only)
On Linux systems with compatible CPUs, Hajr enforces sub-process memory compartments without process context switches:
* **Intel MPK**: Compartments are assigned keys `0-15`. Access permissions are modified instantly by updating the thread's `PKRU` register via assembly.
* **ARM MTE**: Memory is tagged at 16-byte granules. Pointers hold tags in bits `[59:56]`. Faults are thrown immediately if a tagged pointer attempts to access mismatched memory.

### B. Software Fallback (Windows & macOS)
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
> Apple Silicon macOS utilizes **16KB page sizes**, whereas Linux and Windows x86_64 target **4KB page sizes**. 

### Rules:
1. **Never Hardcode Alignments**: Never write `align(4096)`. Always use `align(std.heap.page_size_min)`.
2. **Page Boundaries**: Round up all memory-mapped arena allocations to multiples of `std.heap.page_size_min` (using `std.mem.alignForward`).
3. **Pointers**: Cast dynamically using `std.heap.page_size_min` to ensure safe pointer arithmetic.

---

## 5. Libc Strategy

Hajr's library and FFI shared library targets do not link libc.
However, test binaries **do link libc** (`link_libc` is enabled on the test step in `build.zig`) because `std.c.mprotect` is used for guard page probing — `std.posix.system.mprotect` does not exist in Zig 0.16's POSIX wrapper.

### Guard Page Probing in Tests:
* Tests that verify guard page security probe page permissions via `hw.os.memProtect` (the unified HAL API).
* This abstracts away the platform-specific implementation: `std.c.mprotect` on macOS/POSIX, `std.os.linux.mprotect` on Linux, `VirtualProtect` on Windows.
* There is never a need to call raw `mprotect` outside the `hw` module.
