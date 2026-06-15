# Hajr FFI Exports — C/C++ Integration Guide

## Overview

Hajr exports C-ABI functions that can be called from C/C++ code. These are compiled
into `libhajr_ffi.so` (shared) or `libhajr_ffi_static.a` (static). The FFI boundary
uses `extern "C"` linkage and `callconv(.c)` on the Zig side.

## Build Integration

### Linking

```cmake
# CMake
target_link_libraries(your_target PRIVATE hajr_ffi)          # shared
target_link_libraries(your_target PRIVATE hajr_ffi_static)   # static
```

```makefile
# Makefile
LDFLAGS += -lhajr_ffi          # shared
# or
LDFLAGS += -L/path/to/hajr -lhajr_ffi_static -lm -lpthread -lc
```

### Header Declarations

Add these `extern "C"` declarations in a header (e.g. `hajr_ffi.h`):

```c
#ifndef HAJR_FFI_H
#define HAJR_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Process Sealing (Sandbox Lockdown)
// ============================================================================

// Process type constants — match Zig ProcessType enum
#define HAJR_PROCESS_WEB     0u
#define HAJR_PROCESS_NETWORK 1u
#define HAJR_PROCESS_GPU     2u

// Seal the current process with per-process syscall + filesystem restrictions.
// process_type: HAJR_PROCESS_WEB, HAJR_PROCESS_NETWORK, or HAJR_PROCESS_GPU
//
// What it does on each platform:
//   Linux:   Installs seccomp-BPF filter (KILL on deny) + Landlock FS restrictions
//   macOS:   Applies seatbelt SBPL profile
//   Windows: Sets process mitigation policies (DEP, ASLR, win32k, etc.)
//
// This should be called FIRST in each process, before any other initialization.
// It is idempotent — calling it multiple times is safe (second+ calls are no-ops).
void hajr_seal_process(unsigned int process_type);

// Same as hajr_seal_process but uses SECCOMP_RET_LOG instead of SECCOMP_RET_KILL
// on Linux. Denied syscalls are logged to the audit log instead of killing the
// process. Use during development to discover missing syscall allowlist entries.
//
// On macOS/Windows this behaves identically to hajr_seal_process (no equivalent).
void hajr_seal_process_debug(unsigned int process_type);

// Backward-compatible no-argument version. Defaults to WEB process type.
void hajr_seal_process_legacy(void);

// ============================================================================
// Ring Buffer IPC
// ============================================================================

// Initialize the ring buffer with metadata pointers from the shared memory region.
typedef struct {
    unsigned char* inbound_base;
    unsigned long  inbound_size;
    void*          inbound_meta;   // *RingMetadata
    unsigned char* outbound_base;
    unsigned long  outbound_size;
    void*          outbound_meta;  // *RingMetadata
} HajrFFIConfig;

// Initialize FFI with ring buffer configuration.
void __zawra_init_ffi(const HajrFFIConfig* config);

// Read payload from inbound ring (zero-copy).
// Returns: 1 = success (data in out_ext_buf), 0 = empty, -1 = no config, -2 = poisoned
int __zawra_ring_read(void* out_ext_buf);

// Commit bytes consumed from the inbound ring.
void __zawra_ring_commit_read(unsigned long bytes_consumed);

// ============================================================================
// C-Style Ring Buffer FFI
// ============================================================================

// Opaque ring buffer handle
typedef struct HajrRing HajrRing;

// Create a ring buffer from pre-allocated memory.
HajrRing* hajr_ring_init(
    unsigned char* buffer, unsigned long buffer_len,
    unsigned long size, unsigned int key_value, unsigned char tier_value
);

// Map an existing shared memory ring buffer.
HajrRing* hajr_ring_map(
    unsigned char* buffer, unsigned long buffer_len,
    unsigned long size, unsigned int key_value, unsigned char tier_value
);

// Map with a signal file descriptor for event-driven wakeup.
HajrRing* hajr_ring_map_with_signal(
    unsigned char* buffer, unsigned long buffer_len,
    unsigned long size, unsigned int key_value, unsigned char tier_value,
    int signal_fd
);

// Free a ring buffer.
void hajr_ring_free(HajrRing* ring);

// Write data to ring. Returns: 1 = ok, 0 = full, -1 = null, -2 = poisoned
int hajr_ring_write(HajrRing* ring, const unsigned char* data, unsigned long length);

// Read data from ring. Returns: 1 = ok, 0 = empty, -1 = null, -2 = poisoned
int hajr_ring_read(HajrRing* ring, unsigned char* buf, unsigned long length, unsigned long* bytes_read);

// Signal/wake the ring (via eventfd or futex).
int hajr_ring_signal(HajrRing* ring);

// Wait for ring data (via eventfd or futex).
int hajr_ring_wait(HajrRing* ring);

// Get the signal file descriptor (-1 if none).
int hajr_ring_get_signal_fd(HajrRing* ring);

// ============================================================================
// Anonymous Shared Memory Rings
// ============================================================================

// Create an anonymous ring backed by memfd_create / shm_open.
// Returns: file descriptor, or ULLONG_MAX on error
unsigned long __hajr_create_anonymous_ring(unsigned long size);

// Map an anonymous ring by file descriptor.
void* __hajr_map_anonymous_ring(unsigned long id);

// Map with signal fd.
void* __hajr_map_anonymous_ring_ex(unsigned long id, int signal_fd);

// ============================================================================
// Sandbox Allocation
// ============================================================================

// Allocate a sandbox compartment and return its hardware protection key.
unsigned int __zawra_allocate_sandbox(unsigned char tier);

// Free a sandbox compartment.
void __zawra_free_sandbox(unsigned int id);

// ============================================================================
// IPC File Descriptor Passing
// ============================================================================

// Set the pidfd of the other process for fd passing.
void hajr_ipc_set_other_pidfd(int pidfd);

// Send a file descriptor over IPC.
int hajr_ipc_send_fd(HajrRing* ring, int fd);

// Receive a file descriptor from IPC (via pidfd_getfd).
int hajr_ipc_recv_fd(HajrRing* ring, int handle);

// ============================================================================
// Threading
// ============================================================================

// Create a thread. Returns: thread handle (platform-specific), 0 on error.
unsigned long hajr_thread_create(
    void* (*func)(void*),
    void* arg
);

// Join a thread. Returns: 0 = ok, -1 = error.
int hajr_thread_join(unsigned long handle);

// Set thread priority (0-255). Returns: 0 = ok, -1 = error.
int hajr_thread_set_priority(unsigned long handle, unsigned char priority);

// ============================================================================
// Filesystem
// ============================================================================

// Seek within a file. Returns: new offset, 0 on error.
unsigned long Zawra_File_Seek(int handle, long long offset, int origin);

// Stat a file by path. Returns: 0 = ok, -1 = error.
int Zawra_File_Stat(const char* path, void* info);

// Stat a file by descriptor. Returns: 0 = ok, -1 = error.
int Zawra_File_StatFD(int handle, void* info);

// Check file accessibility. Returns: 1 = accessible, 0 = not
int Zawra_File_Access(const char* path, unsigned int mode);

// Unlink a file. Returns: 0 = ok, -1 = error.
int Zawra_File_Unlink(const char* path);

// Create a directory. Returns: 0 = ok, -1 = error.
int Zawra_File_Mkdir(const char* path);

// ============================================================================
// Memory
// ============================================================================

// Allocate memory (with guard pages). Returns: pointer or NULL.
void* Zawra_Hajr_MemAlloc(unsigned long size);

// Protect memory region. Returns: 0 = ok, -1 = error.
int Zawra_Hajr_MemProtect(void* ptr, unsigned long size, int read, int write);

// ============================================================================
// Time
// ============================================================================

// Get monotonic time in seconds. OS-agnostic.
double Zawra_Hajr_GetMonotonicTime(void);

// ============================================================================
// CRC32
// ============================================================================

// Calculate CRC32 checksum (Castagnoli polynomial).
unsigned int hajr_crc32(const unsigned char* data, unsigned long length);

// Calculate CRC32 of IPC message (header + payload).
unsigned int hajr_ipc_message_checksum(
    const unsigned char* header, unsigned long header_len,
    const unsigned char* payload, unsigned long payload_len
);

// Verify IPC message checksum. Returns: 1 = match, 0 = mismatch
int hajr_ipc_verify_checksum(
    const unsigned char* header, unsigned long header_len,
    const unsigned char* payload, unsigned long payload_len,
    unsigned int expected_checksum
);

// ============================================================================
// Spawn
// ============================================================================

// Spawn a compartment process. Returns: PID, -1 on error.
int hajr_spawn_compartment(
    const char* path,
    const char* const* argv,
    int* out_socket
);

#ifdef __cplusplus
}
#endif

#endif // HAJR_FFI_H
```

## Usage Examples

### Basic Process Sealing (WebProcess)

```cpp
// WebProcessMainWPE.cpp

extern "C" void hajr_seal_process(unsigned int process_type);

#define HAJR_WEB_PROCESS     0u
#define HAJR_NETWORK_PROCESS 1u
#define HAJR_GPU_PROCESS     2u

int WebProcessMain(int argc, char** argv)
{
    // Seal FIRST — before any WebKit initialization
    // This installs seccomp + Landlock on Linux, seatbelt on macOS
    hajr_seal_process(HAJR_WEB_PROCESS);

    // Now initialize WebKit subsystems...
    return AuxiliaryProcessMain<WebProcessMainWPE>(argc, argv);
}
```

### Debug Mode (Audit Denials)

```cpp
extern "C" void hajr_seal_process_debug(unsigned int process_type);

// In a debug build, use _debug variant to log instead of kill:
#ifdef NDEBUG
    hajr_seal_process(HAJR_WEB_PROCESS);     // KILL on denied syscall
#else
    hajr_seal_process_debug(HAJR_WEB_PROCESS); // LOG on denied syscall
#endif
```

When a syscall is denied in debug mode, you'll see output like:

```
audit: SECCOMP audit syscall 2 (openat) allowed=0
```

Check `dmesg` or `/var/log/audit/audit.log` for the full audit trail.

### All Three Process Types

```cpp
// WebProcessMainWPE.cpp
hajr_seal_process(0);  // HAJR_WEB_PROCESS

// NetworkProcessMainSoup.cpp
hajr_seal_process(1);  // HAJR_NETWORK_PROCESS

// GPUProcessMainGLib.cpp
hajr_seal_process(2);  // HAJR_GPU_PROCESS
```

### Error Handling

The `hajr_seal_process` function is fire-and-forget — it does not return an error
code. If sealing fails, the function:
1. Logs the error to stderr: `hajr: [LOCKDOWN FAILED] process_type=web error=SeccompFailed`
2. Returns without sealing — the process continues unsealed

To detect failure programmatically, use the Zig `seal()` function directly (if
linking statically):

```zig
const lockdown = @import("hajr").lockdown;
lockdown.seal(.web) catch |err| {
    // Handle error
};
```

### Ring Buffer IPC (Zero-Copy)

```cpp
extern "C" {
    HajrRing* hajr_ring_init(
        unsigned char* buffer, unsigned long buffer_len,
        unsigned long size, unsigned int key_value, unsigned char tier_value
    );
    int hajr_ring_write(HajrRing* ring, const unsigned char* data, unsigned long length);
    int hajr_ring_read(HajrRing* ring, unsigned char* buf, unsigned long length, unsigned long* bytes_read);
}

// Create a ring buffer from pre-allocated memory
HajrRing* ring = hajr_ring_init(buffer, buffer_len, ring_size, 0, 0);

// Write to ring
const char* msg = "hello from C++";
hajr_ring_write(ring, (const unsigned char*)msg, 14);
```

## What Each Process Type Gets

### Linux

| | WebProcess | NetworkProcess | GPUProcess |
|---|---|---|---|
| **Seccomp syscalls** | ~35 (memory, IPC, FS, threads) | ~50 (+networking) | ~20 (memory, IPC only) |
| **Landlock FS** | Read: fonts, DNS, profile. Write: /tmp | Read: DNS, TLS certs. Write: profile, cache | Read/Write: /dev/dri, profile |
| **Seccomp deny action** | KILL (or LOG in debug) | KILL (or LOG in debug) | KILL (or LOG in debug) |

### macOS

| | WebProcess | NetworkProcess | GPUProcess |
|---|---|---|---|
| **Seatbelt** | Custom SBPL: fonts, network, profile write | Custom SBPL: full network, DNS, TLS, cache | Custom SBPL: Metal/GPU IOKit, no network |
| **Syscall allow** | Network + FS read/write | Network + FS read/write | FS read + profile write only |

### Windows

| | WebProcess | NetworkProcess | GPUProcess |
|---|---|---|---|
| **DEP** | Enabled, permanent | Enabled, permanent | Enabled, permanent |
| **ASLR** | High entropy, bottom-up | High entropy, bottom-up | High entropy, bottom-up |
| **Win32k** | Disabled (prevents font exploits) | Disabled | **Enabled** (GPU needs it) |
| **Extension points** | Disabled | Disabled | Disabled |
| **Image load** | No remote, no low-label | No remote, no low-label | No remote, no low-label |
| **Integrity level** | Low | Low | Low |

## Platform-Specific Notes

### Linux

- Seccomp filter is applied to **all threads** via `SECCOMP_FILTER_FLAG_TSYNC`
- `PR_SET_NO_NEW_PRIVS` is set to prevent privilege escalation
- Landlock is applied **after** seccomp — paths that don't exist are silently skipped
- The `openat` syscall used by Landlock path setup is in the seccomp allowlist

### macOS

- Seatbelt profiles use SBPL (Sandbox Profile Language)
- The `sandbox_init` API with flag `3` (`SBPL`) is used for custom profiles
- PAC (Pointer Authentication) is automatic on arm64e — no explicit enable needed
- No per-process filesystem restriction beyond seatbelt (use sandbox containers for that)

### Windows

- Mitigation policies are **one-way** — once set, they cannot be unset
- `applyLowIntegrity()` drops the process to Low integrity level (write-only to low-integrity locations)
- No per-process syscall filtering equivalent to seccomp — Windows uses AppContainer for that
- GPU process **must** have `no_win32k = false` or DirectX/Metal rendering fails

## Migration from Old API

| Old | New | Notes |
|---|---|---|
| `hajr_seal_process()` (no args) | `hajr_seal_process(0)` | Pass `HAJR_WEB_PROCESS` explicitly |
| `hajr_seal_process_ex(jit, min, ril)` | `hajr_seal_process_debug(0)` | Use debug mode for iteration |
| `hajr_seal_process()` + `catch {}` | `hajr_seal_process(0)` | Errors now logged to stderr |
