# Hajr Zig Developer Guide

This guide defines the engineering standards, architectural patterns, and Zig `0.16.0` constraints for the Hajr project. All contributors must adhere to these rules to maintain portability and security.

## 1. Core Language Standards
- **Memory Management**: Use `std.ArrayListUnmanaged(T)` for all performance-critical paths. This enforces passing the `Allocator` to every mutating operation.
- **Allocator Pattern**: Always pass an explicit `std.mem.Allocator` to any function that performs allocation or deallocation.
- **Error Handling**: Use `try` for all syscalls. Map `errno` to domain-specific `Error` types.
- **Atomic Ordering**: Project policy forbids explicit `@fence` calls. Use operation-level memory ordering (`.acquire`, `.release`, `.acq_rel`).
- **Pointers & Casting**: 
    - `@ptrCast` requires explicit target types: `@as(*T, @ptrCast(ptr))`.
    - **Raw Syscalls**: When passing packed structs (like `PROT` or `MAP`) to raw syscalls, use `@bitCast` to convert them to `u32` (e.g., `@as(u32, @bitCast(std.os.linux.PROT{ .READ = true }))`).
## 2. HAL (Hardware Abstraction Layer) Standards
The HAL is the boundary between hardware primitives (MPK/MTE) and the browser core. All memory protection and hardware-level operations MUST go through the `hw` module.

### Mandatory Usage Rules
- **No Bypassing**: Never call `mprotect`, `pkey_mprotect`, or direct memory mapping syscalls outside of the `hw` module. All sandbox tiers must use the abstractions provided in `src/hw/mod.zig`.
- **Fault Handling**: Do not register POSIX signal handlers (`sigaction`) or Windows Exception Handlers directly. Use the neutral interface: `hw.exception.registerFaultHandler(my_callback)`.
- **Hardware Keys**: Key allocation and permission management (PKRU/MTE tags) are strictly managed via `hw.compartment` and `hw.mod`.

### The Three-Layer Architecture
...
1. **Facade (`src/hw/mod.zig`)**: Public API. Coordinates between hardware and OS. **No raw syscalls allowed here.**
2. **OS Abstraction (`src/hw/os_abstraction.zig`)**: The "OS Boundary." All platform-specific syscalls (mmap, pkey, mprotect, file I/O, timing) must be implemented here.
3. **Hardware Implementation (`src/hw/arch/`)**: Pure assembly for hardware-specific instructions (e.g., `wrpkru`, `stg`).

### Critical Architectural Rules
- **No Redundant Syscalls**: Do not call `mprotect` immediately before `pkey_mprotect`. The latter already handles memory protection; calling both causes performance degradation and potential race conditions.
- **Constant Naming**: Use the UPPERCASE naming convention for `std.posix` fields as enforced by the local 0.16.0 build (e.g., `posix.PROT{ .READ = true }`).

## 3. Zig 0.16 Migration Standards
- **File Metadata**: `posix.Stat_t` / `fstat` are deprecated. Use `std.os.linux.Statx` for performance-critical metadata on Linux.
- **Timing**: `std.time.milliTimestamp()` is deprecated. Use `std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts)` for low-level work or `std.Io.Timestamp` for high-level logic.
- **Alignment**: Never hardcode `4096`. Use the platform-neutral alignment `65536` for page-aligned buffers, or query `std.mem.page_size` at runtime.

## 4. Development Workflow
1. **Modernize**: Align with Zig 0.16 standards (Statx, clock_gettime, explicit allocators).
2. **Abstract**: Move any raw syscalls (including `pkey_mprotect`) into `os_abstraction.zig`.
3. **Verify**: Run `zig build test` after every major module change.
4. **Document**: Record platform-specific findings in `PORTABILITY.md`.
