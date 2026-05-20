# Project Skills and Standards

## Zig 0.16 Standards
- **Memory Management:** Always use `std.ArrayListUnmanaged(T)` instead of `std.ArrayList(T)`.
- **Allocator Pattern:** Always pass an explicit `std.mem.Allocator` to any function that performs allocation or deallocation.
- **System Calls:** Use `std.posix` for low-level system calls where available. Strictly follow the lowercase naming convention (e.g., `posix.O.rdwr`).
- **Atomic Operations:** `std.atomic.fence` and `@fence` are removed. Use appropriate `AtomicOrder` (e.g., `.acquire`, `.release`, `.acq_rel`) directly on atomic operations. For standalone compiler fences, use `asm volatile ("" ::: "memory")`.
- **POSIX Structs:** `posix.Stat_t` is removed. Use `std.os.linux.Statx` for file metadata on Linux systems to leverage performance features.
- **Time Handling:** `std.time.milliTimestamp()` is removed. Use `std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts)` for high-precision measurement.
- **Pointer Safety:** `@fieldParentPtr` now requires an explicit result type. Use `@as(*T, @fieldParentPtr(field_ptr))`.
- **Casting & Alignment:** 0.16 is stricter with `@ptrCast`. Always verify alignment with `@alignOf(T)` and use `@alignCast` when reading from raw ring buffer memory.

## Hajr-Specific Technical Patterns
- **Lock-Free Barriers:** Since explicit fences are gone, the "Release Store" pattern is mandatory. Ensure the payload is fully written *before* the `occupied.store(true, .release)` call.
- **Volatile Metadata:** Use `volatile` when accessing ring buffer metadata that may be modified by a different hardware tier to prevent the compiler from caching values in registers.
- **CPUID Detection:** Use `std.arch.x86.cpuid` for feature detection. Always check for both `PKU` and `OSPKE` before enabling MPK compartments.
- **Error Propagation:** Use `try` on all `std.posix` calls. Convert `errno` to Zig errors using the standard `toError()` pattern where available.


## Hardware Primitive Rules (HAL Usage)
- **Isolation & Protection:** Always use the `hw` module (the Hardware Abstraction Layer) for any memory protection (MPK/MTE) or compartment isolation.
- **Abstraction Mandate:** Do not call raw syscalls for memory protection; use the provided `hw` abstractions.
- **HAL Extension:** If a required hardware feature is missing from the `hw` module, you must extend the HAL first, then use the new extension.
