# Hajr Project Analysis & Memory Summary

## 1. Project Overview
**Hajr** is an experimental, next-generation browser sandbox subsystem for the Zawra browser architecture. It rejects traditional OS-level isolation (which suffers from serialization overhead, e.g., Chrome's Mojo or Firefox's IPDL) in favor of hardware-enforced memory isolation (Intel MPK / ARM MTE) and sub-5ns lock-free data pipelines.

**Core Philosophy:** 
- Trust silicon, not the kernel.
- Zero-copy data transfers via lock-free ring buffers between security tiers.
- "Crash-only" recovery semantics (the Poison Protocol): ANY fault or anomaly terminates the sandbox instantly.

**Project-Wide Rules (Mandatory):**
1. **Zig 0.16 Standards:** Strict usage of `std.ArrayListUnmanaged(T)`, explicit `Allocator` passing for memory management, and lowercase `std.posix` constants.
2. **Hardware Primitive Rules (HAL):** Always use the `hw` module for all hardware primitives (memory protection, compartments). Raw syscalls for hardware access are forbidden. If a primitive is missing, extend the HAL.

**Tech Stack:** Zig 0.16.0. Strict C ABI bindings for FFI.

## 2. Completed Milestones

### Phase 1: Foundational Sandbox Primitive
- Implemented `HajrCage` for hardware-level isolation.
- Created `HardenedRingBuffer` (`src/core/sandbox.zig`) for low-latency IPC. 

### Phase 2: Zero-Copy FFI Bridge & Tier 1 Event Router
*This was the most recent phase of work, successfully implemented and tested locally.*
1. **Arena Layout Manager (`src/hajr/memory.zig`)**: 
   - Uses deterministic `std.posix.mmap` block allocation.
   - Segments memory into an inbound ring, outbound ring, and JS heap with strict 4096-byte page alignment.
2. **SpiderMonkey Zero-Copy FFI (`src/hajr/sm_bindings.zig`)**:
   - `__zawra_ring_read` directly maps contiguous ring memory into SpiderMonkey via its External ArrayBuffer representation, completely bypassing memory duplication.
   - Replaced Zig 0.15 `std.atomic` patterns with explicit Zig 0.16 compliant code (e.g., proper alignment and pointer dereferencing for `atomic.Value(T)`).
3. **Tier 1 Event Router (`src/hajr/router.zig`)**:
   - Built a `< 5ns` lock-free polling mechanism (`poll()`) that iteratives over contiguous arrays of `ActiveRing`s.
   - Routes request payloads (`net_fetch`, `storage_read`, etc.) to respective backends.
4. **Poison Protocol Integration (`src/hajr/router.zig`)**:
   - Atomic checking of `poison_bit` in the polling loop.
   - If a sandbox goes rogue (e.g., sequence anomaly or JIT escape), Tier 0 Observer instantly `munmap`s the arena and kills the threat.

## 3. Next Steps (Phase 3 & Beyond)
Do **not** move to full Phase 3 "glue code" integrations until Phase 2 is validated empirically.

**Immediate Validation Task:**
- Compile `src/hajr/sm_bindings.zig` into a dynamic library (`.so` / `.dylib`).
- Write an isolated test script using **Bun** or **Deno**'s FFI capabilities.
- Validate that the JS runtime can interact with the mock ring buffers natively over the C ABI without buffer overflows.

**Phase 3 Implementation Scope (Post-Validation):**
1. **Rendering Engine (Servo) Integration**: Exposing the ring bindings to Servo so HTML/CSS payloads are pulled straight from the rings.
2. **z-net QUIC/HTTP3 Implementation**: Wiring the router to actually pipe `src/network/netstack.zig` connections.
3. **BrowserDB Storage Engine**: Connecting the storage endpoints (`src/storage/storage.zig`) into the `browser_db()` route.
4. **Full IPC Formalization**: Upgrading the simple payload routing to the slot-based formal protocol in `src/ipc/ipc.zig`.

## 4. Environment & Context Memories
- **Compiler Target:** Zig `0.16.0`
- **Known Zig 0.16 Caveats Handled:**
  - `callconv(.c)` is strictly lowercased.
  - `@ptrFromInt` and `@fieldParentPtr` require strictly defined LHS pointers with `@as`.
  - `std.atomic.Value` replaces the old atomic primitives; standalone fences are replaced by operation-level memory ordering (`.acquire`, `.release`).
  - `std.posix` constants are now lowercase (e.g., `posix.O.rdwr`).
  - `std.os.linux.statx` is the preferred path for high-performance file metadata over the deprecated `fstat`.
  - CPUID detection moved to `std.arch.x86`.
  - All `std.ArrayList` usage migrated to `ArrayListUnmanaged` to support the explicit allocator passing mandate.
- **Git Context:** The initial template was unzipped from `package.zip`. All files were moved to the project root and the `build.zig` has been refactored to compile the test suite. All tests currently pass.
