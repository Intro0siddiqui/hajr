# AGENTS.md

This file documents the specialized sub-agents and their roles for the Hajr project, ensuring efficient task delegation and context preservation.

## Required Reading
**Before implementing any changes, read `.agents/TECHNICAL_STANDARDS.md` first.** This document contains critical Zig 0.16 compatibility requirements, syscall conventions, and hardware primitive rules.

## Sub-Agent Registry

| Agent Name | Primary Responsibility | Best For |
| :--- | :--- | :--- |
| **`codebase_investigator`** | Architectural Analysis | Mapping dependencies, root-cause analysis of cross-module bugs, and feature planning. |
| **`cli_help`** | Gemini CLI Support | Troubleshooting CLI configuration, policies, and sub-agent management. |
| **`generalist`** | Implementation & Refactoring | Batch refactoring, multi-file error fixing, high-volume shell command execution, and test suite maintenance. |

## Project Rules & Standards

1.  **Zig 0.16 Compatibility**: All code must follow strict 0.16 standards.
    - Use `std.ArrayListUnmanaged`, explicit allocators, and lowercase POSIX constants.
    - **Atomics**: Use explicit memory ordering on operations; avoid standalone fences unless using `asm volatile`.
    - **Stat**: Use `std.os.linux.Stat` for file metadata.
    - **Time**: Prefer `std.Io.Timestamp` where `io` is available; otherwise use `std.os.linux.clock_gettime`.
2.  **Hardware Primitives (HAL)**: 
    - **Isolation & Protection:** Always use the `hw` module (the Hardware Abstraction Layer) for any memory protection (MPK/MTE) or compartment isolation.
    - **Abstraction Mandate:** Do not call raw syscalls for memory protection; use the provided `hw` abstractions.
    - **HAL Extension:** If a required hardware feature is missing from the `hw` module, you must extend the HAL first, then use the new extension.

## Delegation Guidelines

1.  **Scope Appropriateness**: Use the most specialized agent possible. Only invoke `generalist` when a task spans multiple, unrelated modules or requires high-volume, low-context output.
2.  **Concurrency Safety**: Do not run multiple agents that mutate the same files. When managing complex state, use sequential delegation.
3.  **Handoff Protocol**: When delegating, provide the sub-agent with:
    -   The specific file paths involved.
    -   The desired outcome (e.g., "Fix compilation errors", "Implement test").
    -   Constraint/Standards information (e.g., "Use `ArrayListUnmanaged` for Zig 0.16 compatibility").
4.  **Verification**: After a sub-agent completes, the main orchestrator (Gemini CLI) is responsible for verifying the change with project-wide build/test commands.

## Task Flow Strategy

*   **Research**: Use `codebase_investigator`.
*   **Execution**: Use `generalist` for batch changes or targeted refactors.
*   **Validation**: Use CLI standard tools (e.g., `zig build test`) to confirm results post-execution.

---

## 🛰️ Lock-Free Trace Subsystem Architecture

1.  **FFI Hooking**:
    *   `hajr_trace_init()` and `hajr_trace_set_process_kind(kind)` are exported by `libhajr_ffi.so`.
    *   `trace.init(allocator)` sets up the global trace ring and spawns the background `drainLoop` consumer thread.
2.  **Direct Ring Hooking**:
    *   `hajr_ring_write` (`.ring_send`, `.ring_full`), `hajr_ring_read` (`.ring_recv`), and `__zawra_ring_read` (`.ffi_ring_read`) record asynchronously to the lock-free trace ring with zero stdout/stderr stalling.
    *   Zero-byte idle polling loops in `hajr_ring_read` bypass trace recording to prevent ring saturation.
3.  **Dual Output Formats**:
    *   `.bin`: Writes raw 64-byte `TraceRecord` binaries prefixed by a 16-byte `HAJR_TRACE\x01...` magic header for compact low-overhead offline analysis.
    *   `.json`: Writes Chrome Trace Event format (Perfetto-compatible) JSON containing `ph`, `ts`, `pid`, `tid`, `name`, `seq`, `src`, `dst`, `tier_src`, `tier_dst`, and `len`.
4.  **PID Disambiguation**:
    *   Multi-process environments automatically format trace filenames (`<name>.<pid>.bin` / `<name>.<pid>.json` or custom `%d`) so concurrent processes (`UIProcess`, `WebProcess`, `NetworkProcess`, `GPUProcess`) do not truncate or clobber each other.

---

## ⚡ Signal & Sandbox Boundary Pitfalls

1.  **Eventfd Fallback**:
    *   `__hajr_map_anonymous_ring_ex` automatically creates a non-blocking `eventfd` if `signal_fd == -1`, ensuring valid IPC signaling endpoints across namespace boundaries.
2.  **MPK Signal Trap Warning**:
    *   Signal handlers on Linux testing Intel MPK (`WRPKRU`) will enter an infinite signal loop on `sigreturn` unless the `ucontext_t` PKRU state is modified or access rights are explicitly restored before returning from the handler.
3.  **Seccomp Pre-Flight & `HAJR_SEAL_DEBUG`**:
    *   **Silent Death Avoidance**: When debugging child processes, always run with `HAJR_SEAL_DEBUG=1`. This switches Seccomp action from `SECCOMP_RET_KILL_PROCESS` (`SIGSYS`) to `SECCOMP_RET_LOG`, recording the exact violating syscall number to `dmesg` without terminating the process.
    *   **Landlock-Before-Seccomp Ordering**: In `os_abstraction.zig`, Landlock ruleset creation (`landlock_create_ruleset`, syscall 444) and ruleset application (`landlock_restrict_self`, syscall 446) must ALWAYS execute *before* `seccomp.install()`. Installing Seccomp first blocks Landlock setup with `SIGSYS` unless syscalls 444–446 are explicitly whitelisted.
    *   **Mandatory GLib Syscall Whitelist**: Linux multi-threaded GLib event loops require `SYS_POLL` (7), `SYS_PPOLL` (271), `SYS_FSYNC` (74), `SYS_FDATASYNC` (75), and `SYS_MEMFD_CREATE` (319). Never seal auxiliary processes without whitelisting these syscalls.
