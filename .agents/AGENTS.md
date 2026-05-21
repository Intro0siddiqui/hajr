# AGENTS.md

This file documents the specialized sub-agents and their roles for the Hajr project, ensuring efficient task delegation and context preservation.

## Required Reading
**Before implementing any changes, read `ZIG_DEVELOPER_GUIDE.md` first.** This document contains critical Zig 0.16 compatibility requirements, syscall conventions, and hardware primitive rules.

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
