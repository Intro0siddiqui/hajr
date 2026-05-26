# Hajr Sandbox & IPC Layer

Hajr is a hardware-enforced sandbox and zero-copy IPC layer — the isolation substrate for the Zawra browser. 

It serves the same role as **Chrome's Sandbox + Mojo IPC**, but replaces OS process boundaries with MPK/MTE hardware keys and lock-free ring buffers for ~200ns cross-thread IPC.

> **Note:** Hajr is the *isolation layer only*. Browser-level subsystems like networking (`z-net`), storage (`BrowserDB`), and rendering (`Gecko`) are independent components built *on top* of Hajr. They are not part of Hajr itself and live in their own repositories.

## How It Works

### Hardware-Enforced Sandboxing
Legacy browsers rely on the OS kernel to enforce security boundaries between processes. Hajr assumes the OS is too slow for high-frequency browser operations. Instead, it uses:
*   **Intel MPK (Memory Protection Keys)**
*   **ARM MTE (Memory Tagging Extension)**

These hardware features enforce strict boundaries at the Memory Management Unit (MMU) level. If a component violates its boundary, a hardware fault triggers an instant termination (Crash-Only Recovery), preventing state leakage.

### Zero-Copy IPC (The "Modern Mojo")
Communication between browser components (Network, Storage, Rendering) occurs through **Lock-Free Ring Buffers**. 
*   **Zero Serialization:** Data is not copied or serialized between boundaries. Memory access rights are simply transferred via hardware keys.
*   **Atomic Validation:** No kernel involvement is required for message passing. Monotonically increasing sequence IDs detect corruption or replay attacks.

## The 4-Tier Security Model

Hajr enforces a strict 4-tier security model using protection keys:

| Tier | Name | Purpose |
| :--- | :--- | :--- |
| **0** | **Root** | System initialization and global policy management. |
| **1** | **Trusted** | Safe subsystems like the Network stack (z-net) and Storage (BrowserDB). |
| **2** | **Untrusted** | Dangerous components like Rendering (Gecko) and JavaScript execution (JavaScriptCore). |
| **3** | **Isolated** | Highly restricted 3rd-party plugins and external handles. |

## Developer Guide

### Prerequisites
*   **Zig `0.16.0`** is strictly required.
*   The project supports **Linux** (`x86_64`, `aarch64`), **Windows** (`x86_64`), and **macOS** (`x86_64`, `aarch64`).
*   For cross-platform behavior, hardware-assisted vs. software-fallback isolation, and OS-specific details, see [PORTABILITY.md](file:///home/Intro/spectre-enviroment/hajr/PORTABILITY.md).

### Building & Testing
To run the comprehensive test suite, which validates the sandbox boundaries, the IPC ring buffers, and the memory arenas:

```bash
zig build test      # compile test suite
```

To run the cross-thread IPC latency benchmark:

```bash
zig build benchmark   # compile and run
```

To cross-compile for other platforms (e.g. Windows or macOS):
```bash
zig build -Dtarget=x86_64-windows
zig build -Dtarget=aarch64-macos
```

### Codebase Organization
*   `src/core/`: The core sandbox architecture and hardware/software fallback key management.
*   `src/ipc/`: The lock-free, zero-copy ring buffer implementation.
*   `src/hw/`: The Hardware Abstraction Layer mapping Zig to raw MPK/MTE operations and OS-specific fallbacks.
*   `src/sandbox/`: Sandbox runtime — memory layout, event routing, poison protocol, JavaScriptCore FFI bindings.
