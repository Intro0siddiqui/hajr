# Hajr Sandbox & IPC Layer

Hajr is a modern browser sandbox and Inter-Process Communication (IPC) subsystem designed for the Zawra browser architecture. 

Conceptually, it serves the same purpose as **Chrome's Sandbox and Mojo IPC**, but rebuilt from the ground up using modern hardware techniques. Instead of relying on slow OS-level process isolation and heavy serialization overhead, Hajr leverages **hardware-enforced memory isolation** and **zero-copy data pipelines** to achieve sub-5ns IPC latency.

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
| **2** | **Untrusted** | Dangerous components like Rendering (Servo) and JavaScript execution (SpiderMonkey). |
| **3** | **Isolated** | Highly restricted 3rd-party plugins and external handles. |

## Developer Guide

### Prerequisites
*   **Zig `0.16.0`** is strictly required.
*   The project relies on specific POSIX and OS-level interfaces, with portability currently focused on Linux/x86_64 and AArch64.

### Building & Testing
To run the comprehensive test suite, which validates the hardware sandbox boundaries, the IPC ring buffers, and the memory arenas:

```bash
zig build test
```

### Codebase Organization
*   `src/core/`: The core sandbox architecture and hardware key management.
*   `src/ipc/`: The lock-free, zero-copy ring buffer implementation.
*   `src/hw/`: The Hardware Abstraction Layer mapping Zig to raw MPK/MTE operations.
*   `src/network/` & `src/storage/`: High-performance, sandboxed subsystems.
