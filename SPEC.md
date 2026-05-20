# Hajr Browser Sandbox System

## Concept & Vision

Hajr is a next-generation browser sandbox architecture that replaces slow OS-level isolation with hardware-enforced memory protection. By leveraging Intel MPK (Memory Protection Keys) and ARM MTE (Memory Tagging Extension), Hajr achieves sub-5ns IPC latency while maintaining strong security boundaries between browser components. The system treats the network stack, storage engine, and rendering engine as zero-copy data pipelines connected by lock-free ring buffers, eliminating the serialization overhead that plagues legacy browsers like Chrome's Mojo and Firefox's IPDL.

The architecture assumes the OS is too slow to handle security boundaries and places trust in silicon rather than kernel mechanisms. Every sandbox tier operates in isolated memory regions enforced at the hardware level, with crashes resulting in instant CPU faults rather than graceful degradation. This design philosophy enables extreme performance while maintaining defense-in-depth security.

## Design Language

### Aesthetic Direction
Industrial systems programming aesthetic with focus on clarity and security visualization. The codebase emphasizes hardware-level concepts (protection keys, memory rings, tier isolation) over traditional software abstractions.

### Color Palette
- **Primary**: `#2563EB` (Security Blue)
- **Secondary**: `#10B981` (Trust Green)  
- **Accent**: `#F59E0B` (Warning Amber)
- **Danger**: `#EF4444` (Fault Red)
- **Background**: `#0F172A` (Deep Navy)
- **Text**: `#E2E8F0` (Light Slate)

### Typography
- **Code**: JetBrains Mono, monospace
- **Documentation**: Inter, sans-serif
- **Comments**: 60% opacity for inline documentation

### Module Structure
```
hajr/
├── src/
│   ├── core/
│   │   └── sandbox.zig        # Core sandbox architecture
│   ├── network/
│   │   └── netstack.zig       # QUIC/HTTP3 network pipeline
│   ├── ipc/
│   │   └── ipc.zig            # Inter-sandbox communication
│   ├── storage/
│   │   └── storage.zig        # BrowserDB zero-copy storage
│   └── examples/
│       └── simple_sandbox.zig # Basic demonstration
├── build.zig                  # Build configuration
└── SPEC.md                    # This specification
```

## Architecture

### Tier System
Hajr implements a 4-tier security model enforced by hardware:

| Tier | Name | Components | Protection Key |
|------|------|------------|---------------|
| 0 | Root | System initialization, policy management | Key 0 |
| 1 | Trusted | Network stack (z-net), Storage (BrowserDB) | Key 1 |
| 2 | Untrusted | Rendering (Servo), JavaScript (SpiderMonkey) | Key 2 |
| 3 | Isolated | Plugin processes, external handles | Key 3 |

### Memory Model
- **Thread-Bound Arenas**: Each sandbox tier operates within dedicated memory arenas
- **Hardware-Enforced Isolation**: MPK/MTE prevents cross-tier memory access at the MMU level
- **Zero-Copy Rings**: Lock-free ring buffers enable direct memory transfer between tiers

### IPC Mechanism
Lock-free ring buffers with sequence validation provide inter-sandbox communication:

- **Atomic Operations**: No kernel involvement required for message passing
- **Sequence Validation**: Monotonically increasing sequence IDs detect corruption
- **Sub-5ns Latency**: Hardware atomic operations achieve nanosecond-scale IPC

## Features & Interactions

### Core Components

1. **HardenedRingBuffer**: Lock-free ring buffer with hardware protection
   - Memory-mapped anonymous or file-backed storage
   - Sequence-validated atomic indices
   - Power-of-2 sizing for efficient modulo operations

2. **SandboxContext**: Isolated execution environment
   - Unique identifier and tier assignment
   - Hardware protection key management
   - Memory arena allocation
   - IPC ring attachment

3. **SandboxManager**: System coordinator
   - Manages all sandbox contexts
   - Ring buffer pool for IPC
   - Hardware key allocation
   - Fault detection and recovery

4. **NetworkStack**: QUIC/HTTP3 implementation
   - Connection state machine
   - QPACK header compression
   - Zero-copy data paths
   - Direct ring buffer output

5. **IpcRing**: Lock-free IPC primitive
   - Slot-based message passing
   - Atomic producer/consumer indices
   - Hardware protection enforcement

### Message Types
- `init`: Initialize sandbox
- `execute`: Execute function call
- `query/response`: State queries
- `error`: Error reporting
- `shutdown`: Graceful termination
- `heartbeat`: Keepalive monitoring

### Security Properties
- Hardware keys prevent memory access outside tier boundary
- Sequence numbers detect replay attacks and data corruption
- Crash-only recovery prevents state leakage
- No cross-tier pointer passing

## Technical Approach

### Language & Framework
- **Zig 0.16**: Systems programming with comptime, error handling, and C ABI interop
- **Standard Library**: std.io, std.posix, std.atomic for I/O and synchronization
- **Build System**: Zig's built-in build system with cross-compilation support

**Project-Wide Rules (Mandatory):**
1. **Zig 0.16 Standards:** Strict usage of `std.ArrayListUnmanaged(T)`, explicit `Allocator` passing for memory management, and lowercase `std.posix` constants.
2. **Hardware Primitive Rules (HAL):** Always use the `hw` module for all hardware primitives (memory protection, compartments). Raw syscalls for hardware access are forbidden. If a primitive is missing, extend the HAL.

### Hardware Protection
- **Intel MPK**: WRPKRU instruction for setting protection key rights
- **ARM MTE**: Memory tagging for bounds checking
- **Fallback**: Software-based isolation for unsupported platforms

### Data Flow
```
Network (z-net) → Ring Buffer → Servo (parsing) → Ring Buffer → SpiderMonkey (execution)
                                 ↓                      ↓
                            Tier 1               Tier 2
                         (Trusted)           (Untrusted)
```

### Build & Testing
- Standard Zig build with `zig build`
- Test suite with `zig build test`
- Cross-compilation for x86_64 and aarch64

## Component Specifications

### HardenedRingBuffer
```zig
pub const HardenedRingBuffer = struct {
    memory: []align(4096) u8,
    metadata: *volatile RingMetadata,
    data: [*]u8,
    size: usize,
    protection_key: HardwareProtection.Key,
};
```

### IpcRing
```zig
pub const IpcRing = struct {
    slots: [*]RingSlot,
    slot_count: usize,
    head: atomic(u64),
    tail: atomic(u64),
    sequence: atomic(u64),
    protection_key: u32,
};
```

### Message Types
```zig
pub const IpcMessageType = enum(u32) {
    init = 0x00,
    execute = 0x01,
    query = 0x02,
    response = 0x03,
    error = 0x04,
    shutdown = 0x05,
    heartbeat = 0x06,
    // ... storage and network types
};
```

## Security Model

### Threat Model
- Compromised JavaScript engine cannot access network stack memory
- Compromised rendering engine cannot access storage engine memory
- Hardware faults trigger immediate termination, not graceful degradation
- No state leakage across sandbox boundaries

### Defense Layers
1. **Hardware Enforcement**: MPK/MTE at MMU level
2. **Ring Isolation**: Separate rings for each tier boundary
3. **Sequence Validation**: Corruption detection via sequence numbers
4. **Crash-Only Recovery**: Instant termination on fault

### Performance Targets
- IPC latency: < 5ns (vs 100-500μs for Mojo)
- Memory overhead: Minimal (hardware keys instead of processes)
- Throughput: Lock-free design scales with core count