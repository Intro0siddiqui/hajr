# Poison Protocol — Activation Guide

## What It Does

The poison protocol provides **fail-fast crash-only recovery** when a sandbox is compromised. It detects:
- Ring buffer metadata corruption
- Sequence number anomalies (replay attacks)
- Out-of-bounds memory access (SIGSEGV/SIGBUS)
- JIT escape attempts
- Ring corruption

When detected, the ring is "poisoned" — all reads/writes immediately return `-2`, and the sandbox is terminated.

## Current State

**Implemented but not wired.** All components exist:

| Component | File | Status |
|-----------|------|--------|
| `poison_bit` / `poison_cause` in `RingMetadata` | `core/sandbox.zig:124-127` | ✅ Exists |
| `poisonRing()` / `isRingPoisoned()` | `poison.zig:75-88` | ✅ Exists |
| Poison check in `hajr_ring_read/write` | `bindings.zig:52,203,290` | ✅ Returns -2 on poison |
| `Tier0Observer` | `poison.zig:102-203` | ✅ Exists |
| `RecoveryManager` | `poison.zig:280-383` | ✅ Exists |
| `hardwareFaultHandler` | `poison.zig:250-269` | ✅ Exists |
| **`poison.init()` called** | — | ❌ Never |
| **`global_recovery_manager` assigned** | — | ❌ Never |
| **`Tier0Observer` instantiated** | — | ❌ Never |
| **`RecoveryManager` instantiated** | — | ❌ Never |

## Activation Steps

### Step 1: Call `poison.init()` at Startup

In `src/wpe_glue/init.rs`, inside `Zawra_Init_Subsystems()`:

```rust
extern "C" {
    fn hajr_poison_init();
}

// After Hajr ring setup:
unsafe { hajr_poison_init(); }
```

This registers the `hardwareFaultHandler` with the exception module. When a SIGSEGV/SIGBUS occurs in a sandbox's ring memory, the handler will poison the ring instead of crashing the process.

### Step 2: Create `Tier0Observer`

In `ConnectionUnix.cpp` or a new initialization file:

```cpp
// C FFI declarations (add to bindings or header):
extern "C" void* hajr_poison_create_observer(uint64_t poll_interval_ns, bool kill_on_poison);
extern "C" void hajr_poison_register_ring(void* observer, void* ring_metadata, void* ring_base, 
                                           uint64_t ring_size, uint64_t sandbox_id, uint32_t protection_key);
extern "C" void hajr_poison_check_all(void* observer, void (*callback)(uint64_t sandbox_id, uint32_t cause));
```

Create observer during UI process initialization:
```cpp
static void* g_poison_observer = nullptr;

void initPoisonObserver() {
    g_poison_observer = hajr_poison_create_observer(
        100_000_000,  // 100ms poll interval
        true          // kill on poison
    );
}
```

### Step 3: Register Rings After Connection Setup

In `ConnectionUnix.cpp::platformOpen()`, after mapping the rings:

```cpp
if (m_isHajrEnabled && m_inboundRing) {
    hajr_poison_register_ring(
        g_poison_observer,
        m_inboundRing->metadata_ptr,
        m_inboundRing->data_ptr,
        m_inboundRing->size,
        connectionId,  // unique ID for this connection
        m_inboundRing->key_val
    );
}
```

### Step 4: Add Periodic Poison Check to Event Loop

Option A: Use a GLib timer source:

```cpp
static gboolean poisonCheckCallback(gpointer data) {
    if (g_poison_observer) {
        hajr_poison_check_all(g_poison_observer, onPoisonDetected);
    }
    return G_SOURCE_CONTINUE;  // Keep timer running
}

// In init:
g_timeout_add(100, poisonCheckCallback, nullptr);  // Check every 100ms
```

Option B: Check in `readyReadHandler()` before processing messages.

### Step 5: Implement Poison Recovery Callback

```cpp
static void onPoisonDetected(uint64_t sandbox_id, uint32_t cause) {
    fprintf(stderr, "[HAJR] POISON DETECTED: sandbox=%llu cause=%u\n", sandbox_id, cause);
    
    // 1. Find the connection for this sandbox
    // 2. Close the connection (triggers WebKit process termination)
    // 3. WebKit will respawn the child process on next message
    
    // The child process crash is detected by WebKit's ProcessLauncher
    // and a new process is spawned automatically.
}
```

### Step 6: Create `RecoveryManager` (Optional)

For explicit recovery (kill thread, unmap memory, release keys):

```cpp
extern "C" void* hajr_poison_create_recovery(
    void* observer,
    void (*unmap_fn)(void* base, uint64_t size),
    void (*release_key_fn)(uint32_t key),
    uint64_t (*create_sandbox_fn)()
);

// Initialize with callbacks that match your process model:
void* recovery = hajr_poison_create_recovery(
    g_poison_observer,
    [](void* base, uint64_t size) { munmap(base, size); },
    [](uint32_t key) { pkey_free(key); },
    []() -> uint64_t { return launchNewWebProcess(); }
);
```

## What Each Poison Cause Means

| Cause | Value | Meaning |
|-------|-------|---------|
| `sequence_anomaly` | 1 | Read/write index doesn't match expected sequence |
| `out_of_bounds` | 2 | SIGSEGV/SIGBUS accessing ring memory |
| `unauthorized_write` | 3 | Write attempted to read-only ring |
| `jit_escape` | 4 | JIT code attempted to write to ring |
| `external_buffer_overflow` | 5 | JSC external ArrayBuffer exceeded bounds |
| `ring_corruption` | 6 | Checksum or metadata validation failed |
| `thread_died` | 7 | Sandbox thread terminated unexpectedly |
| `timeout` | 8 | No response within expected timeframe |

## Security Value

Without poison detection:
```
Compromised renderer → corrupts ring metadata → UI processes forged message → sandbox escape
```

With poison detection:
```
Compromised renderer → corrupts ring → poison bit set → ring unusable → renderer crashes
```

This is the **crash-only** philosophy: a compromised renderer should crash immediately, not silently corrupt the trusted process.
