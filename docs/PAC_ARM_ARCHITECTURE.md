# PAC & ARM Hardware Security Architecture for Hajr

## Overview

This document covers the integration plan for ARM64 Pointer Authentication (PAC) and
Memory Tagging Extension (MTE) into Hajr's Hardware Abstraction Layer (HAL), alongside
the existing Intel MPK support.

## Hardware Security Mechanisms by Platform

| Platform | Mechanism | Purpose | Hajr Status |
|----------|-----------|---------|-------------|
| Intel x86_64 | **MPK** (Memory Protection Keys) | Memory domain isolation | Working (`hw/mod.zig`) |
| ARM Linux (Snapdragon, etc.) | **MTE** (Memory Tagging Extension) | Memory safety (use-after-free, buffer overflow) | Working (`hw/mod.zig:144-197`) |
| Apple Silicon (M2/M3/M4) | **PAC** (Pointer Authentication) | Control flow integrity + pointer integrity | Not implemented |

### Key Insight: Complementary, Not Competing

- **MPK/MTE** = memory access control (which pages can this domain touch?)
- **PAC** = pointer integrity (are these pointers/authentic return addresses forged?)

A hardened system uses both on their respective platforms.

---

## PAC (Pointer Authentication) — ARMv8.3-A

### What PAC Protects

PAC computes a cryptographic MAC over a pointer value and stores it in the unused
upper bits of the pointer. On dereference, the MAC is recomputed and compared — if
it doesn't match, the pointer is poisoned and the process crashes.

**Protected targets:**
- Return addresses (X30/LR) via `PACIASP`/`AUTIASP`
- Function pointers via `PACIA`/`AUTIA`
- C++ vtable entries (signed with IA key + address diversity)
- Data pointers via `PACDA`/`AUTDA`

### PAC Instructions

| Category | Instructions | Key | Purpose |
|----------|-------------|-----|---------|
| **Sign** | `PACIA Xd, Xn\|SP` | IA | Sign instruction pointer |
| | `PACIB Xd, Xn\|SP` | IB | Sign with key B |
| | `PACDA Xd, Xn\|SP` | DA | Sign data pointer |
| | `PACIASP` | IA | Sign X30 (LR) with SP — most common |
| **Auth** | `AUTIA Xd, Xn\|SP` | IA | Authenticate + strip |
| | `AUTIB Xd, Xn\|SP` | IB | Authenticate with key B |
| | `AUTDA Xd, Xn\|SP` | DA | Authenticate data pointer |
| | `AUTIASP` | IA | Auth X30 with SP |
| **Combined** | `BRAA Xn, Xm\|SP` | IA | Auth + branch |
| | `BLRAA Xn, Xm\|SP` | IA | Auth + branch with link |
| | `RETA` | IA | Authenticated return |
| **Strip** | `XPACI Xd` | — | Strip PAC from instruction ptr |
| | `XPACD Xd` | — | Strip PAC from data ptr |

### PAC Key Registers

ARM64 has 5 hardware key registers (128-bit each):

| Register | Name | Primary Use |
|----------|------|-------------|
| APIAKey | Instruction A | Return addresses, function pointers |
| APIBKey | Instruction B | Alternate instruction auth |
| APDAKey | Data A | Data pointer authentication |
| APDBKey | Data B | Alternate data auth |
| APGAKey | Generic | PACGA instruction (32-bit hash) |

---

## Linux vs macOS PAC Differences

| Aspect | Linux | macOS (arm64e) |
|--------|-------|----------------|
| **Key management** | Kernel sets random keys at `exec()` | Kernel + EL3 + custom ISA extension |
| **Key accessibility** | Kernel can read/write key registers | Keys inaccessible even from kernel |
| **Cipher** | QARMA5 (ARM standard) | Implementation-defined (Apple private) |
| **Keys used** | IA, IB, DA, DB, GA (all 5) | IA, IB, DA (main 3) |
| **A-key behavior** | Random per-process | Static across processes (for shared cache) |
| **B-key behavior** | Random per-process | Random per-process |
| **EL0→EL1 transition** | Only IA key changes | All keys change (via KERNKey) |
| **Protection scope** | `-mbranch-protection=pac-ret` (return addrs only) | Full ABI: all pointers |
| **ABI** | Compatible with non-PAC code | New arm64e ABI (incompatible with arm64) |
| **Kernel trust** | Kernel is fully trusted | Kernel NOT trusted (hardware enforced) |

### Key Apple Silicon Detail: KERNKey

Apple added a hardware "KERNKey" that automatically XORs into the signing key based
on exception level. This means:
- Same IA key register value produces different PACs in user vs kernel mode
- No explicit key reprogramming needed on EL0↔EL1 transitions
- Even a compromised kernel cannot disable PAC

---

## MTE (Memory Tagging Extension) — ARMv8.5-A

### What MTE Protects

MTE assigns a 4-bit tag to every 16-byte memory granule and embeds the matching tag
in the top byte of pointers (bits 59:56). On access, if the pointer tag doesn't match
the granule tag, a synchronous or asynchronous SIGSEGV fires.

**Protected against:**
- Use-after-free (dangling pointer has old tag, new allocation has new tag)
- Buffer overflow (writing past granule boundary changes adjacent granule's tag)
- Stack buffer overflows (stack granules get unique tags)

### Current Hajr MTE Implementation

In `hw/mod.zig`, the `AArch64_Linux` variant:

```zig
// TCO (Tag Check Override) register — globally disable/enable MTE checks
pub fn writeProtectionKey(value: u32) void {
    asm volatile ("msr tco, %[val]" ...);
}

// Apply MTE tag to memory granules via STG instruction
pub fn applyProtectionToRegion(ptr: [*]u8, len: usize, key: u32) !void {
    // Iterates 16-byte granules, setting tags in bits [59:56]
    while (addr < end_addr) {
        const tagged_addr = (addr & 0x00FFFFFFFFFFFFFF) | tag;
        asm volatile ("stg %[addr], [%[addr]]" ...);
        addr += 16;
    }
}
```

### MTE vs PAC — Different Mechanisms

| Feature | PAC | MTE |
|---------|-----|-----|
| Architecture | ARMv8.3-A | ARMv8.5-A |
| Purpose | Control-flow integrity | Memory safety |
| Mechanism | Cryptographic MAC in upper pointer bits | 4-bit tag per 16-byte granule |
| Protects | Code pointers + data pointers | All memory accesses |
| Error detection | Pointer poisoned → crash on dereference | Tag mismatch → SIGSEGV |
| Keys | 5 hardware keys (128-bit) | No keys — metadata per granule |
| Overhead | ~1-2 CPU cycles per instruction | 3-5% RAM, low CPU |
| Apple Silicon | Supported (M1+) | **Not supported** on M1/M2/M3 |
| Coexistence | MTE uses bits [59:56], PAC uses nearby bits | Combined scheme needs careful bit layout |

---

## PAC vs MPK Comparison

| Aspect | Intel MPK | ARM PAC |
|--------|-----------|---------|
| **Mechanism** | Per-page protection keys (pkey_alloc) | Cryptographic pointer signing |
| **Granularity** | Page-level (4KB regions) | Per-pointer |
| **Enforcement** | MMU (memory protection) | CPU (pointer authentication) |
| **Key count** | 16 protection keys | 5 PAC keys (128-bit each) |
| **Switching cost** | WRPKRU instruction (~20 cycles) | PAC/AUT instructions (~1-2 cycles) |
| **What it protects** | Memory regions (read/write/execute) | Pointers (integrity) |
| **Threat model** | Cross-compartment memory access | ROP/JOP/code reuse attacks |
| **Apple Silicon** | Not available | Native |

**PAC cannot directly replace MPK** because:
1. PAC authenticates pointers, not memory regions
2. PAC has limited keys (can't create per-compartment keys easily)
3. PAC is CFI-oriented, not memory-access-control-oriented

**Best practice:** Use both — MPK for memory domains on Intel, PAC for pointer
integrity on ARM.

---

## PAC Pointer Layout

```
ARM64 pointer bits (with MTE + PAC):
  [63:60] — PAC signature (upper 4 bits of 64-bit PAC output)
  [59:56] — MTE tag (4-bit tag per 16-byte granule)
  [55:0]  — actual virtual address

ARM64 pointer bits (PAC only, no MTE — Apple Silicon):
  [63:56] — PAC signature (full 8 bits available)
  [55:0]  — actual virtual address
```

On Apple Silicon (no MTE), PAC gets the full upper byte for signatures.
On standard ARM Linux with both, the bit layout needs careful coordination.

---

## Linux Kernel PAC Support

Linux fully supports user-space PAC since kernel 5.0:

### Key Management
- Kernel assigns random keys to each process at `exec()` time (all 5 keys)
- Keys shared by all threads within a process
- Keys preserved across `fork()`, reset on `exec()`
- Keys stored in EL1 system registers — inaccessible from EL0

### prctl API

```c
#include <sys/prctl.h>

// Reset PAC keys to fresh random values
prctl(PR_PAC_RESET_KEYS,
      PR_PAC_APIAKEY | PR_PAC_APIBKEY | PR_PAC_APDAKEY | PR_PAC_APDBKEY,
      0L, 0L, 0L);

// Control which keys are enabled/disabled per-task
prctl(PR_PAC_SET_ENABLED_KEYS,
      PR_PAC_APIAKEY | PR_PAC_APIBKEY,  // which keys
      PR_PAC_APIBKEY,                      // enable mask
      0L, 0L);

// Query which keys are enabled
long enabled = prctl(PR_PAC_GET_ENABLED_KEYS, 0L, 0L, 0L, 0L);
```

### HWCAP Detection

```c
#include <sys/auxv.h>

if (getauxval(AT_HWCAP) & HWCAP_PACA) { /* address auth supported */ }
if (getauxval(AT_HWCAP) & HWCAP_PACG) { /* generic auth supported */ }
```

---

## Integration Plan for Hajr HAL

### Phase 3 Scope

1. **New file: `hw/pac.zig`** — PAC instruction wrappers via Zig inline assembly
2. **Extend `hw/pointer.zig`** — PAC-signed pointer support on arm64e
3. **Extend `hw/compartment.zig`** — PAC key detection alongside MPK/MTE
4. **Extend `hw/exception.zig`** — PAC fault detection (SEGV_ACCADI, etc.)
5. **New file: `hw/arch/pac_aarch64.s`** — PAC instruction implementations
6. **Extend `build.zig`** — Conditionally link PAC assembly on aarch64
7. **Extend `core/sandbox.zig`** — New `arm_pac` mechanism variant

### Target HAL Interface

```zig
// hw/pac.zig
pub const PacKey = enum { ia, ib, da, db, ga };

pub fn sign(ptr: usize, modifier: usize, key: PacKey) usize;
pub fn auth(ptr: usize, modifier: usize, key: PacKey) error{AuthFailed}!usize;
pub fn signData(ptr: usize, modifier: usize, key: PacKey) usize;
pub fn authData(ptr: usize, modifier: usize, key: PacKey) error{AuthFailed}!usize;

// Runtime detection
pub fn hasPacAddressAuth() bool;  // Linux: getauxval HWCAP_PACA
pub fn hasPacGenericAuth() bool;  // Linux: getauxval HWCAP_PACG
```

### Target Detection Logic

```zig
const ArmSecurityFeature = enum {
    mte,    // Linux on standard ARM (Snapdragon, etc.)
    pac,    // Apple Silicon (macOS arm64e) or Linux with HWCAP_PACA
    pac_mte,// Future: ARMv9 with both
    none,   // Older ARM
};

fn detectArmFeature() ArmSecurityFeature {
    if (comptime builtin.cpu.arch != .aarch64) return .none;
    if (builtin.os.tag == .macos) return .pac;           // Apple Silicon
    if (hasHwcap(HWCAP_PACA)) return .pac;               // Linux with PAC
    if (hasHwcap(HWCAP_MTE)) return .mte;                // Linux with MTE
    return .none;
}
```

### Zig 0.16 Inline Assembly for PAC

```zig
// PACIASP — sign X30 (return address) with SP context
pub fn signLR() void {
    asm volatile ("paciasp"
        :
        :
        : "cc", "x30"
    );
}

// AUTIASP — authenticate X30 with SP context
pub fn authLR() void {
    asm volatile ("autiasp"
        :
        :
        : "cc", "x30"
    );
}

// PACIA — sign data pointer with modifier
pub fn pacia(ptr: u64, modifier: u64) u64 {
    return asm volatile (
        \\pacia %[p], %[m]
        : [p] "={x0}" (ptr),
        : [m] "r" (modifier)
        : "cc"
    );
}

// AUTIA — authenticate data pointer
pub fn autia(ptr: u64, modifier: u64) u64 {
    return asm volatile (
        \\autia %[p], %[m]
        : [p] "={x0}" (ptr),
        : [m] "r" (modifier)
        : "cc"
    );
}
```

### Usage in Sandbox System

- **Return address protection**: Sign LR on function entry, auth on return
  (compiler-inserted via `-mbranch-protection=pac-ret`)
- **IPC ring buffer integrity**: PAC-sign ring buffer metadata pointers
- **Compartment trampolines**: Sign branch targets for cross-compartment calls
- **Data pointer protection**: Sign data pointers at store, verify at load

---

## Open Questions

1. **Bit layout coordination**: On systems with both MTE and PAC (future ARMv9),
   how do we partition the upper pointer bits? MTE needs [59:56], PAC can use
   [63:60] (4-bit) or [63:56] (8-bit without MTE).

2. **macOS arm64e ABI**: Do we need to compile with `-arch arm64e` for full PAC
   support, or is the default arm64 with `-mbranch-protection=pac-ret` sufficient?

3. **Performance benchmarking**: PAC overhead is ~1-2 cycles per instruction, but
   the cumulative effect across millions of function calls needs measurement.

4. **PAC key rotation**: Should we rotate PAC keys periodically (via
   `PR_PAC_RESET_KEYS`) for additional security, or is the per-exec randomization
   sufficient?

5. **Interaction with seccomp/Landlock**: PAC operates at the pointer level, while
   seccomp/Landlock operate at the syscall/filesystem level. They're orthogonal but
   should be documented as a unified defense-in-depth strategy.
