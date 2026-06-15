# PAC Implementation Plan for Hajr HAL

## Context

MPK (Intel x86_64) and MTE (ARM AArch64 Linux) are fully implemented in the HAL. PAC (Pointer Authentication Codes) is the remaining ARM hardware security primitive. A comprehensive design doc exists at `docs/PAC_ARM_ARCHITECTURE.md`. This plan covers the implementation.

PAC protects pointer integrity (return addresses, function pointers, data pointers) via cryptographic MACs stored in unused upper pointer bits. It is complementary to MTE — MTE protects memory regions, PAC protects pointers.

## Files to Create

### 1. `src/hw/pac.zig` — Core PAC instruction wrappers

Zig inline assembly for all PAC instructions, following the same comptime dispatch pattern as `mod.zig`.

**API:**
```zig
pub const PacKey = enum { ia, ib, da, db, ga };

// LR signing (most common use case — compiler-inserted for return address protection)
pub fn signLR() void;          // PACIASP
pub fn authLR() void;          // AUTIASP

// Generic pointer signing with modifier
pub fn sign(ptr: usize, modifier: usize, key: PacKey) usize;
pub fn auth(ptr: usize, modifier: usize, key: PacKey) error{AuthFailed}!usize;

// Data pointer variants
pub fn signData(ptr: usize, modifier: usize, key: PacKey) usize;
pub fn authData(ptr: usize, modifier: usize, key: PacKey) error{AuthFailed}!usize;

// Strip PAC bits (for pointer comparison/logging)
pub fn stripInstruction(ptr: usize) usize;  // XPACI
pub fn stripData(ptr: usize) usize;         // XPACD

// Feature detection
pub fn hasPacAddressAuth() bool;  // Linux: getauxval(HWCAP) & HWCAP_PACA
pub fn hasPacGenericAuth() bool;  // Linux: getauxval(HWCAP) & HWCAP_PACG
pub fn isSupported() bool;        // Combined check

// Key management (Linux only)
pub fn resetKeys() ResetError!void;  // prctl(PR_PAC_RESET_KEYS, ...)
```

**Platform behavior:**
- `AArch64_Linux`: Full implementation via inline asm + syscalls (prctl, getauxval)
- `AArch64_Portable` (macOS): Instructions work (arm64e ABI), detection returns `true`, key management is no-op (kernel-managed)
- `X86_64_*` and `Fallback`: All functions are no-ops that return safe defaults

## Files to Modify

### 2. `src/hw/mod.zig` — Add PAC public API

- Import `pac.zig` (conditionally, same pattern as `pointer`, `compartment`, `exception`)
- Export facade functions that dispatch to `pac.signLR()`, `pac.authLR()`, etc.
- The existing `writeProtectionKey`/`readProtectionKey`/`setKeyPermission`/`applyProtectionToRegion` API stays unchanged (MPK/MTE domain)

### 3. `src/hw/pointer.zig` — Add PAC-signed pointer variant

Extend `TaggedPointer(T)` or add a new `PacSignedPointer(T)` type:
- On `aarch64`: stores PAC signature in upper bits [63:60] (without MTE) or [63:60] (with MTE using [59:56])
- Provides `sign()`, `auth()`, `verify()` methods
- Uses the `pac.sign`/`pac.auth` primitives from `pac.zig`

### 4. `src/hw/compartment.zig` — PAC feature detection

Add `detectPac()` method to `CompartmentAllocator`:
- On `aarch64_linux`: check `HWCAP_PACA` via `getauxval`
- On `aarch64_macos`: always return true (Apple Silicon)
- Cache result like `detectMpk()` does

### 5. `src/hw/exception.zig` — PAC fault detection

Extend `extractFaultType()` to detect PAC authentication failures:
- Linux: `SEGV_ACCADI` (0x06) — Authentication Data Instruction fault
- Add `is_pac_fault: bool` to `FaultInfo` (or handle in callback)

### 6. `src/hw/os_abstraction.zig` — PAC syscalls

Add Linux-specific helpers:
- `getHwcap() u32` — reads `AT_HWCAP` from auxiliary vector
- `prctlPacResetKeys(mask: u32) PrctlError!void` — wraps `prctl(PR_PAC_RESET_KEYS, ...)`

### 7. `src/core/sandbox.zig` — Add `arm_pac` mechanism

Extend `HardwareProtection.Mechanism`:
```zig
pub const Mechanism = enum {
    intel_mpk,
    arm_mte,
    arm_pac,          // NEW: PAC only (macOS arm64e, Linux with HWCAP_PACA)
    arm_pac_mte,      // Future: ARMv9 with both
    software_fallback,
};
```

Update `detect()` to check PAC availability on aarch64.

### 8. `build.zig` — No changes needed

PAC instructions are implemented via Zig inline assembly (no separate .s file). The existing build system handles aarch64 targets correctly. The `pkru.c` conditional linking pattern is not needed for PAC since Zig inline asm is self-contained.

## Implementation Order

1. `src/hw/os_abstraction.zig` — Add `getHwcap()` and `prctlPacResetKeys()`
2. `src/hw/pac.zig` — New file with all PAC instruction wrappers
3. `src/hw/mod.zig` — Import pac.zig and add facade exports
4. `src/hw/compartment.zig` — Add `detectPac()` method
5. `src/hw/exception.zig` — Add PAC fault detection
6. `src/hw/pointer.zig` — Add `PacSignedPointer(T)`
7. `src/core/sandbox.zig` — Add `arm_pac` variant to Mechanism enum

## Open Questions

1. **MTE+PAC bit layout coordination**: On future ARMv9 with both, MTE uses [59:56] and PAC uses [63:60] (4-bit). For now, this is a future concern — current ARM Linux devices have either MTE or PAC, not both.

2. **macOS arm64e compilation**: The default `aarch64` target with `-mbranch-protection=pac-ret` is sufficient for return address protection. Full arm64e ABI is only needed if we want to PAC-sign all data pointers. For now, we target the standard arm64 + branch protection.

3. **Key rotation**: Per-exec randomization (kernel default) is sufficient. `resetKeys()` is exposed for optional periodic rotation but not called by default.

## CI Workflow Changes (`ci.yml`)

**Status:** `macos-latest` is already Apple Silicon (M1, ARM64). PAC works out of the box on macOS CI.

**Only change needed:** Add an `aarch64-linux-gnu` cross-compile job to verify PAC inline asm compiles on Linux ARM too.

### Add cross-compilation job:
```yaml
  cross-aarch64-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mlugg/setup-zig@v2
        with:
          version: 0.16.0
      - name: Build for aarch64-linux
        run: zig build -Dtarget=aarch64-linux-gnu
```

## Git Commit Strategy (Incremental, CI-verified)

Each commit pushes to a feature branch. CI must pass before next commit.

| Step | Commit Message | Files | CI Check |
|------|---------------|-------|----------|
| 0 | `ci(ci): add aarch64-linux cross-compile job` | `.github/workflows/ci.yml` | Green on all + cross-compile |
| 1 | `feat(hw): add getauxval and prctl wrappers for PAC detection` | `src/hw/os_abstraction.zig` | Green on all platforms |
| 2 | `feat(hw): implement PAC instruction wrappers and feature detection` | `src/hw/pac.zig` (new) | Green on all platforms |
| 3 | `feat(hw): add PAC facade exports to hw module` | `src/hw/mod.zig` | Green on all platforms |
| 4 | `feat(hw): add PAC detection to CompartmentAllocator` | `src/hw/compartment.zig` | Green on all platforms |
| 5 | `feat(hw): add PAC authentication fault detection` | `src/hw/exception.zig` | Green on all platforms |
| 6 | `feat(hw): add PacSignedPointer type` | `src/hw/pointer.zig` | Green on all platforms |
| 7 | `feat(sandbox): add arm_pac mechanism variant` | `src/core/sandbox.zig` | Green on all platforms |

**Branch:** `feat/pac-implementation`

**Rule:** Never proceed to step N+1 if step N CI is red.

## Verification

1. Build: `zig build` on x86_64 (should compile with no-ops for PAC)
2. Build: `zig build -Dtarget=aarch64-linux-gnu` (cross-compile, verifies inline asm)
3. CI: macos-14 and/or macos-15 runner must pass (real Apple Silicon)
4. Tests: `zig build test` — existing tests must pass unchanged
5. Manual: On ARM hardware, verify `pac.isSupported()` returns true
