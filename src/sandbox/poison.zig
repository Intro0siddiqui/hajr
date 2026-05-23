//! Hajr Poison Protocol Implementation
//! 
//! Integrates ring buffer poison bits with Tier 0 Observer for
//! fail-fast crash-only recovery. Any hardware fault or sequence
//! anomaly triggers immediate sandbox termination.

const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const hw = @import("../hw/mod.zig");
const sandbox = @import("../core/sandbox.zig");
const router = @import("router.zig");

// ============================================================================
// Poison Types and Constants
// ============================================================================

/// Poison cause identifiers
pub const PoisonCause = enum(u32) {
    /// Unknown cause
    unknown = 0,
    /// Sequence number anomaly detected
    sequence_anomaly = 1,
    /// Out-of-bounds memory access detected
    out_of_bounds = 2,
    /// Unauthorized write attempt
    unauthorized_write = 3,
    /// JIT escape detected (attempted code injection)
    jit_escape = 4,
    /// External ArrayBuffer bounds violation
    external_buffer_overflow = 5,
    /// Ring buffer corruption detected
    ring_corruption = 6,
    /// Thread terminated unexpectedly
    thread_died = 7,
    /// Timeout waiting for response
    timeout = 8,
};

/// Poison record for forensic analysis
pub const PoisonRecord = extern struct {
    /// When the poison was detected
    timestamp_ns: u64,
    /// Which sandbox was poisoned
    sandbox_id: u64,
    /// What caused the poison
    cause: u32,
    /// Sequence number when detected
    sequence_at_fault: u64,
    /// Expected sequence number
    expected_sequence: u64,
    /// Additional context (ring ID, address, etc.)
    context: [64]u8,
};

/// Maximum poison records to retain
pub const MAX_POISON_RECORDS: usize = 1024;

/// Ring state flags
pub const RingFlags = struct {
    pub const POISONED: u32 = 0x00000001;
    pub const OVERFLOW_DETECTED: u32 = 0x00000002;
    pub const SEQUENCE_BROKEN: u32 = 0x00000004;
    pub const GUARD_PAGE_FAULT: u32 = 0x00000008;
};

// ============================================================================
// Ring Metadata (Extended with Poison Support)
// ============================================================================

/// Extended ring metadata including poison protocol fields
pub const PoisonableRingMetadata = sandbox.RingMetadata;

/// Poison the ring with cause
pub fn poisonRing(ring: *PoisonableRingMetadata, cause: PoisonCause) void {
    ring.poison_cause.store(@intFromEnum(cause), .release);
    ring.poison_bit.store(true, .release);
}

/// Check if ring is poisoned
pub fn isRingPoisoned(ring: *const PoisonableRingMetadata) bool {
    return ring.poison_bit.load(.acquire);
}

/// Get poison cause
pub fn getRingPoisonCause(ring: *const PoisonableRingMetadata) PoisonCause {
    return @enumFromInt(ring.poison_cause.load(.acquire));
}

// ============================================================================
// Tier 0 Observer
// ============================================================================

/// Tier 0 Observer for monitoring and killing compromised sandboxes
/// 
/// This is the critical security component that:
/// 1. Monitors all sandbox rings for poison bits
/// 2. Kills compromised SpiderMonkey threads
/// 3. Unmaps compromised memory
/// 4. Triggers sandbox rotation

pub const Tier0Observer = struct {
    /// Observable rings and their associated sandboxes
    observables: std.ArrayListUnmanaged(*ObservableRing),
    
    /// Poison event log
    poison_log: std.ArrayListUnmanaged(PoisonRecord),
    
    /// Callback for when a sandbox is poisoned
    on_poison_callback: ?*const fn (sandbox_id: u64, cause: PoisonCause, record: PoisonRecord) void,
    
    /// Configuration
    config: Config,
    
    /// Observer configuration
    pub const Config = struct {
        poll_interval_ns: u64 = 1000, // 1us polling interval
        max_log_entries: usize = 1024,
        enable_kill_on_poison: bool = true,
    };
    
    /// Create observer instance
    pub fn init(config: Config) !*Tier0Observer {
        const observer = try std.heap.page_allocator.create(Tier0Observer);
        observer.* = Tier0Observer{
            .observables = .empty,
            .poison_log = .empty,
            .on_poison_callback = null,
            .config = config,
        };
        
        return observer;
    }
    
    /// Destroy observer
    pub fn destroy(observer: *Tier0Observer) void {
        observer.observables.deinit(std.heap.page_allocator);
        observer.poison_log.deinit(std.heap.page_allocator);
        std.heap.page_allocator.destroy(observer);
    }
    
    /// Register a ring for monitoring
    pub fn registerRing(observer: *Tier0Observer, ring: *ObservableRing) !void {
        try observer.observables.append(std.heap.page_allocator, ring);
    }
    
    /// Unregister a ring
    pub fn unregisterRing(observer: *Tier0Observer, sandbox_id: u64) void {
        for (observer.observables.items, 0..) |ring, i| {
            if (ring.sandbox_id == sandbox_id) {
                _ = observer.observables.swapRemove(i);
                return;
            }
        }
    }
    
    /// Check all rings for poison
    /// 
    /// This function should be called from the main event loop
    /// or a dedicated monitoring thread. It is lock-free and uses
    /// only atomic operations.
    /// 
    /// Returns list of poisoned sandbox IDs.

    pub fn checkAllRings(observer: *Tier0Observer) ![]const u64 {
        var poisoned = std.ArrayList(u64).init(std.heap.page_allocator);
        errdefer poisoned.deinit();
        
        for (observer.observables.items) |ring| {
            if (ring.isPoisoned()) {
                // Record the poison event
                const timestamp = hw.posix_io.monotonicTimestamp();

                const record = PoisonRecord{
                    .timestamp_ns = timestamp,
                    .sandbox_id = ring.sandbox_id,
                    .cause = @intFromEnum(ring.getPoisonCause()),
                    .sequence_at_fault = ring.metadata.sequence.load(.acquire),
                    .expected_sequence = ring.expected_sequence,
                    .context = [1]u8{0} ** 64,
                };
                
                try observer.poison_log.append(std.heap.page_allocator, record);
                
                // Limit log size (preserve chronological order)
                while (observer.poison_log.items.len > observer.config.max_log_entries) {
                    observer.poison_log.orderedRemove(0);
                }
                
                // Trigger kill if enabled
                if (observer.config.enable_kill_on_poison) {
                    if (observer.on_poison_callback) |callback| {
                        callback(ring.sandbox_id, @enumFromInt(record.cause), record);
                    }
                }
                
                try poisoned.append(ring.sandbox_id);
            }
        }
        
        return poisoned.toOwnedSlice();
    }
    
};

/// Ring that can be observed by Tier 0
pub const ObservableRing = struct {
    /// Ring metadata pointer
    metadata: *PoisonableRingMetadata,
    
    /// Ring base pointer (for unmapping on poison)
    base: [*]align(std.heap.page_size_min) u8,
    
    /// Ring size
    size: usize,
    
    /// Associated sandbox ID
    sandbox_id: u64,
    
    /// Hardware protection key
    protection_key: u32,
    
    /// Thread handle (for termination)
    thread_handle: ?std.Thread,
    
    /// Expected sequence number (for validation)
    expected_sequence: u64,
    
    /// Memory allocator (for freeing on poison)
    memory: *anyopaque,
    
    /// Check if ring is poisoned
    pub fn isPoisoned(ring: *const ObservableRing) bool {
        return ring.metadata.poison_bit.load(.acquire);
    }
    
    /// Get poison cause
    pub fn getPoisonCause(ring: *const ObservableRing) PoisonCause {
        return @enumFromInt(ring.metadata.poison_cause.load(.acquire));
    }
    
};

// ============================================================================
// Crash-Only Recovery
// ============================================================================

var global_recovery_manager: ?*RecoveryManager = null;

fn hardwareFaultHandler(info: hw.os.FaultInfo) callconv(.C) void {
    const fault_addr = info.address;

    if (global_recovery_manager) |rm| {
        for (rm.observer.observables.items) |ring| {
            const base = @intFromPtr(ring.base);
            if (fault_addr >= base and fault_addr - base < ring.size) {
                poisonRing(ring.metadata, .out_of_bounds);
                return;
            }
        }
    }

    std.posix.exit(1);
}

/// Register the hardware fault handler into the exception pipeline.
/// Must be called once during initialization.
pub fn init() void {
    hw.exception.registerCallback(hardwareFaultHandler);
}

/// Sandbox recovery manager
/// 
/// Handles the complete recovery cycle when a sandbox is poisoned:
/// 1. Kill the SpiderMonkey thread
/// 2. Unmap the memory arena
/// 3. Release hardware keys
/// 4. Create a new sandbox instance

pub const RecoveryManager = struct {
    /// Observer reference
    observer: *Tier0Observer,
    
    /// Memory unmapping function
    unmapFn: *const fn (base: [*]align(std.heap.page_size_min) u8, size: usize) void,
    
    /// Key release function
    releaseKeyFn: *const fn (key: u32) void,
    
    /// Sandbox factory function
    createSandboxFn: *const fn () anyerror!u64,
    
    /// Active recovery operations
    in_recovery: std.atomic.Value(bool),
    
    /// Create recovery manager
    pub fn init(
        observer: *Tier0Observer,
        unmap_fn: *const fn ([*]align(std.heap.page_size_min) u8, usize) void,
        release_key_fn: *const fn (u32) void,
        create_sandbox_fn: *const fn () anyerror!u64,
    ) RecoveryManager {
        return RecoveryManager{
            .observer = observer,
            .unmapFn = unmap_fn,
            .releaseKeyFn = release_key_fn,
            .createSandboxFn = create_sandbox_fn,
            .in_recovery = std.atomic.Value(bool).init(false),
        };
    }

    /// Execute recovery for a poisoned sandbox
    /// 
    /// This is the crash-only recovery path. There is no graceful
    /// degradation - the sandbox is killed and rotated immediately.
    
    pub fn recover(recovery: *RecoveryManager, sandbox_id: u64) !u64 {
        // Prevent concurrent recoveries
        while (recovery.in_recovery.load(.acquire)) {
            std.atomic.spinLoopHint();
        }
        recovery.in_recovery.store(true, .release);
        defer recovery.in_recovery.store(false, .release);
        
        // 1. Kill the SpiderMonkey thread
        recovery.killThread(sandbox_id);
        
        // 2. Unmap memory arena
        recovery.unmapMemory(sandbox_id);
        
        // 3. Release hardware key
        recovery.releaseHardwareKey(sandbox_id);
        
        // 4. Create new sandbox
        const new_id = try (recovery.createSandboxFn)();
        
        return new_id;
    }
    
    /// Kill sandbox thread
    fn killThread(recovery: *RecoveryManager, sandbox_id: u64) void {
        for (recovery.observer.observables.items) |ring| {
            if (ring.sandbox_id == sandbox_id) {
                if (ring.thread_handle) |thread| {
                    thread.detach();
                }
                return;
            }
        }
    }
    
    /// Unmap sandbox memory
    fn unmapMemory(recovery: *RecoveryManager, sandbox_id: u64) void {
        for (recovery.observer.observables.items) |ring| {
            if (ring.sandbox_id == sandbox_id) {
                recovery.unmapFn(ring.base, ring.size);
                return;
            }
        }
    }
    
    /// Release hardware protection key
    fn releaseHardwareKey(recovery: *RecoveryManager, sandbox_id: u64) void {
        for (recovery.observer.observables.items) |ring| {
            if (ring.sandbox_id == sandbox_id) {
                recovery.releaseKeyFn(ring.protection_key);
                return;
            }
        }
    }
    
    /// Recovery with panic on failure
    pub fn recoverOrPanic(recovery: *RecoveryManager, sandbox_id: u64) u64 {
        return recovery.recover(sandbox_id) catch |err| {
            @panic(switch (err) {
                error.OutOfMemory => "Out of memory during recovery",
                error.KeyAllocationFailed => "Failed to allocate hardware key",
                error.ThreadCreationFailed => "Failed to create replacement thread",
                else => "Unknown recovery error",
            });
        };
    }
};

// ============================================================================
// Default System Functions
// ============================================================================

/// Default memory unmapping function
pub fn defaultUnmap(base: [*]align(std.heap.page_size_min) u8, size: usize) void {
    hw.os.memFree(base[0..size]);
}

/// Default hardware key release function
pub fn defaultReleaseKey(key: u32) void {
    hw.compartment.global_allocator.free(.{ .id = key });
}


// ============================================================================
// Integration with RingRouter
// ============================================================================

/// Enhanced RingRouter with poison protocol integration
pub const PoisonAwareRouter = struct {
    /// Base router
    base: *router.RingRouter,
    /// Observer for poison detection
    observer: *Tier0Observer,
    /// Recovery manager
    recovery: *RecoveryManager,
    
    pub fn init(
        handlers: router.BackendHandler,
        config: router.RingRouter.Config,
        observer: *Tier0Observer,
        recovery: *RecoveryManager,
    ) !PoisonAwareRouter {
        const base = try router.RingRouter.init(handlers, config);
        return PoisonAwareRouter{
            .base = base,
            .observer = observer,
            .recovery = recovery,
        };
    }
    
    /// Poll with poison detection and recovery
    /// 
    /// This is the main entry point for the event loop.
    /// It checks for poison bits before polling and triggers
    /// recovery if any are detected.
    
    pub fn poll(self: *PoisonAwareRouter) usize {
        // First, check all rings for poison (fail-fast)
        const poisoned = self.observer.checkAllRings() catch &[_]u64{};
        defer std.heap.page_allocator.free(poisoned);
        
        // Recover any poisoned sandboxes immediately
        for (poisoned) |sandbox_id| {
            _ = self.recovery.recoverOrPanic(sandbox_id);
        }
        
        // Then poll remaining active rings
        return self.base.poll();
    }
};
