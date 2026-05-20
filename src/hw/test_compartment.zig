const std = @import("std");
const compartment = @import("compartment.zig");
const builtin = @import("builtin");

test "CompartmentAllocator basic allocation" {
    var allocator = compartment.CompartmentAllocator.init();
    
    // Test multiple allocations
    const t1 = try allocator.alloc();
    const t2 = try allocator.alloc();
    
    try std.testing.expect(t1.id != t2.id);
    
    allocator.free(t1);
    allocator.free(t2);
}

test "CompartmentAllocator exhaustion" {
    // This test is most predictable on non-x86_64-linux where we use the 16-key limit
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .linux) {
        var allocator = compartment.CompartmentAllocator.init();
        var tokens: [16]compartment.CompartmentToken = undefined;
        
        for (0..16) |i| {
            tokens[i] = try allocator.alloc();
        }
        
        const res = allocator.alloc();
        try std.testing.expectError(error.NoAvailableTags, res); // or NoAvailableKeys
        
        for (0..16) |i| {
            allocator.free(tokens[i]);
        }
        
        // Should be able to allocate again
        const t = try allocator.alloc();
        allocator.free(t);
    }
}
