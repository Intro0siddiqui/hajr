pub const sandbox = @import("core/sandbox.zig");
pub const hw = @import("hw/mod.zig");
pub const ipc = @import("ipc/ipc.zig");
pub const network = @import("network/netstack.zig");
pub const storage = @import("storage/storage.zig");
pub const hajr = struct {
    pub const memory = @import("hajr/memory.zig");
    pub const sm_bindings = @import("hajr/sm_bindings.zig");
    pub const router = @import("hajr/router.zig");
    pub const poison = @import("hajr/poison.zig");
    pub const phase2 = @import("hajr/phase2.zig");
    pub const protection = @import("hajr/protection.zig");
};

test {
    _ = @import("hajr/phase2.zig");
    _ = @import("ipc/ipc.zig");
    _ = @import("network/netstack.zig");
    _ = @import("storage/storage.zig");
    @import("std").testing.refAllDecls(@This());
}
