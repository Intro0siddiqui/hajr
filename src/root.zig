pub const sandbox = @import("core/sandbox.zig");
pub const hw = @import("hw/mod.zig");
pub const ipc = @import("ipc/ipc.zig");
pub const sandbox_rt = struct {
    pub const memory = @import("sandbox/memory.zig");
    pub const router = @import("sandbox/router.zig");
    pub const poison = @import("sandbox/poison.zig");
    pub const system = @import("sandbox/system.zig");
};
pub const bindings = @import("sandbox/bindings.zig");

test {
    _ = @import("sandbox/system.zig");
    _ = @import("ipc/ipc.zig");
    @import("std").testing.refAllDecls(@This());
}
