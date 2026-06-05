const std = @import("std");
const builtin = @import("builtin");
const hw = @import("../hw/mod.zig");
const posix = std.posix;

pub const SpawnError = error{
    SpawnFailed,
    MemoryAllocationFailed,
    NamespaceFailed,
    PkeyFailed,
};

pub fn spawnCompartment(
    allocator: std.mem.Allocator,
    path: []const u8,
    argv: []const []const u8,
    out_socket: *i32,
) !u32 {
    if (comptime builtin.os.tag == .linux) {
        // On Linux, we use namespaces and MPK
        // We use fork/exec to have full control over the child state
        const res_fork = std.os.linux.syscall0(.fork);
        if (std.os.linux.errno(res_fork) != .SUCCESS) return error.SpawnFailed;
        const pid = res_fork;
        
        if (pid == 0) {
            // Child process
            
            // 1. Unshare namespaces for isolation
            // CLONE_NEWNS (mount), CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET (if needed)
            const flags: u32 = std.os.linux.CLONE.NEWNS | std.os.linux.CLONE.NEWPID | std.os.linux.CLONE.NEWUSER;
            const res = std.os.linux.syscall1(.unshare, flags);
            if (std.os.linux.errno(res) != .SUCCESS) {
                hw.os.exitProcess(1);
            }

            // 2. Allocate MPK key
            const pkey = hw.os.pkeyAlloc(0, 0) catch -1;
            
            // 3. Preserve the socket FD
            if (out_socket.* != -1) {
                const fd = out_socket.*;
                // Use raw syscall for fcntl if posix.fcntl is missing
                const res_fcntl = std.os.linux.syscall3(.fcntl, @as(usize, @intCast(fd)), 1, 0); // F_GETFD = 1
                if (std.os.linux.errno(res_fcntl) == .SUCCESS) {
                    const flags_fd: usize = res_fcntl;
                    _ = std.os.linux.syscall3(.fcntl, @as(usize, @intCast(fd)), 2, flags_fd & ~@as(usize, 1)); // F_SETFD = 2, FD_CLOEXEC = 1
                }
            }

            // 4. Prepare environment and exec the process
            var env_list: std.ArrayListUnmanaged(?[*:0]const u8) = .empty;
            if (pkey != -1) {
                var env_buf: [32]u8 = undefined;
                const env_str = std.fmt.bufPrint(&env_buf, "ZAWRA_HAJR_PKEY={d}", .{pkey}) catch "ZAWRA_HAJR_PKEY=-1";
                const env_entry = (try allocator.dupeZ(u8, env_str)).ptr;
                try env_list.append(allocator, env_entry);
            }
            
            // Add other essential env vars if needed, or inherit from parent
            try env_list.append(allocator, null);

            // Convert argv to null-terminated list of C strings
            var c_argv = try allocator.alloc(?[*:0]const u8, argv.len + 1);
            for (argv, 0..) |arg, i| {
                c_argv[i] = (try allocator.dupeZ(u8, arg)).ptr;
            }
            c_argv[argv.len] = null;

            _ = std.os.linux.syscall3(.execve, @intFromPtr(path.ptr), @intFromPtr(c_argv.ptr), @intFromPtr(env_list.items.ptr));
            hw.os.exitProcess(1);
        } else {
            // Parent process
            const child_pid: u32 = @intCast(pid);
            
            // Get a pidfd for the child to allow FD brokering
            const pidfd_res = std.os.linux.syscall2(.pidfd_open, child_pid, 0);
            if (std.os.linux.errno(pidfd_res) == .SUCCESS) {
                const pidfd: i32 = @intCast(pidfd_res);
                // Store this pidfd somewhere globally or in the ring structure
                // For now, we'll use a global map in bindings.zig
                _ = pidfd;
            }
            
            return child_pid;
        }
    } else {
        // Fallback for other OSs (like macOS)
        var child = std.ChildProcess.init(argv, allocator);
        child.executable_path = path;
        try child.spawn();
        return @intCast(child.id);
    }
}
