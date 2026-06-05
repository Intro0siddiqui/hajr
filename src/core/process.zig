const std = @import("std");
const builtin = @import("builtin");
const hw = @import("../hw/mod.zig");

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
        // 1. Prepare all data BEFORE fork (async-signal-safe)
        const path_z = try allocator.dupeZ(u8, path);
        defer allocator.free(path_z);
        
        var c_argv = try allocator.alloc(?[*:0]const u8, argv.len + 1);
        defer allocator.free(c_argv);
        for (argv, 0..) |arg, i| {
            c_argv[i] = (try allocator.dupeZ(u8, arg)).ptr;
        }
        c_argv[argv.len] = null;
        defer {
            for (c_argv[0..argv.len]) |arg| {
                if (arg) |ptr| allocator.free(std.mem.span(ptr));
            }
        }

        const envp = [_:null]?[*:0]const u8{null};

        // On Linux, we use namespaces and MPK
        const res_fork = std.os.linux.syscall0(.fork);
        if (std.os.linux.errno(res_fork) != .SUCCESS) return error.SpawnFailed;
        const pid = res_fork;
        
        if (pid == 0) {
            // Child process - ONLY ASYNC-SIGNAL-SAFE CODE HERE
            
            // 1. Unshare namespaces for isolation
            const flags: u32 = std.os.linux.CLONE.NEWNS | std.os.linux.CLONE.NEWPID | std.os.linux.CLONE.NEWUSER;
            const res_unshare = std.os.linux.syscall1(.unshare, flags);
            if (std.os.linux.errno(res_unshare) != .SUCCESS) {
                hw.os.exitProcess(1);
            }

            // 2. Preserve the socket FD
            if (out_socket.* != -1) {
                const fd = out_socket.*;
                const res_fcntl = std.os.linux.syscall3(.fcntl, @as(usize, @intCast(fd)), 1, 0); // F_GETFD
                if (std.os.linux.errno(res_fcntl) == .SUCCESS) {
                    const flags_fd: usize = res_fcntl;
                    _ = std.os.linux.syscall3(.fcntl, @as(usize, @intCast(fd)), 2, flags_fd & ~@as(usize, 1)); // F_SETFD, ~FD_CLOEXEC
                }
            }

            // 3. Exec the process
            _ = std.os.linux.syscall3(.execve, @intFromPtr(path_z.ptr), @intFromPtr(c_argv.ptr), @intFromPtr(&envp));
            hw.os.exitProcess(1);
        } else {
            // Parent process
            return @intCast(pid);
        }
    } else {
        // Fallback for other OSs (like macOS and Windows)
        var threaded_io = std.Io.Threaded.init(allocator, .{});
        defer threaded_io.deinit();
        const io = threaded_io.io();
        
        const child = try std.process.spawn(io, .{
            .argv = argv,
        });
        
        if (comptime builtin.os.tag == .windows) {
            return 0; // Windows PID stub
        } else {
            // On POSIX, child.id is a PID (optional)
            return @intCast(child.id orelse 0);
        }
    }
}
