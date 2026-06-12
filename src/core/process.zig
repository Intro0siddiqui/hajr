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

        // Inherit parent's environment so child gets ZAWRA_HAJR_* vars for IPC bootstrap
        const envp: [*:null]?[*:0]const u8 = @ptrCast(std.c.environ);

        // On Linux, we use namespaces and MPK
        const res_fork = std.os.linux.syscall0(.fork);
        if (std.os.linux.errno(res_fork) != .SUCCESS) return error.SpawnFailed;
        const pid = res_fork;
        
        if (pid == 0) {
            // Child process - ONLY ASYNC-SIGNAL-SAFE CODE HERE
            
            // 1. Unshare namespaces for isolation.
            // NOTE: CLONE_NEWUSER is intentionally omitted. Without writing
            // to /proc/self/uid_map, the child's UID becomes `nobody` (65534),
            // which causes bmalloc's scavenger thread creation to fail with
            // EPERM, triggering a SIGILL assertion in pas_scavenger.c. The full
            // Hajr sandbox (hajr_seal_process) will re-enable user namespace
            // isolation with proper UID mapping when allowlist is expanded.
            const flags: u32 = std.os.linux.CLONE.NEWNS | std.os.linux.CLONE.NEWPID;
            const res_unshare = std.os.linux.syscall1(.unshare, flags);
            if (std.os.linux.errno(res_unshare) != .SUCCESS) {
                hw.os.exitProcess(1);
            }

            // 2. Preserve the socket FD (signal1_fd)
            if (out_socket.* != -1) {
                const fd = out_socket.*;
                const res_fcntl = std.os.linux.syscall3(.fcntl, @as(usize, @intCast(fd)), 1, 0); // F_GETFD
                if (std.os.linux.errno(res_fcntl) == .SUCCESS) {
                    const flags_fd: usize = res_fcntl;
                    _ = std.os.linux.syscall3(.fcntl, @as(usize, @intCast(fd)), 2, flags_fd & ~@as(usize, 1)); // F_SETFD, ~FD_CLOEXEC
                }
            }

            // 3. Preserve all Hajr FDs (read from env, remove CLOEXEC so they survive execve)
            //    Ring buffer memfd FDs are created with MFD_CLOEXEC; without removing it,
            //    execve closes them and the child cannot mmap the shared rings.
            //    The parent pidfd also needs CLOEXEC cleared for hajr_ipc_set_other_pidfd.
            const hajr_fd_prefixes = [_]struct{ prefix: []const u8, plen: usize }{
                .{ .prefix = "ZAWRA_HAJR_SIGNAL1=", .plen = 19 },
                .{ .prefix = "ZAWRA_HAJR_SIGNAL2=", .plen = 19 },
                .{ .prefix = "ZAWRA_HAJR_RING1=", .plen = 16 },
                .{ .prefix = "ZAWRA_HAJR_RING2=", .plen = 16 },
                .{ .prefix = "ZAWRA_HAJR_PARENT_PIDFD=", .plen = 24 },
            };
            var i_env: usize = 0;
            while (envp[i_env]) |env_ptr| : (i_env += 1) {
                const entry = std.mem.span(env_ptr);
                for (hajr_fd_prefixes) |p| {
                    if (entry.len > p.plen and std.mem.eql(u8, entry[0..p.plen], p.prefix)) {
                        const fd_val = std.fmt.parseInt(i32, entry[p.plen..], 10) catch break;
                        if (fd_val != -1) {
                            const res_fcntl2 = std.os.linux.syscall3(.fcntl, @as(usize, @intCast(fd_val)), 1, 0); // F_GETFD
                            if (std.os.linux.errno(res_fcntl2) == .SUCCESS) {
                                const flags_fd2: usize = res_fcntl2;
                                _ = std.os.linux.syscall3(.fcntl, @as(usize, @intCast(fd_val)), 2, flags_fd2 & ~@as(usize, 1)); // F_SETFD, ~FD_CLOEXEC
                            }
                        }
                        break;
                    }
                }
            }

            // 4. Exec the process (with inherited environment)
            _ = std.os.linux.syscall3(.execve, @intFromPtr(path_z.ptr), @intFromPtr(c_argv.ptr), @intFromPtr(envp));
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
