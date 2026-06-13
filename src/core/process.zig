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
            
            // 1. Create user namespace (always succeeds for unprivileged users)
            const user_ns_flags: u32 = std.os.linux.CLONE.NEWUSER;
            const res_userns = std.os.linux.syscall1(.unshare, user_ns_flags);
            if (std.os.linux.errno(res_userns) != .SUCCESS) {
                const err_msg = "[HAJR-CHILD] WARNING: CLONE_NEWUSER failed, trying fallback without user namespace...\n";
                _ = std.os.linux.syscall3(.write, 2, @intFromPtr(err_msg.ptr), err_msg.len);
                // Fallback: try without user namespace (requires root)
                const fallback_flags: u32 = std.os.linux.CLONE.NEWNS | std.os.linux.CLONE.NEWPID;
                const res_fallback = std.os.linux.syscall1(.unshare, fallback_flags);
                if (std.os.linux.errno(res_fallback) != .SUCCESS) {
                    const err_msg2 = "[HAJR-CHILD] FATAL: unshare failed (need root or user namespaces)\n";
                    _ = std.os.linux.syscall3(.write, 2, @intFromPtr(err_msg2.ptr), err_msg2.len);
                    hw.os.exitProcess(1);
                }
            } else {
                // Write /proc/self/setgroups "deny" (required before gid_map)
                const fd_sg = std.os.linux.syscall4(.openat, @as(usize, @bitCast(@as(isize, -100))), @intFromPtr("/proc/self/setgroups"), @as(usize, 1), 0); // AT_FDCWD, O_WRONLY
                if (@as(isize, @bitCast(fd_sg)) >= 0) {
                    const deny = "deny\n";
                    const written = std.os.linux.syscall3(.write, fd_sg, @intFromPtr(deny.ptr), deny.len);
                    if (@as(isize, @bitCast(written)) != deny.len) {
                        const err_msg = "[HAJR-CHILD] WARNING: failed to write setgroups, continuing...\n";
                        _ = std.os.linux.syscall3(.write, 2, @intFromPtr(err_msg.ptr), err_msg.len);
                    }
                    _ = std.os.linux.syscall1(.close, fd_sg);
                } else {
                    // ENOENT is OK for kernels < 3.19, other errors are non-fatal
                    // (setgroups denial is best-effort; gid_map write will catch failures)
                    const err_no = std.os.linux.errno(fd_sg);
                    if (err_no != .NOENT) {
                        const err_msg = "[HAJR-CHILD] WARNING: failed to open setgroups, continuing...\n";
                        _ = std.os.linux.syscall3(.write, 2, @intFromPtr(err_msg.ptr), err_msg.len);
                    }
                }

                // Restore dumpable state so /proc/self/ files are owned by us, not root.
                // Non-dumpable processes have their /proc/self/ files root-owned, causing EPERM on uid_map writes.
                const res_prctl = std.os.linux.syscall2(.prctl, 4, 1); // PR_SET_DUMPABLE = 4, 1 = true
                const prctl_err = std.os.linux.errno(res_prctl);
                if (prctl_err != .SUCCESS) {
                    var buf: [64]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, "[HAJR-CHILD] DIAG: prctl(PR_SET_DUMPABLE) failed, errno={d}\n", .{@intFromEnum(prctl_err)}) catch "prctl failed\n";
                    _ = std.os.linux.syscall3(.write, 2, @intFromPtr(msg.ptr), msg.len);
                }

                // Log UID info for debugging
                const real_uid = std.os.linux.syscall0(.getuid);
                const real_euid = std.os.linux.syscall0(.geteuid);
                {
                    var buf: [96]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, "[HAJR-CHILD] DIAG: uid={d} euid={d}\n", .{ real_uid, real_euid }) catch "uid info\n";
                    _ = std.os.linux.syscall3(.write, 2, @intFromPtr(msg.ptr), msg.len);
                }

                // Map namespace root -> host UID (so child appears as host user, not nobody)
                const fd_uid = std.os.linux.syscall4(.openat, @as(usize, @bitCast(@as(isize, -100))), @intFromPtr("/proc/self/uid_map"), @as(usize, 1), 0); // AT_FDCWD, O_WRONLY
                if (@as(isize, @bitCast(fd_uid)) < 0) {
                    const err_no = std.os.linux.errno(fd_uid);
                    var buf: [96]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, "[HAJR-CHILD] WARNING: failed to open uid_map, errno={d}, continuing...\n", .{@intFromEnum(err_no)}) catch "uid_map open failed\n";
                    _ = std.os.linux.syscall3(.write, 2, @intFromPtr(msg.ptr), msg.len);
                } else {
                    var uid_buf: [32]u8 = undefined;
                    const uid_str = std.fmt.bufPrint(&uid_buf, "0 {d} 1\n", .{real_uid}) catch unreachable;
                    const uid_written = std.os.linux.syscall3(.write, fd_uid, @intFromPtr(uid_str.ptr), uid_str.len);
                    _ = std.os.linux.syscall1(.close, fd_uid);
                    if (@as(isize, @bitCast(uid_written)) != uid_str.len) {
                        const err_no = std.os.linux.errno(uid_written);
                        var buf: [96]u8 = undefined;
                        const msg = std.fmt.bufPrint(&buf, "[HAJR-CHILD] WARNING: failed to write uid_map, errno={d}, continuing...\n", .{@intFromEnum(err_no)}) catch "uid_map write failed\n";
                        _ = std.os.linux.syscall3(.write, 2, @intFromPtr(msg.ptr), msg.len);
                    } else {
                        const ok_msg = "[HAJR-CHILD] DIAG: uid_map write succeeded\n";
                        _ = std.os.linux.syscall3(.write, 2, @intFromPtr(ok_msg.ptr), ok_msg.len);
                    }
                }

                // Map namespace root -> host GID
                const real_gid = std.os.linux.syscall0(.getgid);
                const real_egid = std.os.linux.syscall0(.getegid);
                {
                    var buf: [96]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, "[HAJR-CHILD] DIAG: gid={d} egid={d}\n", .{ real_gid, real_egid }) catch "gid info\n";
                    _ = std.os.linux.syscall3(.write, 2, @intFromPtr(msg.ptr), msg.len);
                }
                const fd_gid = std.os.linux.syscall4(.openat, @as(usize, @bitCast(@as(isize, -100))), @intFromPtr("/proc/self/gid_map"), @as(usize, 1), 0); // AT_FDCWD, O_WRONLY
                if (@as(isize, @bitCast(fd_gid)) < 0) {
                    const err_no = std.os.linux.errno(fd_gid);
                    var buf: [96]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, "[HAJR-CHILD] WARNING: failed to open gid_map, errno={d}, continuing...\n", .{@intFromEnum(err_no)}) catch "gid_map open failed\n";
                    _ = std.os.linux.syscall3(.write, 2, @intFromPtr(msg.ptr), msg.len);
                } else {
                    var gid_buf: [32]u8 = undefined;
                    const gid_str = std.fmt.bufPrint(&gid_buf, "0 {d} 1\n", .{real_gid}) catch unreachable;
                    const gid_written = std.os.linux.syscall3(.write, fd_gid, @intFromPtr(gid_str.ptr), gid_str.len);
                    _ = std.os.linux.syscall1(.close, fd_gid);
                    if (@as(isize, @bitCast(gid_written)) != gid_str.len) {
                        const err_no = std.os.linux.errno(gid_written);
                        var buf: [96]u8 = undefined;
                        const msg = std.fmt.bufPrint(&buf, "[HAJR-CHILD] WARNING: failed to write gid_map, errno={d}, continuing...\n", .{@intFromEnum(err_no)}) catch "gid_map write failed\n";
                        _ = std.os.linux.syscall3(.write, 2, @intFromPtr(msg.ptr), msg.len);
                    } else {
                        const ok_msg2 = "[HAJR-CHILD] DIAG: gid_map write succeeded\n";
                        _ = std.os.linux.syscall3(.write, 2, @intFromPtr(ok_msg2.ptr), ok_msg2.len);
                    }
                }

                // Now create mount and PID namespaces (succeeds because we have CAP_SYS_ADMIN in user ns)
                const ns_flags: u32 = std.os.linux.CLONE.NEWNS | std.os.linux.CLONE.NEWPID;
                const res_ns = std.os.linux.syscall1(.unshare, ns_flags);
                if (std.os.linux.errno(res_ns) != .SUCCESS) {
                    const err_msg = "[HAJR-CHILD] FATAL: unshare(NEWNS|NEWPID) failed\n";
                    _ = std.os.linux.syscall3(.write, 2, @intFromPtr(err_msg.ptr), err_msg.len);
                    hw.os.exitProcess(1);
                }
            }

            // Fork again so the grandchild becomes PID 1 in the new PID namespace.
            // CLONE_NEWPID only takes effect on the next fork/clone, not execve.
            const res_fork2 = std.os.linux.syscall0(.fork);
            if (std.os.linux.errno(res_fork2) != .SUCCESS) {
                const err_msg = "[HAJR-CHILD] FATAL: second fork for PID namespace failed\n";
                _ = std.os.linux.syscall3(.write, 2, @intFromPtr(err_msg.ptr), err_msg.len);
                hw.os.exitProcess(1);
            }
            if (res_fork2 != 0) {
                // Intermediate child: wait for grandchild and exit
                _ = std.os.linux.syscall4(.wait4, res_fork2, 0, 0, 0);
                hw.os.exitProcess(0);
            }
            // Grandchild continues here as PID 1 in new PID namespace

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
