const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .macos) @compileError("seatbelt is macOS-specific");
}

extern "System" fn sandbox_init(
    profile: [*:0]const u8,
    flags: u64,
    errorbuf: ?*?*u8,
) callconv(.c) c_int;

extern "System" fn sandbox_free_error(errorbuf: *u8) callconv(.c) void;

pub const Profile = enum {
    no_internet,
    no_write,
    no_write_except_system,
    web_process,
    network_process,
    gpu_process,
};

pub fn apply(profile: Profile) !void {
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;

    const sbpl = switch (profile) {
        .no_internet => no_internet_profile,
        .no_write => no_write_profile,
        .no_write_except_system => no_write_except_system_profile,
        .web_process => web_process_profile,
        .network_process => network_process_profile,
        .gpu_process => gpu_process_profile,
    };

    try applyCustom(sbpl);
}

pub fn applyCustom(profile_contents: []const u8) !void {
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;

    const null_terminated = try std.heap.page_allocator.dupeZ(u8, profile_contents);
    defer std.heap.page_allocator.free(null_terminated);

    var error_buf: ?*u8 = null;
    const result = sandbox_init(@ptrCast(null_terminated), 3, &error_buf);
    if (result != 0) {
        if (error_buf) |buf| {
            sandbox_free_error(buf);
        }
        return error.SandboxInitFailed;
    }
}

// ============================================================================
// Legacy profiles (backward compat)
// ============================================================================

pub const no_internet_profile =
    "(version 1)\n" ++
    "(deny default)\n" ++
    "(allow sysctl-read)\n" ++
    "(allow mach-lookup (global-name \"com.apple.system.logger\"))\n";

pub const no_write_profile =
    "(version 1)\n" ++
    "(deny default)\n" ++
    "(allow sysctl-read)\n" ++
    "(allow mach-lookup (global-name \"com.apple.system.logger\"))\n" ++
    "(allow file-read-data*\n" ++
    "  (require-all\n" ++
    "    (require-ancestor)\n" ++
    "    (require-not (subpath \"/private/var/db\"))\n" ++
    "  )\n" ++
    ")\n";

pub const no_write_except_system_profile =
    "(version 1)\n" ++
    "(deny default)\n" ++
    "(allow sysctl-read)\n" ++
    "(allow mach-lookup (global-name \"com.apple.system.logger\"))\n" ++
    "(allow file-read-data*\n" ++
    "  (require-all\n" ++
    "    (require-ancestor)\n" ++
    "    (require-not (subpath \"/private/var/db\"))\n" ++
    "  )\n" ++
    ")\n" ++
    "(allow file-write*\n" ++
    "  (require-all\n" ++
    "    (require-ancestor)\n" ++
    "    (require-not (subpath \"/private/var/db\"))\n" ++
    "  )\n" ++
    ")\n";

// ============================================================================
// Per-process profiles
// ============================================================================

// WebProcess (renderer) -- WPE/WebKit content renderer.
//
// Needs:
// - Read: fonts, web content, DNS config, system libraries
// - Network: HTTP(S), WebSocket, DNS resolution
// - Write: profile dir (localStorage, IndexedDB), cache dir
// - Mach: system logger, WindowServer (for compositing)
const web_process_profile =
    "(version 1)\n" ++
    "(deny default)\n" ++
    "\n" ++
    // -- System basics --
    "(allow sysctl-read)\n" ++
    "(allow mach-lookup\n" ++
    "  (global-name \"com.apple.system.logger\")\n" ++
    "  (global-name \"com.apple.system.notification_center\")\n" ++
    "  (global-name \"com.apple.WindowServer\")\n" ++
    "  (global-name \"com.apple.CFBundle.internal\")\n" ++
    ")\n" ++
    "\n" ++
    // -- Signal handling (required for process management) --
    "(allow signal)\n" ++
    "\n" ++
    // -- Filesystem: read-only access --
    "(allow file-read-data*\n" ++
    "  (require-all\n" ++
    "    (require-ancestor)\n" ++
    "    (require-not (subpath \"/private/var/db\"))\n" ++
    "  )\n" ++
    ")\n" ++
    "(allow file-read-metadata*\n" ++
    "  (require-all\n" ++
    "    (require-ancestor)\n" ++
    "  )\n" ++
    ")\n" ++
    // -- Filesystem: write access to profile and cache dirs --
    "(allow file-write*\n" ++
    "  (subpath \"/tmp/zawra-profile\")\n" ++
    "  (subpath \"/tmp\")\n" ++
    "  (subpath \"/private/tmp\")\n" ++
    "  (subpath (param \"profile_dir\"))\n" ++
    "  (subpath (param \"cache_dir\"))\n" ++
    ")\n" ++
    "\n" ++
    // -- Network access (HTTP, WebSocket, DNS) --
    "(allow network*\n" ++
    "  (require-ancestor)\n" ++
    ")\n" ++
    "(allow system-socket)\n" ++
    "\n" ++
    // -- Mach IPC (for XPC services) --
    "(allow mach-lookup\n" ++
    "  (global-name-prefix \"com.apple.\")\n" ++
    ")\n" ++
    "(allow mach-lookup\n" ++
    "  (global-name-prefix \"com.apple.cfnetwork\")\n" ++
    "  (global-name-prefix \"com.apple.securityd\")\n" ++
    "  (global-name-prefix \"com.apple.nsurlsessiond\")\n" ++
    ")\n" ++
    "\n" ++
    // -- Process operations --
    "(allow process*)\n" ++
    "(allow syscall-mach\n" ++
    "  (mach-trap-number 24)\n" ++ // task_set_exception_ports
    "  (mach-trap-number 48)\n" ++ // mach_vm_allocate
    ")\n" ++
    "(allow syscall-unix\n" ++
    "  (syscall-number 0)\n" ++   // read
    "  (syscall-number 1)\n" ++   // write
    "  (syscall-number 3)\n" ++   // close
    "  (syscall-number 4)\n" ++   // open
    "  (syscall-number 33)\n" ++  // dup2
    "  (syscall-number 34)\n" ++  // fcntl
    "  (syscall-number 39)\n" ++  // getppid
    "  (syscall-number 56)\n" ++  // posix_spawn
    "  (syscall-number 59)\n" ++  // execve
    "  (syscall-number 73)\n" ++  // flock
    "  (syscall-number 78)\n" ++  // readlink
    "  (syscall-number 83)\n" ++  // symlink
    "  (syscall-number 97)\n" ++  // socket
    "  (syscall-number 98)\n" ++  // connect
    "  (syscall-number 104)\n" ++ // bind
    "  (syscall-number 105)\n" ++ // setsockopt
    "  (syscall-number 106)\n" ++ // listen
    "  (syscall-number 118)\n" ++ // getsockname
    "  (syscall-number 119)\n" ++ // getpeername
    "  (syscall-number 125)\n" ++ // recvfrom
    "  (syscall-number 133)\n" ++ // sendto
    "  (syscall-number 135)\n" ++ // socketpair
    "  (syscall-number 137)\n" ++ // shutdown
    "  (syscall-number 146)\n" ++ // sendmsg
    "  (syscall-number 147)\n" ++ // recvmsg
    ")\n" ++
    "\n" ++
    // -- Memory management --
    "(allow syscall-unix\n" ++
    "  (syscall-number 197)\n" ++ // mmap
    "  (syscall-number 199)\n" ++ // munmap
    "  (syscall-number 74)\n" ++  // msync
    ")\n" ++
    "\n" ++
    // -- DNS resolution --
    "(allow file-read-data\n" ++
    "  (literal \"/etc/resolv.conf\")\n" ++
    "  (literal \"/etc/hosts\")\n" ++
    "  (literal \"/etc/services\")\n" ++
    "  (literal \"/etc/protocols\")\n" ++
    ")\n" ++
    "\n" ++
    // -- Font access --
    "(allow file-read-data\n" ++
    "  (subpath \"/Library/Fonts\")\n" ++
    "  (subpath \"/System/Library/Fonts\")\n" ++
    "  (subpath (home-subpath \"/Library/Fonts\"))\n" ++
    ")\n" ++
    "\n" ++
    // -- TLS certificates --
    "(allow file-read-data\n" ++
    "  (subpath \"/etc/ssl\")\n" ++
    "  (subpath \"/System/Library/Frameworks/Security.framework\")\n" ++
    ")\n";

// NetworkProcess -- WPE/WebKit network stack.
//
// Needs:
// - Full networking (HTTP, HTTPS, WebSocket, DNS, TLS)
// - Read/Write: cache dir, cookie storage, HSTS pins
// - Read: DNS config, TLS certificates
// - No: fonts, GUI, most filesystem
const network_process_profile =
    "(version 1)\n" ++
    "(deny default)\n" ++
    "\n" ++
    // -- System basics --
    "(allow sysctl-read)\n" ++
    "(allow mach-lookup\n" ++
    "  (global-name \"com.apple.system.logger\")\n" ++
    "  (global-name \"com.apple.CFBundle.internal\")\n" ++
    ")\n" ++
    "\n" ++
    // -- Signal handling --
    "(allow signal)\n" ++
    "\n" ++
    // -- Filesystem: read-only for system files --
    "(allow file-read-data*\n" ++
    "  (require-all\n" ++
    "    (require-ancestor)\n" ++
    "    (require-not (subpath \"/private/var/db\"))\n" ++
    "  )\n" ++
    ")\n" ++
    "(allow file-read-metadata*\n" ++
    "  (require-ancestor)\n" ++
    ")\n" ++
    "\n" ++
    // -- Filesystem: write access to cache and profile --
    "(allow file-write*\n" ++
    "  (subpath \"/tmp/zawra-profile\")\n" ++
    "  (subpath \"/tmp\")\n" ++
    "  (subpath \"/private/tmp\")\n" ++
    "  (subpath (param \"cache_dir\"))\n" ++
    "  (subpath (param \"profile_dir\"))\n" ++
    ")\n" ++
    "\n" ++
    // -- Full network access --
    "(allow network*\n" ++
    "  (require-ancestor)\n" ++
    ")\n" ++
    "(allow system-socket)\n" ++
    "\n" ++
    // -- Mach IPC --
    "(allow mach-lookup\n" ++
    "  (global-name-prefix \"com.apple.\")\n" ++
    ")\n" ++
    "(allow mach-lookup\n" ++
    "  (global-name-prefix \"com.apple.cfnetwork\")\n" ++
    "  (global-name-prefix \"com.apple.securityd\")\n" ++
    "  (global-name-prefix \"com.apple.nsurlsessiond\")\n" ++
    "  (global-name-prefix \"com.apple.smdns\")\n" ++
    "  (global-name-prefix \"com.apple.dnssd\")\n" ++
    "  (global-name-prefix \"com.apple.gidad\")\n" ++
    ")\n" ++
    "\n" ++
    // -- Process operations --
    "(allow process*)\n" ++
    "(allow syscall-unix\n" ++
    "  (syscall-number 0)\n" ++   // read
    "  (syscall-number 1)\n" ++   // write
    "  (syscall-number 3)\n" ++   // close
    "  (syscall-number 4)\n" ++   // open
    "  (syscall-number 33)\n" ++  // dup2
    "  (syscall-number 34)\n" ++  // fcntl
    "  (syscall-number 39)\n" ++  // getppid
    "  (syscall-number 56)\n" ++  // posix_spawn
    "  (syscall-number 59)\n" ++  // execve
    "  (syscall-number 73)\n" ++  // flock
    "  (syscall-number 78)\n" ++  // readlink
    "  (syscall-number 83)\n" ++  // symlink
    "  (syscall-number 97)\n" ++  // socket
    "  (syscall-number 98)\n" ++  // connect
    "  (syscall-number 104)\n" ++ // bind
    "  (syscall-number 105)\n" ++ // setsockopt
    "  (syscall-number 106)\n" ++ // listen
    "  (syscall-number 118)\n" ++ // getsockname
    "  (syscall-number 119)\n" ++ // getpeername
    "  (syscall-number 125)\n" ++ // recvfrom
    "  (syscall-number 133)\n" ++ // sendto
    "  (syscall-number 135)\n" ++ // socketpair
    "  (syscall-number 137)\n" ++ // shutdown
    "  (syscall-number 146)\n" ++ // sendmsg
    "  (syscall-number 147)\n" ++ // recvmsg
    ")\n" ++
    "\n" ++
    // -- Memory management --
    "(allow syscall-unix\n" ++
    "  (syscall-number 197)\n" ++ // mmap
    "  (syscall-number 199)\n" ++ // munmap
    "  (syscall-number 74)\n" ++  // msync
    ")\n" ++
    "\n" ++
    // -- DNS resolution --
    "(allow file-read-data\n" ++
    "  (literal \"/etc/resolv.conf\")\n" ++
    "  (literal \"/etc/hosts\")\n" ++
    "  (literal \"/etc/services\")\n" ++
    "  (literal \"/etc/protocols\")\n" ++
    ")\n" ++
    "\n" ++
    // -- TLS certificates --
    "(allow file-read-data\n" ++
    "  (subpath \"/etc/ssl\")\n" ++
    "  (subpath \"/System/Library/Frameworks/Security.framework\")\n" ++
    "  (subpath \"/System/Library/Frameworks/CoreServices.framework\")\n" ++
    ")\n";

// GPUProcess -- WPE/WebKit GPU accelerated rendering.
//
// Needs:
// - GPU device access (IOKit for Metal/OpenGL)
// - Minimal filesystem (profile dir)
// - Network: none (compositing only, delegated from WebProcess)
// - Mach: WindowServer for display
const gpu_process_profile =
    "(version 1)\n" ++
    "(deny default)\n" ++
    "\n" ++
    // -- System basics --
    "(allow sysctl-read)\n" ++
    "(allow mach-lookup\n" ++
    "  (global-name \"com.apple.system.logger\")\n" ++
    "  (global-name \"com.apple.WindowServer\")\n" ++
    "  (global-name \"com.apple.CFBundle.internal\")\n" ++
    "  (global-name \"com.apple.Metal\")\n" ++
    "  (global-name \"com.apple.IOAccelerator\")\n" ++
    "  (global-name \"com.apple.gpu\")\n" ++
    ")\n" ++
    "\n" ++
    // -- Signal handling --
    "(allow signal)\n" ++
    "\n" ++
    // -- Filesystem: read-only for system libraries --
    "(allow file-read-data*\n" ++
    "  (require-all\n" ++
    "    (require-ancestor)\n" ++
    "    (require-not (subpath \"/private/var/db\"))\n" ++
    "  )\n" ++
    ")\n" ++
    "(allow file-read-metadata*\n" ++
    "  (require-ancestor)\n" ++
    ")\n" ++
    "\n" ++
    // -- Filesystem: write access to profile dir only --
    "(allow file-write*\n" ++
    "  (subpath \"/tmp/zawra-profile\")\n" ++
    "  (subpath \"/tmp\")\n" ++
    "  (subpath \"/private/tmp\")\n" ++
    "  (subpath (param \"profile_dir\"))\n" ++
    ")\n" ++
    "\n" ++
    // -- No network access for GPU process --
    // -- Mach IPC (for XPC and GPU services) --
    "(allow mach-lookup\n" ++
    "  (global-name-prefix \"com.apple.\")\n" ++
    ")\n" ++
    "(allow mach-lookup\n" ++
    "  (global-name \"com.apple.windowserver.active\")\n" ++
    "  (global-name \"com.apple.fonts\")\n" ++
    "  (global-name \"com.apple.CoreDisplay\")\n" ++
    "  (global-name \"com.apple.colorsync\")\n" ++
    ")\n" ++
    "\n" ++
    // -- IOKit access (GPU device discovery) --
    "(allow iokit-open\n" ++
    "  (iokit-class \"AGXAccelerator\")\n" ++
    "  (iokit-class \"IOAccelerator\")\n" ++
    "  (iokit-class \"IOGPUDevice\")\n" ++
    "  (iokit-class \"AppleGPU\")\n" ++
    "  (iokit-class \"AGXCommandQueue\")\n" ++
    "  (iokit-class \"AGXDevice\")\n" ++
    "  (iokit-class \"AGXSharedUserClient\")\n" ++
    ")\n" ++
    "(allow iokit-get-properties\n" ++
    "  (require-ancestor)\n" ++
    ")\n" ++
    "\n" ++
    // -- Process operations --
    "(allow process*)\n" ++
    "(allow syscall-unix\n" ++
    "  (syscall-number 0)\n" ++   // read
    "  (syscall-number 1)\n" ++   // write
    "  (syscall-number 3)\n" ++   // close
    "  (syscall-number 4)\n" ++   // open
    "  (syscall-number 33)\n" ++  // dup2
    "  (syscall-number 34)\n" ++  // fcntl
    "  (syscall-number 39)\n" ++  // getppid
    ")\n" ++
    "\n" ++
    // -- Memory management --
    "(allow syscall-unix\n" ++
    "  (syscall-number 197)\n" ++ // mmap
    "  (syscall-number 199)\n" ++ // munmap
    "  (syscall-number 74)\n" ++  // msync
    ")\n";

test "seatbelt profiles exist" {
    try std.testing.expect(no_internet_profile.len > 0);
    try std.testing.expect(no_write_profile.len > 0);
    try std.testing.expect(web_process_profile.len > 0);
    try std.testing.expect(network_process_profile.len > 0);
    try std.testing.expect(gpu_process_profile.len > 0);
}
