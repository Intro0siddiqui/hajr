const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{ .cpu_model = .native } });
    const optimize = b.standardOptimizeOption(.{});

    // Link PKRU C implementation only on x86_64 (Intel MPK)
    // Create this before modules so we can link it to any module that needs it
    const pkru_link: ?Build.Module.LinkObject = if (target.result.cpu.arch == .x86_64) blk: {
        const c_source = b.allocator.create(Build.Module.CSourceFile) catch @panic("OOM");
        c_source.* = .{ .file = b.path("src/hw/arch/pkru.c") };
        break :blk Build.Module.LinkObject{ .c_source_file = c_source };
    } else null;

    const hajr_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    hajr_mod.link_libc = true;
    if (pkru_link) |link| {
        hajr_mod.link_objects.append(b.allocator, link) catch @panic("OOM");
    }

    // FFI Bindings (shared library for JavaScriptCore/Bun/Deno)
    const ffi_mod = b.createModule(.{
        .root_source_file = b.path("src/ffi_export.zig"),
        .target = target,
        .optimize = optimize,
    });
    ffi_mod.link_libc = true;
    if (pkru_link) |link| {
        ffi_mod.link_objects.append(b.allocator, link) catch @panic("OOM");
    }

    // Examples
    const example_mod = b.createModule(.{
        .root_source_file = b.path("src/example_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (pkru_link) |link| {
        example_mod.link_objects.append(b.allocator, link) catch @panic("OOM");
    }

    // Main library
    const lib = b.addLibrary(.{
        .name = "hajr",
        .root_module = hajr_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    const ffi_lib = b.addLibrary(.{
        .name = "hajr_ffi",
        .root_module = ffi_mod,
        .linkage = .dynamic,
    });
    b.installArtifact(ffi_lib);

    // Static library with FFI exports for tight integration
    const ffi_static_lib = b.addLibrary(.{
        .name = "hajr_ffi_static",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi_export.zig"),
            .target = target,
            .optimize = optimize,
            .pic = true,
        }),
        .linkage = .static,
    });
    b.installArtifact(ffi_static_lib);

    // Examples
    const example = b.addExecutable(.{
        .name = "simple_sandbox",
        .root_module = example_mod,
    });
    b.installArtifact(example);

    // Build tests - uses hajr_mod which already has pkru_link added above
    const tests = b.addTest(.{
        .root_module = hajr_mod,
    });
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    // Benchmark
    const benchmark = b.addExecutable(.{
        .name = "benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests/benchmark.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        }),
    });
    benchmark.root_module.addImport("hajr", hajr_mod);
    b.installArtifact(benchmark);

    const bench_run = b.addRunArtifact(benchmark);
    const bench_step = b.step("benchmark", "Run high-precision performance benchmark");
    bench_step.dependOn(&bench_run.step);
}
