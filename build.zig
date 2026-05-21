const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{ .cpu_model = .native } });
    const optimize = b.standardOptimizeOption(.{});

    const hajr_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Main library
    const lib = b.addLibrary(.{
        .name = "hajr",
        .root_module = hajr_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // FFI Bindings (shared library for SpiderMonkey/Bun/Deno)
    const ffi_lib = b.addLibrary(.{
        .name = "hajr_ffi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi_export.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .dynamic,
    });
    b.installArtifact(ffi_lib);

    // Examples
    const example = b.addExecutable(.{
        .name = "simple_sandbox",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/example_root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(example);

    // Build tests
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
            .optimize = .ReleaseFast, // High performance for benchmarks
        }),
    });
    benchmark.root_module.addImport("hajr", hajr_mod);
    b.installArtifact(benchmark);

    const bench_run = b.addRunArtifact(benchmark);
    const bench_step = b.step("benchmark", "Run high-precision performance benchmark");
    bench_step.dependOn(&bench_run.step);
}