const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main library
    const lib = b.addLibrary(.{
        .name = "hajr",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .static,
    });

    b.installArtifact(lib);

    // FFI Bindings (shared library for SpiderMonkey/Bun/Deno)
    const ffi_lib = b.addLibrary(.{
        .name = "hajr_ffi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/hajr/sm_bindings.zig"),
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
            .root_source_file = b.path("src/examples/simple_sandbox.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(example);

    // Build tests
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}