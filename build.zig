const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main library
    const lib = b.addStaticLibrary(.{
        .name = "hajr",
        .root_source_file = b.path("src/core/sandbox.zig"),
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(lib);

    // Build tests
    const tests = b.addTest(.{
        .root_source_file = b.path("src/core/sandbox.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}