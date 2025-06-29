//! Build configuration for FFI libraries
//!
//! Generates C-compatible shared/static libraries for Rust integration

const std = @import("std");

pub fn buildFfi(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) void {
    // Create the main ZQUIC module
    const zquic_mod = b.addModule("zquic", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    // ZQUIC FFI Library
    const zquic_ffi_lib = b.addSharedLibrary(.{
        .name = "zquic",
        .root_source_file = b.path("src/ffi/zquic_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    zquic_ffi_lib.root_module.addImport("zquic", zquic_mod);
    zquic_ffi_lib.linkLibC();
    b.installArtifact(zquic_ffi_lib);

    // Static version for linking
    const zquic_ffi_static = b.addStaticLibrary(.{
        .name = "zquic",
        .root_source_file = b.path("src/ffi/zquic_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    zquic_ffi_static.root_module.addImport("zquic", zquic_mod);
    zquic_ffi_static.linkLibC();
    b.installArtifact(zquic_ffi_static);

    // ZCrypto FFI Library
    const zcrypto_ffi_lib = b.addSharedLibrary(.{
        .name = "zcrypto",
        .root_source_file = b.path("src/ffi/zcrypto_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    zcrypto_ffi_lib.linkLibC();
    b.installArtifact(zcrypto_ffi_lib);

    // ZCrypto static version
    const zcrypto_ffi_static = b.addStaticLibrary(.{
        .name = "zcrypto",
        .root_source_file = b.path("src/ffi/zcrypto_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    zcrypto_ffi_static.linkLibC();
    b.installArtifact(zcrypto_ffi_static);

    // GhostBridge FFI Library
    const ghostbridge_ffi_lib = b.addSharedLibrary(.{
        .name = "ghostbridge",
        .root_source_file = b.path("src/ffi/ghostbridge_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    ghostbridge_ffi_lib.root_module.addImport("zquic", zquic_mod);
    ghostbridge_ffi_lib.linkLibC();
    b.installArtifact(ghostbridge_ffi_lib);

    // GhostBridge static version
    const ghostbridge_ffi_static = b.addStaticLibrary(.{
        .name = "ghostbridge",
        .root_source_file = b.path("src/ffi/ghostbridge_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    ghostbridge_ffi_static.root_module.addImport("zquic", zquic_mod);
    ghostbridge_ffi_static.linkLibC();
    b.installArtifact(ghostbridge_ffi_static);

    // Generate C headers
    const header_gen = b.addExecutable(.{
        .name = "header_gen",
        .root_source_file = b.path("src/ffi/header_gen.zig"),
        .target = target,
        .optimize = optimize,
    });

    const gen_headers = b.addRunArtifact(header_gen);
    gen_headers.addArg("--output-dir");
    gen_headers.addArg(b.getInstallPath(.header, ""));

    const header_step = b.step("headers", "Generate C headers for FFI");
    header_step.dependOn(&gen_headers.step);

    // Test executables for FFI validation
    const ffi_test = b.addExecutable(.{
        .name = "ffi_test",
        .root_source_file = b.path("src/ffi/test_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    ffi_test.linkLibrary(zquic_ffi_static);
    ffi_test.linkLibrary(zcrypto_ffi_static);
    ffi_test.linkLibrary(ghostbridge_ffi_static);
    ffi_test.linkLibC();
    b.installArtifact(ffi_test);

    const run_ffi_test = b.addRunArtifact(ffi_test);
    const ffi_test_step = b.step("test-ffi", "Test FFI interface");
    ffi_test_step.dependOn(&run_ffi_test.step);
}
