//! ZQUIC Build Script
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Get zcrypto dependency
    const zcrypto_dep = b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
    });

    // Create the ZQUIC library module
    const mod = b.addModule("zquic", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "zcrypto", .module = zcrypto_dep.module("zcrypto") },
        },
    });

    // Main executable
    const exe = b.addExecutable(.{
        .name = "zquic",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        }),
    });
    b.installArtifact(exe);

    // Examples
    const client_exe = b.addExecutable(.{
        .name = "zquic-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        }),
    });
    b.installArtifact(client_exe);

    const server_exe = b.addExecutable(.{
        .name = "zquic-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        }),
    });
    b.installArtifact(server_exe);

    // const ghostmesh_exe = b.addExecutable(.{
    //     .name = "ghostmesh-vpn",
    //     .root_module = b.createModule(.{
    //         .root_source_file = b.path("examples/ghostmesh_vpn.zig"),
    //         .target = target,
    //         .optimize = optimize,
    //         .imports = &.{
    //             .{ .name = "zquic", .module = mod },
    //         },
    //     }),
    // });
    // b.installArtifact(ghostmesh_exe);

    // Enhanced HTTP/3 server example
    const http3_server_exe = b.addExecutable(.{
        .name = "zquic-http3-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http3_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        }),
    });
    b.installArtifact(http3_server_exe);

    // FFI Library for Rust Integration
    const ffi_lib = b.addSharedLibrary(.{
        .name = "zquic",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi/zquic_ffi.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        }),
    });
    ffi_lib.linkLibC(); // Required for FFI
    b.installArtifact(ffi_lib);

    // Static library for linking
    const static_lib = b.addStaticLibrary(.{
        .name = "zquic",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi/zquic_ffi.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        }),
    });
    static_lib.linkLibC(); // Required for FFI
    b.installArtifact(static_lib);

    // Install header for C/Rust integration
    const install_header = b.addInstallFile(b.path("include/zquic.h"), "include/zquic.h");
    b.getInstallStep().dependOn(&install_header.step);

    // Run steps
    const run_step = b.step("run", "Run the main demo");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_client_step = b.step("run-client", "Run the client example");
    const run_client_cmd = b.addRunArtifact(client_exe);
    run_client_step.dependOn(&run_client_cmd.step);
    run_client_cmd.step.dependOn(b.getInstallStep());

    const run_server_step = b.step("run-server", "Run the server example");
    const run_server_cmd = b.addRunArtifact(server_exe);
    run_server_step.dependOn(&run_server_cmd.step);
    run_server_cmd.step.dependOn(b.getInstallStep());

    // const run_ghostmesh_step = b.step("run-ghostmesh", "Run the GhostMesh VPN example");
    // const run_ghostmesh_cmd = b.addRunArtifact(ghostmesh_exe);
    // run_ghostmesh_step.dependOn(&run_ghostmesh_cmd.step);
    // run_ghostmesh_cmd.step.dependOn(b.getInstallStep());

    const run_http3_server_step = b.step("run-http3-server", "Run the HTTP/3 server example");
    const run_http3_server_cmd = b.addRunArtifact(http3_server_exe);
    run_http3_server_step.dependOn(&run_http3_server_cmd.step);
    run_http3_server_cmd.step.dependOn(b.getInstallStep());

    // FFI build step for Rust integration
    const ffi_step = b.step("ffi", "Build FFI library for Rust integration");
    ffi_step.dependOn(&ffi_lib.step);
    ffi_step.dependOn(&static_lib.step);
    ffi_step.dependOn(&install_header.step);

    // Allow passing arguments to the applications
    if (b.args) |args| {
        run_cmd.addArgs(args);
        run_client_cmd.addArgs(args);
        run_server_cmd.addArgs(args);
        // run_ghostmesh_cmd.addArgs(args);
        run_http3_server_cmd.addArgs(args);
    }

    // Tests
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    // Documentation generation
    const docs_step = b.step("docs", "Generate documentation");
    const docs_install = b.addInstallDirectory(.{
        .source_dir = mod_tests.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    docs_step.dependOn(&docs_install.step);

    // FFI Test Example
    const ffi_test_exe = b.addExecutable(.{
        .name = "zquic-ffi-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/ffi_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        }),
    });
    ffi_test_exe.linkLibC();
    b.installArtifact(ffi_test_exe);

    // FFI Integration Test
    const integration_test_exe = b.addExecutable(.{
        .name = "zquic-integration-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/integration_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    integration_test_exe.linkLibrary(ffi_lib);
    b.installArtifact(integration_test_exe);

    // Post-Quantum QUIC Demo
    const pq_demo_exe = b.addExecutable(.{
        .name = "zquic-pq-demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/pq_quic_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        }),
    });
    b.installArtifact(pq_demo_exe);

    // GhostBridge gRPC-over-QUIC Demo
    const ghostbridge_demo_exe = b.addExecutable(.{
        .name = "zquic-ghostbridge-demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/ghostbridge_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        }),
    });
    ghostbridge_demo_exe.linkLibrary(ffi_lib);
    b.installArtifact(ghostbridge_demo_exe);

    // Run steps for FFI tests
    const run_ffi_test_step = b.step("run-ffi-test", "Run the FFI test example");
    const run_ffi_test_cmd = b.addRunArtifact(ffi_test_exe);
    run_ffi_test_step.dependOn(&run_ffi_test_cmd.step);

    const run_integration_test_step = b.step("run-integration-test", "Run the FFI integration test");
    const run_integration_test_cmd = b.addRunArtifact(integration_test_exe);
    run_integration_test_step.dependOn(&run_integration_test_cmd.step);
    run_integration_test_cmd.step.dependOn(&ffi_lib.step);

    const run_pq_demo_step = b.step("run-pq-demo", "Run the Post-Quantum QUIC demo");
    const run_pq_demo_cmd = b.addRunArtifact(pq_demo_exe);
    run_pq_demo_step.dependOn(&run_pq_demo_cmd.step);

    const run_ghostbridge_demo_step = b.step("run-ghostbridge-demo", "Run the GhostBridge gRPC-over-QUIC demo");
    const run_ghostbridge_demo_cmd = b.addRunArtifact(ghostbridge_demo_exe);
    run_ghostbridge_demo_step.dependOn(&run_ghostbridge_demo_cmd.step);
    run_ghostbridge_demo_cmd.step.dependOn(&ffi_lib.step);
}
