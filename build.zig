//! ZQUIC Build Script
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create the ZQUIC library module
    const mod = b.addModule("zquic", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
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
}
