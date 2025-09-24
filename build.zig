//! ZQUIC Build Script - Modular QUIC Library for Zig
//!
//! Supports fine-grained zcrypto feature selection for optimized builds:
//! - Core QUIC + zsync: Always included (~1.5MB)
//! - HTTP/3: Web server support (+0.5MB)
//! - DoQ: DNS-over-QUIC (+0.3MB)
//! - Services: GhostBridge/Wraith (+1.5MB)
//! - VPN: zcrypto VPN features (+0.5MB)
//! - Post-Quantum: zcrypto PQ features (+1.5MB)
//! - Monitoring: Performance tracking (+0.2MB)
//!
//! The real size savings come from zcrypto modularity:
//!
//! Examples:
//!   zig build                              # Common features (HTTP/3, DoQ, PQ)
//!   zig build -Dpost-quantum=false        # Disable PQ crypto (-1.5MB)
//!   zig build -Dvpn=false -Dservices=false # Minimal zcrypto features
//!   zig build -Dservices=true -Dvpn=true  # Full enterprise build

const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ============================================================================
    // FEATURE FLAGS - Enable/disable optional components for modular builds
    // ============================================================================

    const enable_http3 = b.option(bool, "http3", "Enable HTTP/3 support") orelse true;
    const enable_doq = b.option(bool, "doq", "Enable DNS-over-QUIC support") orelse true;
    const enable_vpn = b.option(bool, "vpn", "Enable VPN functionality") orelse false;
    const enable_services = b.option(bool, "services", "Enable GhostBridge/Wraith services") orelse false;
    const enable_post_quantum = b.option(bool, "post-quantum", "Enable post-quantum QUIC") orelse true;
    const enable_monitoring = b.option(bool, "monitoring", "Enable performance monitoring") orelse false;
    // Note: zsync is always enabled - modularity focuses on zcrypto features
    const enable_examples = b.option(bool, "examples", "Build example executables") orelse true;

    // ============================================================================
    // DEPENDENCIES - Conditionally include based on features
    // ============================================================================

    // zcrypto dependency (configure features based on zquic needs)
    const zcrypto_dep = b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
        // Pass our feature flags to zcrypto
        .@"post-quantum" = enable_post_quantum,
        .vpn = enable_vpn,
        .async = true, // zsync always enabled
    });

    // zsync dependency (always enabled - high performance async runtime)
    const zsync_dep = b.dependency("zsync", .{
        .target = target,
        .optimize = optimize,
    });

    // ============================================================================
    // MAIN ZQUIC MODULE - Includes all enabled features
    // ============================================================================

    // Add build options for conditional compilation
    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_http3", enable_http3);
    build_options.addOption(bool, "enable_doq", enable_doq);
    build_options.addOption(bool, "enable_vpn", enable_vpn);
    build_options.addOption(bool, "enable_services", enable_services);
    build_options.addOption(bool, "enable_post_quantum", enable_post_quantum);
    build_options.addOption(bool, "enable_monitoring", enable_monitoring);
    build_options.addOption(bool, "enable_async_zsync", true); // zsync always enabled

    const mod = b.addModule("zquic", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "build_options", .module = build_options.createModule() },
            .{ .name = "zcrypto", .module = zcrypto_dep.module("zcrypto") },
            .{ .name = "zsync", .module = zsync_dep.module("zsync") },
        },
    });

    // ============================================================================
    // EXECUTABLES AND EXAMPLES
    // ============================================================================

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

    // Examples (conditional)
    if (enable_examples) {
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

        // HTTP/3 server example (only if HTTP/3 is enabled)
        if (enable_http3) {
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
        }

        // DoQ echo server example (only if DoQ is enabled)
        if (enable_doq) {
            const doq_server_exe = b.addExecutable(.{
                .name = "zquic-doq-server",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("examples/doq_echo_server.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "zquic", .module = mod },
                    },
                }),
            });
            b.installArtifact(doq_server_exe);
        }

        // VPN examples (only if VPN is enabled)
        if (enable_vpn) {
            const ghostmesh_exe = b.addExecutable(.{
                .name = "ghostmesh-vpn",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("examples/ghostmesh_vpn.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "zquic", .module = mod },
                    },
                }),
            });
            b.installArtifact(ghostmesh_exe);

            const ghostscale_exe = b.addExecutable(.{
                .name = "ghostscale-vpn",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("examples/ghostscale_vpn.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "zquic", .module = mod },
                    },
                }),
            });
            b.installArtifact(ghostscale_exe);
        }

        // Post-Quantum demo (only if PQ is enabled)
        if (enable_post_quantum) {
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
        }

        // Services examples (only if services are enabled)
        if (enable_services) {
            const ghostbridge_demo_exe = b.addExecutable(.{
                .name = "ghostbridge-demo",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("examples/ghostbridge_demo.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "zquic", .module = mod },
                    },
                }),
            });
            b.installArtifact(ghostbridge_demo_exe);

            const crypto_trading_demo_exe = b.addExecutable(.{
                .name = "crypto-trading-demo",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("examples/crypto_trading_demo.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "zquic", .module = mod },
                    },
                }),
            });
            b.installArtifact(crypto_trading_demo_exe);
        }
    }

    // ============================================================================
    // RUN STEPS
    // ============================================================================

    // Run steps
    const run_step = b.step("run", "Run the main demo");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    // Additional run steps for examples (only if examples are enabled)
    if (enable_examples) {
        // Note: Need to reference the executables created above, not dependencies
        // This is a placeholder - would need to be implemented properly
        // For now, commenting out to avoid build errors

        // const run_client_step = b.step("run-client", "Run the client example");
        // const run_server_step = b.step("run-server", "Run the server example");
        // ... other run steps would go here
    }

    // Allow passing arguments to the applications
    if (b.args) |args| {
        run_cmd.addArgs(args);
        // Add args to other run commands as needed
    }

    // ============================================================================
    // TESTS
    // ============================================================================

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

    // ============================================================================
    // DOCUMENTATION
    // ============================================================================

    // Documentation generation
    const docs_step = b.step("docs", "Generate documentation");
    const docs_install = b.addInstallDirectory(.{
        .source_dir = mod_tests.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    docs_step.dependOn(&docs_install.step);
}
