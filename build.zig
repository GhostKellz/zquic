//! ZQUIC Build Script - Modular QUIC Library for Zig
//!
//! Supports fine-grained feature selection for optimized builds:
//! - Core QUIC: Always included (~1.5MB)
//! - HTTP/3: Web server support (+0.5MB)
//! - DoQ: DNS-over-QUIC (+0.3MB)
//! - Services: GhostBridge/Wraith (+1.5MB)
//! - VPN: zcrypto VPN features (+0.5MB)
//! - Post-Quantum: zcrypto PQ features (+1.5MB)
//! - Monitoring: Performance tracking (+0.2MB)
//!
//! Examples:
//!   zig build                              # Common features (HTTP/3, DoQ, PQ)
//!   zig build -Dpost-quantum=false        # Disable PQ crypto (-1.5MB)
//!   zig build -Dvpn=false -Dservices=false # Minimal features
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
    const enable_post_quantum = b.option(bool, "post-quantum", "Enable post-quantum QUIC") orelse false;
    const enable_experimental_crypto = b.option(bool, "experimental-crypto", "Enable experimental crypto features (required for PQ)") orelse false;
    const enable_monitoring = b.option(bool, "monitoring", "Enable performance monitoring") orelse false;
    const enable_examples = b.option(bool, "examples", "Build example executables") orelse true;

    // ============================================================================
    // DEPENDENCIES - Conditionally include based on features
    // ============================================================================

    // zcrypto dependency (configure features based on zquic needs)
    // PQ requires both post-quantum AND experimental-crypto flags
    const zcrypto_dep = b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
        // Stable features always enabled
        .tls = true,
        .@"hardware-accel" = true,
        // Async disabled unless needed
        .async = false,
        // PQ only enabled when both flags set
        .@"post-quantum" = enable_post_quantum and enable_experimental_crypto,
        .@"experimental-crypto" = enable_experimental_crypto,
        .vpn = enable_vpn,
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
    build_options.addOption(bool, "enable_experimental_crypto", enable_experimental_crypto);
    build_options.addOption(bool, "enable_monitoring", enable_monitoring);

    const mod = b.addModule("zquic", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "build_options", .module = build_options.createModule() },
            .{ .name = "zcrypto", .module = zcrypto_dep.module("zcrypto") },
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
            const vpn_server_demo = b.addExecutable(.{
                .name = "quic-vpn-server-demo",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("examples/quic_vpn_server.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "zquic", .module = mod },
                    },
                }),
            });
            b.installArtifact(vpn_server_demo);

            const vpn_client_demo = b.addExecutable(.{
                .name = "quic-vpn-client-demo",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("examples/quic_vpn_client.zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{
                        .{ .name = "zquic", .module = mod },
                    },
                }),
            });
            b.installArtifact(vpn_client_demo);
        }

        // Post-Quantum demo (only if both PQ and experimental-crypto are enabled)
        if (enable_post_quantum and enable_experimental_crypto) {
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
        // Note: ghostbridge_demo.zig and crypto_trading_demo.zig removed pending API updates
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

    const handshake_test_module = b.createModule(.{
        .root_source_file = b.path("tests/handshake_integration_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zquic", .module = mod },
        },
    });
    const handshake_tests = b.addTest(.{
        .root_module = handshake_test_module,
    });
    const run_handshake_tests = b.addRunArtifact(handshake_tests);

    const fuzz_test_module = b.createModule(.{
        .root_source_file = b.path("tests/packet_fuzz_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zquic", .module = mod },
        },
    });
    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_test_module,
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);

    const integration_step = b.step("integration-tests", "Run integration tests");
    integration_step.dependOn(&run_handshake_tests.step);

    const fuzz_step = b.step("fuzz-tests", "Run packet parsing fuzz tests");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_handshake_tests.step);
    test_step.dependOn(&run_fuzz_tests.step);

    if (enable_http3) {
        const http3_test_module = b.createModule(.{
            .root_source_file = b.path("tests/http3_integration_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        });
        const http3_tests = b.addTest(.{
            .root_module = http3_test_module,
        });
        const run_http3_tests = b.addRunArtifact(http3_tests);
        integration_step.dependOn(&run_http3_tests.step);
        test_step.dependOn(&run_http3_tests.step);
    }

    if (enable_doq) {
        const doq_test_module = b.createModule(.{
            .root_source_file = b.path("tests/doq_integration_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        });
        const doq_tests = b.addTest(.{
            .root_module = doq_test_module,
        });
        const run_doq_tests = b.addRunArtifact(doq_tests);
        integration_step.dependOn(&run_doq_tests.step);
        test_step.dependOn(&run_doq_tests.step);
    }

    if (enable_services) {
        const services_test_module = b.createModule(.{
            .root_source_file = b.path("tests/services_integration_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
            },
        });
        const services_tests = b.addTest(.{
            .root_module = services_test_module,
        });
        const run_services_tests = b.addRunArtifact(services_tests);
        integration_step.dependOn(&run_services_tests.step);
        test_step.dependOn(&run_services_tests.step);
    }

    // zcrypto stable API tests (always run - tests hash, kex, kdf, rand, util)
    {
        const zcrypto_stable_module = b.createModule(.{
            .root_source_file = b.path("tests/zcrypto_stable_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zcrypto", .module = zcrypto_dep.module("zcrypto") },
            },
        });
        const zcrypto_stable_tests = b.addTest(.{
            .root_module = zcrypto_stable_module,
        });
        const run_zcrypto_stable = b.addRunArtifact(zcrypto_stable_tests);
        integration_step.dependOn(&run_zcrypto_stable.step);
        test_step.dependOn(&run_zcrypto_stable.step);
    }

    // zcrypto PQ integration tests (require PQ flags - test ML-KEM, hybrid key exchange)
    if (enable_post_quantum and enable_experimental_crypto) {
        const zcrypto_pq_module = b.createModule(.{
            .root_source_file = b.path("tests/zcrypto_integration_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = mod },
                .{ .name = "zcrypto", .module = zcrypto_dep.module("zcrypto") },
            },
        });
        const zcrypto_pq_tests = b.addTest(.{
            .root_module = zcrypto_pq_module,
        });
        const run_zcrypto_pq = b.addRunArtifact(zcrypto_pq_tests);
        integration_step.dependOn(&run_zcrypto_pq.step);
        test_step.dependOn(&run_zcrypto_pq.step);
    }

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
