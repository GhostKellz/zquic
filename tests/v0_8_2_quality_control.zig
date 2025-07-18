//! ZQUIC v0.8.2 Quality Control Tests
//!
//! Comprehensive test suite for validating:
//! - Memory leak detection
//! - Post-quantum hybrid TLS functionality
//! - Zero-RTT connection resumption
//! - Crypto-optimized congestion control
//! - Connection multiplexing and pooling
//! - Telemetry and monitoring systems
//! - Performance benchmarks

const std = @import("std");
const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectError = testing.expectError;

// Import ZQUIC v0.8.2 modules
const zquic = @import("../src/root.zig");
const HybridPQTlsContext = @import("../src/crypto/hybrid_pq_tls.zig").HybridPQTlsContext;
const HybridConfig = @import("../src/crypto/hybrid_pq_tls.zig").HybridConfig;
const ZeroRttSessionManager = @import("../src/crypto/zero_rtt_resumption.zig").ZeroRttSessionManager;
const ZeroRttContext = @import("../src/crypto/zero_rtt_resumption.zig").ZeroRttContext;
const CryptoOptimizedCongestionController = @import("../src/core/crypto_optimized_congestion.zig").CryptoOptimizedCongestionController;
const CryptoWorkloadType = @import("../src/core/crypto_optimized_congestion.zig").CryptoWorkloadType;
const CryptoConnectionMultiplexer = @import("../src/performance/crypto_connection_multiplexer.zig").CryptoConnectionMultiplexer;
const CryptoConnectionPoolConfig = @import("../src/performance/crypto_connection_multiplexer.zig").CryptoConnectionPoolConfig;
const CryptoTelemetrySystem = @import("../src/monitoring/crypto_telemetry.zig").CryptoTelemetrySystem;
const CryptoTelemetryConfig = @import("../src/monitoring/crypto_telemetry.zig").CryptoTelemetryConfig;

/// Memory leak detection helper
const MemoryTracker = struct {
    allocator: std.mem.Allocator,
    initial_stats: std.heap.GeneralPurposeAllocator(.{}).Stats,
    gpa: *std.heap.GeneralPurposeAllocator(.{}),
    
    const Self = @This();
    
    pub fn init(gpa: *std.heap.GeneralPurposeAllocator(.{})) Self {
        const allocator = gpa.allocator();
        return Self{
            .allocator = allocator,
            .initial_stats = gpa.stats,
            .gpa = gpa,
        };
    }
    
    pub fn checkForLeaks(self: *Self) !void {
        const final_stats = self.gpa.stats;
        const leaked_bytes = final_stats.total_allocated - final_stats.total_freed;
        const initial_leaked = self.initial_stats.total_allocated - self.initial_stats.total_freed;
        const new_leaks = leaked_bytes - initial_leaked;
        
        std.log.info("Memory Stats: {} bytes allocated, {} bytes freed, {} bytes leaked (+{} new)", .{
            final_stats.total_allocated, final_stats.total_freed, leaked_bytes, new_leaks
        });
        
        // Allow small leaks for static data but fail on significant leaks
        if (new_leaks > 1024) { // 1KB tolerance
            std.log.err("Memory leak detected: {} bytes leaked", .{new_leaks});
            return error.MemoryLeak;
        }
    }
};

/// Test post-quantum hybrid TLS functionality
test "Hybrid PQ-TLS: Basic functionality and memory safety" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    const config = HybridConfig{
        .enable_ml_kem = true,
        .enable_x25519 = true,
        .prefer_pq = true,
        .fallback_to_classical = true,
    };
    
    // Test server context
    {
        var server_ctx = try HybridPQTlsContext.init(tracker.allocator, true, config);
        defer server_ctx.deinit();
        
        try server_ctx.initializeHandshake();
        try expect(server_ctx.getSecurityLevel().len > 0);
    }
    
    // Test client context
    {
        var client_ctx = try HybridPQTlsContext.init(tracker.allocator, false, config);
        defer client_ctx.deinit();
        
        try client_ctx.initializeHandshake();
        try expect(client_ctx.isPostQuantumActive() or !config.enable_ml_kem);
    }
    
    try tracker.checkForLeaks();
}

/// Test hybrid TLS handshake between client and server
test "Hybrid PQ-TLS: Full handshake simulation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    const config = HybridConfig{
        .enable_ml_kem = true,
        .enable_x25519 = true,
        .prefer_pq = true,
        .fallback_to_classical = false,
    };
    
    var server_ctx = try HybridPQTlsContext.init(tracker.allocator, true, config);
    defer server_ctx.deinit();
    
    var client_ctx = try HybridPQTlsContext.init(tracker.allocator, false, config);
    defer client_ctx.deinit();
    
    // Initialize both contexts
    try server_ctx.initializeHandshake();
    try client_ctx.initializeHandshake();
    
    // Simulate handshake (simplified)
    var client_hello = try tracker.allocator.alloc(u8, 32 + 1184); // X25519 + ML-KEM
    defer tracker.allocator.free(client_hello);
    
    @memcpy(client_hello[0..32], &client_ctx.hybrid_kx.x25519_public);
    @memcpy(client_hello[32..], client_ctx.hybrid_kx.ml_kem_public);
    
    const server_hello = try server_ctx.processClientHello(client_hello);
    defer tracker.allocator.free(server_hello);
    
    try client_ctx.processServerHello(server_hello);
    
    // Verify both contexts have established secure connection
    try expect(server_ctx.isPostQuantumActive());
    try expect(client_ctx.isPostQuantumActive());
    
    // Derive keys
    const server_keys = try server_ctx.deriveQuicKeys(tracker.allocator);
    defer tracker.allocator.free(server_keys);
    const client_keys = try client_ctx.deriveQuicKeys(tracker.allocator);
    defer tracker.allocator.free(client_keys);
    
    try expect(server_keys.len == 128);
    try expect(client_keys.len == 128);
    
    try tracker.checkForLeaks();
}

/// Test Zero-RTT session management
test "Zero-RTT: Session management and anti-replay" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    var session_mgr = try ZeroRttSessionManager.init(tracker.allocator);
    defer session_mgr.deinit();
    
    // Create resumption secret
    var resumption_secret: [32]u8 = undefined;
    std.crypto.random.bytes(&resumption_secret);
    
    // Create and validate session ticket
    const ticket = try session_mgr.createSessionTicket(resumption_secret);
    try expect(ticket.isValid());
    
    // Test session validation
    const validated_ticket = session_mgr.validateSessionTicket(ticket.ticket_id, 12345);
    try expect(validated_ticket != null);
    
    // Test anti-replay protection
    const replay_result = session_mgr.validateSessionTicket(ticket.ticket_id, 12345);
    try expect(replay_result == null); // Should reject replay
    
    // Test new packet acceptance
    const new_packet_result = session_mgr.validateSessionTicket(ticket.ticket_id, 12346);
    try expect(new_packet_result != null);
    
    // Test cleanup
    try session_mgr.cleanupExpiredSessions();
    const stats = session_mgr.getStats();
    try expect(stats.active_sessions >= 0);
    
    try tracker.checkForLeaks();
}

/// Test Zero-RTT context and early data
test "Zero-RTT: Early data handling" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    var zero_rtt = ZeroRttContext.init(tracker.allocator);
    defer zero_rtt.deinit();
    
    // Create session ticket
    var resumption_secret: [32]u8 = undefined;
    std.crypto.random.bytes(&resumption_secret);
    
    var session_mgr = try ZeroRttSessionManager.init(tracker.allocator);
    defer session_mgr.deinit();
    
    const ticket = try session_mgr.createSessionTicket(resumption_secret);
    
    // Start early data
    try zero_rtt.startEarlyData(ticket);
    try expect(zero_rtt.canUseEarlyData());
    
    // Write early data (crypto trading order)
    const trading_order = "BUY,ETH,100,@3500,URGENT";
    const success = try zero_rtt.writeEarlyData(trading_order);
    try expect(success);
    
    // Verify early data
    const early_data = zero_rtt.getEarlyData();
    try expect(std.mem.eql(u8, early_data, trading_order));
    
    // Accept early data
    zero_rtt.acceptEarlyData();
    try expect(zero_rtt.early_data_accepted);
    
    try tracker.checkForLeaks();
}

/// Test crypto-optimized congestion control
test "Congestion Control: BBR crypto optimization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    var controller = CryptoOptimizedCongestionController.init(
        tracker.allocator, 
        .bbr, 
        .high_frequency_trading
    );
    
    // Test packet sending
    try expect(controller.canSend(1460, .normal)); // Standard packet
    controller.onPacketSent(1460);
    
    // Simulate ACK with latency
    controller.onPacketAcked(1460, 5000, .high); // 5ms RTT
    
    // Test high priority packet handling
    try expect(controller.canSend(1460, .critical));
    
    // Simulate packet loss
    controller.onPacketLost(1460);
    
    // Test workload optimization
    controller.optimizeForCrypto(.high_frequency_trading);
    
    // Get statistics
    const stats = controller.getCryptoStats();
    try expect(stats.algorithm == .bbr);
    try expect(stats.cwnd > 0);
    try expect(stats.pacing_rate > 0);
    
    try tracker.checkForLeaks();
}

/// Test CUBIC congestion control for blockchain workloads
test "Congestion Control: CUBIC blockchain optimization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    var controller = CryptoOptimizedCongestionController.init(
        tracker.allocator, 
        .cubic, 
        .blockchain_sync
    );
    
    // Test large blockchain packets
    const block_size: u32 = 65536; // 64KB block
    try expect(controller.canSend(block_size, .normal));
    
    controller.onPacketSent(block_size);
    controller.onPacketAcked(block_size, 20_000, .normal); // 20ms RTT
    
    // Test burst handling for blockchain
    controller.optimizeForCrypto(.blockchain_sync);
    
    const stats = controller.getCryptoStats();
    try expect(stats.algorithm == .cubic);
    try expect(stats.cwnd >= 20 * 1460); // Large window for blockchain
    
    try tracker.checkForLeaks();
}

/// Test connection multiplexer and pooling
test "Connection Multiplexing: Pool management" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    const pool_config = CryptoConnectionPoolConfig{
        .initial_pool_size = 5,
        .max_pool_size = 20,
        .min_pool_size = 2,
        .idle_timeout_ms = 1000,
        .health_check_interval_ms = 500,
        .acquire_timeout_ms = 100,
        .enable_zero_rtt = true,
        .enable_post_quantum = true,
        .enable_connection_migration = true,
        .enable_priority_queuing = true,
        .enable_adaptive_scaling = true,
        .enable_load_balancing = true,
        .enable_burst_handling = true,
        .enable_protocol_multiplexing = true,
        .max_concurrent_protocols = 4,
    };
    
    var multiplexer = CryptoConnectionMultiplexer.init(tracker.allocator, pool_config);
    defer multiplexer.deinit();
    
    // Test connection acquisition for different protocols
    const doq_conn = try multiplexer.acquireConnection(
        .dns_over_quic, 
        .high, 
        .high_frequency_trading
    );
    defer multiplexer.releaseConnection(doq_conn);
    
    const http3_conn = try multiplexer.acquireConnection(
        .http3, 
        .normal, 
        .defi_api
    );
    defer multiplexer.releaseConnection(http3_conn);
    
    // Test connection properties
    try expect(doq_conn.id != http3_conn.id);
    try expect(doq_conn.supported_protocols.contains(.dns_over_quic));
    try expect(http3_conn.supported_protocols.contains(.http3));
    
    // Test statistics
    const stats = multiplexer.getStats();
    try expect(stats.total_connections >= 2);
    try expect(stats.connections_created >= 2);
    
    try tracker.checkForLeaks();
}

/// Test protocol multiplexing on single connection
test "Connection Multiplexing: Protocol multiplexing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    // Enable aggressive multiplexing
    const pool_config = CryptoConnectionPoolConfig{
        .initial_pool_size = 1,
        .max_pool_size = 1, // Force reuse
        .enable_protocol_multiplexing = true,
        .max_concurrent_protocols = 4,
    };
    
    var multiplexer = CryptoConnectionMultiplexer.init(tracker.allocator, pool_config);
    defer multiplexer.deinit();
    
    // Acquire connections for different protocols (should reuse)
    const conn1 = try multiplexer.acquireConnection(.dns_over_quic, .high, .high_frequency_trading);
    const stream_id1 = try conn1.getNextStreamId(.dns_over_quic);
    multiplexer.releaseConnection(conn1);
    
    const conn2 = try multiplexer.acquireConnection(.http3, .normal, .defi_api);
    try conn2.enableProtocol(.http3);
    const stream_id2 = try conn2.getNextStreamId(.http3);
    multiplexer.releaseConnection(conn2);
    
    // Verify protocol multiplexing
    try expect(stream_id1 != stream_id2);
    try expect(conn1.id == conn2.id or multiplexer.getStats().total_connections == 1);
    
    try tracker.checkForLeaks();
}

/// Test telemetry system
test "Telemetry: Metrics collection and monitoring" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    const telemetry_config = CryptoTelemetryConfig{
        .metrics_collection_interval_ms = 100,
        .max_metric_history = 10,
        .latency_warning_threshold_us = 1000,
        .latency_critical_threshold_us = 5000,
        .enable_json_export = true,
    };
    
    var telemetry = CryptoTelemetrySystem.init(tracker.allocator, telemetry_config);
    defer telemetry.deinit();
    
    // Record various crypto requests
    telemetry.recordRequest(.doq, .high, 500, 512); // DNS query
    telemetry.recordRequest(.http3, .critical, 2000, 1024); // Trading API
    telemetry.recordRequest(.grpc, .normal, 800, 256); // Service call
    telemetry.recordRequest(.custom, .critical, 10000, 64); // Should trigger alert
    
    // Record connections
    telemetry.recordConnection(true, true, true); // Zero-RTT success
    telemetry.recordConnection(true, true, false); // Zero-RTT failure
    
    // Collect metrics
    try telemetry.collectMetrics();
    
    // Verify metrics
    const summary = telemetry.getPerformanceSummary();
    try expect(summary.requests_per_second >= 0);
    try expect(summary.zero_rtt_success_rate >= 0.0 and summary.zero_rtt_success_rate <= 1.0);
    
    // Test JSON export
    var json_buffer = std.ArrayList(u8).init(tracker.allocator);
    defer json_buffer.deinit();
    
    try telemetry.exportJson(json_buffer.writer());
    try expect(json_buffer.items.len > 0);
    try expect(std.mem.indexOf(u8, json_buffer.items, "timestamp") != null);
    
    try tracker.checkForLeaks();
}

/// Performance stress test
test "Performance: High-frequency operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    // Test rapid session creation/destruction
    var session_mgr = try ZeroRttSessionManager.init(tracker.allocator);
    defer session_mgr.deinit();
    
    const iterations = 1000;
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        var secret: [32]u8 = undefined;
        std.crypto.random.bytes(&secret);
        
        const ticket = try session_mgr.createSessionTicket(secret);
        _ = session_mgr.validateSessionTicket(ticket.ticket_id, i);
    }
    
    // Verify no excessive memory growth
    try session_mgr.cleanupExpiredSessions();
    const stats = session_mgr.getStats();
    try expect(stats.active_sessions < iterations); // Should have cleaned up some
    
    try tracker.checkForLeaks();
}

/// Integration test: Full crypto trading simulation
test "Integration: Crypto trading workflow" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    // Initialize all v0.8.2 components
    const hybrid_config = HybridConfig{
        .enable_ml_kem = true,
        .enable_x25519 = true,
        .prefer_pq = true,
        .fallback_to_classical = true,
    };
    
    var pq_tls = try HybridPQTlsContext.init(tracker.allocator, false, hybrid_config);
    defer pq_tls.deinit();
    
    var session_mgr = try ZeroRttSessionManager.init(tracker.allocator);
    defer session_mgr.deinit();
    
    var congestion_ctrl = CryptoOptimizedCongestionController.init(
        tracker.allocator, 
        .bbr, 
        .high_frequency_trading
    );
    
    const pool_config = CryptoConnectionPoolConfig{
        .initial_pool_size = 10,
        .max_pool_size = 100,
        .enable_zero_rtt = true,
        .enable_post_quantum = true,
        .enable_protocol_multiplexing = true,
    };
    
    var multiplexer = CryptoConnectionMultiplexer.init(tracker.allocator, pool_config);
    defer multiplexer.deinit();
    
    const telemetry_config = CryptoTelemetryConfig{
        .metrics_collection_interval_ms = 50,
        .max_metric_history = 20,
    };
    
    var telemetry = CryptoTelemetrySystem.init(tracker.allocator, telemetry_config);
    defer telemetry.deinit();
    
    // Simulate trading workflow
    try pq_tls.initializeHandshake();
    
    // Create Zero-RTT session
    var secret: [32]u8 = undefined;
    std.crypto.random.bytes(&secret);
    const ticket = try session_mgr.createSessionTicket(secret);
    
    // Acquire trading connection
    const trading_conn = try multiplexer.acquireConnection(
        .custom, 
        .critical, 
        .high_frequency_trading
    );
    defer multiplexer.releaseConnection(trading_conn);
    
    // Simulate high-frequency trading
    var trade_count: u32 = 0;
    while (trade_count < 100) : (trade_count += 1) {
        // Check congestion control
        if (congestion_ctrl.canSend(256, .critical)) {
            congestion_ctrl.onPacketSent(256);
            
            // Simulate fast execution (500μs)
            congestion_ctrl.onPacketAcked(256, 500, .critical);
            
            // Record telemetry
            telemetry.recordRequest(.custom, .critical, 500, 256);
        }
    }
    
    // Collect final metrics
    try telemetry.collectMetrics();
    
    // Verify performance
    const summary = telemetry.getPerformanceSummary();
    try expect(summary.avg_latency_us < 10_000); // < 10ms average
    try expect(summary.requests_per_second > 10); // > 10 RPS
    
    const congestion_stats = congestion_ctrl.getCryptoStats();
    try expect(congestion_stats.algorithm == .bbr);
    try expect(congestion_stats.loss_rate < 0.1); // < 10% loss
    
    try tracker.checkForLeaks();
}

/// Comprehensive memory safety test
test "Memory Safety: Extensive allocation/deallocation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    // Test multiple allocation/deallocation cycles
    var cycle: u32 = 0;
    while (cycle < 10) : (cycle += 1) {
        // Create multiple contexts
        var contexts = std.ArrayList(*HybridPQTlsContext).init(tracker.allocator);
        defer contexts.deinit();
        
        const config = HybridConfig{
            .enable_ml_kem = true,
            .enable_x25519 = true,
            .prefer_pq = true,
            .fallback_to_classical = true,
        };
        
        var i: u32 = 0;
        while (i < 5) : (i += 1) {
            const ctx = try tracker.allocator.create(HybridPQTlsContext);
            ctx.* = try HybridPQTlsContext.init(tracker.allocator, i % 2 == 0, config);
            try contexts.append(ctx);
        }
        
        // Use contexts
        for (contexts.items) |ctx| {
            try ctx.initializeHandshake();
            _ = ctx.getSecurityLevel();
        }
        
        // Clean up
        for (contexts.items) |ctx| {
            ctx.deinit();
            tracker.allocator.destroy(ctx);
        }
    }
    
    try tracker.checkForLeaks();
}

/// Error handling and edge cases
test "Error Handling: Edge cases and recovery" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    // Test invalid configurations
    const invalid_config = HybridConfig{
        .enable_ml_kem = false,
        .enable_x25519 = false,
        .prefer_pq = true,
        .fallback_to_classical = false,
    };
    
    // Should handle gracefully
    var ctx = try HybridPQTlsContext.init(tracker.allocator, true, invalid_config);
    defer ctx.deinit();
    
    try ctx.initializeHandshake();
    
    // Test Zero-RTT with expired tickets
    var session_mgr = try ZeroRttSessionManager.init(tracker.allocator);
    defer session_mgr.deinit();
    
    // Create expired ticket (simulate)
    var secret: [32]u8 = undefined;
    std.crypto.random.bytes(&secret);
    var ticket = try session_mgr.createSessionTicket(secret);
    ticket.expiry_time = std.time.timestamp() - 3600; // 1 hour ago
    
    // Should reject expired ticket
    const result = session_mgr.validateSessionTicket(ticket.ticket_id, 12345);
    try expect(result == null);
    
    // Test congestion control with extreme values
    var controller = CryptoOptimizedCongestionController.init(
        tracker.allocator, 
        .bbr, 
        .high_frequency_trading
    );
    
    // Test with very large packet
    const large_packet: u32 = 1024 * 1024; // 1MB
    try expect(!controller.canSend(large_packet, .normal)); // Should reject
    
    // Test with zero RTT
    controller.onPacketAcked(1460, 0, .critical); // Zero RTT
    
    try tracker.checkForLeaks();
}

/// Benchmark basic operations
test "Benchmarks: Core operation performance" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var tracker = MemoryTracker.init(&gpa);
    
    const iterations = 1000;
    
    // Benchmark hybrid key generation
    {
        var timer = try std.time.Timer.start();
        
        const config = HybridConfig{
            .enable_ml_kem = true,
            .enable_x25519 = true,
            .prefer_pq = true,
            .fallback_to_classical = true,
        };
        
        var i: u32 = 0;
        while (i < 10) : (i += 1) { // Smaller iteration for key gen
            var ctx = try HybridPQTlsContext.init(tracker.allocator, i % 2 == 0, config);
            defer ctx.deinit();
            try ctx.initializeHandshake();
        }
        
        const elapsed_ns = timer.read();
        const avg_ns = elapsed_ns / 10;
        std.log.info("Hybrid key generation: {} ns average", .{avg_ns});
        
        // Should be reasonable performance (< 1ms average)
        try expect(avg_ns < 1_000_000);
    }
    
    // Benchmark Zero-RTT session operations
    {
        var session_mgr = try ZeroRttSessionManager.init(tracker.allocator);
        defer session_mgr.deinit();
        
        var timer = try std.time.Timer.start();
        
        var i: u32 = 0;
        while (i < iterations) : (i += 1) {
            var secret: [32]u8 = undefined;
            std.crypto.random.bytes(&secret);
            const ticket = try session_mgr.createSessionTicket(secret);
            _ = session_mgr.validateSessionTicket(ticket.ticket_id, i);
        }
        
        const elapsed_ns = timer.read();
        const avg_ns = elapsed_ns / iterations;
        std.log.info("Zero-RTT session ops: {} ns average", .{avg_ns});
        
        // Should be very fast (< 100μs average)
        try expect(avg_ns < 100_000);
    }
    
    // Benchmark congestion control updates
    {
        var controller = CryptoOptimizedCongestionController.init(
            tracker.allocator, 
            .bbr, 
            .high_frequency_trading
        );
        
        var timer = try std.time.Timer.start();
        
        var i: u32 = 0;
        while (i < iterations) : (i += 1) {
            controller.onPacketAcked(1460, 1000, .normal); // 1ms RTT
        }
        
        const elapsed_ns = timer.read();
        const avg_ns = elapsed_ns / iterations;
        std.log.info("Congestion control update: {} ns average", .{avg_ns});
        
        // Should be extremely fast (< 10μs average)
        try expect(avg_ns < 10_000);
    }
    
    try tracker.checkForLeaks();
}