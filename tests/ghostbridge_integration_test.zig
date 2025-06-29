//! GhostBridge Integration Tests
//!
//! Comprehensive tests for gRPC-over-QUIC implementation

const std = @import("std");
const zquic = @import("zquic");

const GhostBridge = zquic.Services.GhostBridge;
const GhostBridgeConfig = zquic.Services.GhostBridgeConfig;
const GrpcConnection = zquic.Services.GrpcConnection;
const GrpcStream = zquic.Services.GrpcStream;
const GrpcMethod = zquic.Services.GrpcRequest;
const ServiceRegistration = zquic.Services.ServiceRegistration;

test "GhostBridge initialization and configuration" {
    const allocator = std.testing.allocator;
    
    const config = GhostBridgeConfig{
        .port = 50051,
        .max_connections = 1000,
        .request_timeout_ms = 30000,
        .enable_discovery = true,
        .enable_post_quantum = true,
    };
    
    var bridge = try GhostBridge.init(allocator, config);
    defer bridge.deinit();
    
    try std.testing.expect(bridge.config.port == 50051);
    try std.testing.expect(bridge.config.max_connections == 1000);
    try std.testing.expect(bridge.config.enable_discovery);
    try std.testing.expect(bridge.config.enable_post_quantum);
    try std.testing.expect(!bridge.running);
}

test "service registration and discovery" {
    const allocator = std.testing.allocator;
    
    const config = GhostBridgeConfig{
        .port = 50052,
    };
    
    var bridge = try GhostBridge.init(allocator, config);
    defer bridge.deinit();
    
    // Register GhostChain services
    try bridge.registerService("ghostd", "localhost:50001", .ghostd);
    try bridge.registerService("walletd", "localhost:50002", .walletd);
    try bridge.registerService("edge-node-1", "localhost:50003", .edge_node);
    
    try std.testing.expect(bridge.services.count() == 3);
    
    // Check service health
    const ghostd_health = bridge.checkServiceHealth("ghostd");
    try std.testing.expect(ghostd_health == .unknown); // New service
    
    const invalid_health = bridge.checkServiceHealth("nonexistent");
    try std.testing.expect(invalid_health == .unknown);
    
    // Unregister service
    try bridge.unregisterService("edge-node-1");
    try std.testing.expect(bridge.services.count() == 2);
}

test "gRPC method creation and validation" {
    const allocator = std.testing.allocator;
    
    const method = try zquic.Services.GrpcMethod.init(allocator, "ghost.wallet", "GetBalance");
    defer method.deinit(allocator);
    
    try std.testing.expectEqualStrings("ghost.wallet", method.service);
    try std.testing.expectEqualStrings("GetBalance", method.method);
    try std.testing.expectEqualStrings("/ghost.wallet/GetBalance", method.full_path);
}

test "gRPC request and response handling" {
    const allocator = std.testing.allocator;
    
    const method = try zquic.Services.GrpcMethod.init(allocator, "ghost.wallet", "SendTransaction");
    defer method.deinit(allocator);
    
    const request_data = "{ \"to\": \"ghost1abc...\", \"amount\": \"100.0\" }";
    var request = try zquic.Services.GrpcRequest.init(allocator, method, request_data, 12345);
    defer request.deinit(allocator);
    
    // Add headers
    try request.addHeader(allocator, "authorization", "Bearer token123");
    try request.addHeader(allocator, "content-type", "application/json");
    
    try std.testing.expect(request.request_id == 12345);
    try std.testing.expect(request.headers.count() == 2);
    try std.testing.expectEqualStrings(request.body, request_data);
    
    // Create response
    const response_data = "{ \"transaction_id\": \"tx123\", \"status\": \"success\" }";
    var response = try zquic.Services.GrpcResponse.init(allocator, 0, response_data, 12345);
    defer response.deinit(allocator);
    
    try std.testing.expect(response.status_code == 0);
    try std.testing.expect(response.response_id == 12345);
    try std.testing.expectEqualStrings(response.body, response_data);
    try std.testing.expectEqualStrings(response.status_message, "OK");
}

test "bridge statistics and monitoring" {
    const allocator = std.testing.allocator;
    
    const config = GhostBridgeConfig{
        .port = 50053,
    };
    
    var bridge = try GhostBridge.init(allocator, config);
    defer bridge.deinit();
    
    // Initial stats
    try std.testing.expect(bridge.stats.total_connections == 0);
    try std.testing.expect(bridge.stats.active_connections == 0);
    try std.testing.expect(bridge.stats.requests_handled == 0);
    try std.testing.expect(bridge.stats.errors == 0);
    
    // Update stats
    bridge.updateStats();
    
    // Verify uptime is calculated
    try std.testing.expect(bridge.stats.uptime_seconds >= 0);
}

test "gRPC frame serialization" {
    const allocator = std.testing.allocator;
    
    // Test gRPC frame header
    const header = zquic.Services.GrpcFrameHeader{
        .message_type = .request,
        .compressed = 0,
        .reserved = 0,
        .length = std.mem.nativeToBig(u32, 100),
    };
    
    const header_bytes = std.mem.asBytes(&header);
    try std.testing.expect(header_bytes.len == @sizeOf(zquic.Services.GrpcFrameHeader));
    
    // Verify serialization
    const deserialized = std.mem.bytesAsValue(zquic.Services.GrpcFrameHeader, header_bytes);
    try std.testing.expect(deserialized.message_type == .request);
    try std.testing.expect(std.mem.bigToNative(u32, deserialized.length) == 100);
}

test "service type detection and classification" {
    const allocator = std.testing.allocator;
    
    const config = GhostBridgeConfig{};
    var bridge = try GhostBridge.init(allocator, config);
    defer bridge.deinit();
    
    // Test service type classification
    try bridge.registerService("ghostd", "localhost:50001", .ghostd);
    try bridge.registerService("walletd", "localhost:50002", .walletd);
    try bridge.registerService("edge-proxy", "localhost:50003", .edge_node);
    try bridge.registerService("custom-service", "localhost:50004", .other);
    
    // Verify services are registered with correct types
    const ghostd_service = bridge.services.get("ghostd").?;
    try std.testing.expect(ghostd_service.service_type == .ghostd);
    
    const walletd_service = bridge.services.get("walletd").?;
    try std.testing.expect(walletd_service.service_type == .walletd);
    
    const edge_service = bridge.services.get("edge-proxy").?;
    try std.testing.expect(edge_service.service_type == .edge_node);
    
    const custom_service = bridge.services.get("custom-service").?;
    try std.testing.expect(custom_service.service_type == .other);
}

test "error handling and recovery" {
    const allocator = std.testing.allocator;
    
    const config = GhostBridgeConfig{
        .port = 50054,
    };
    
    var bridge = try GhostBridge.init(allocator, config);
    defer bridge.deinit();
    
    // Test invalid operations
    try std.testing.expectError(error.OutOfMemory, bridge.unregisterService("nonexistent"));
    
    // Test service health for non-existent service
    const health = bridge.checkServiceHealth("nonexistent");
    try std.testing.expect(health == .unknown);
}

test "concurrent operations simulation" {
    const allocator = std.testing.allocator;
    
    const config = GhostBridgeConfig{
        .port = 50055,
        .max_connections = 100,
    };
    
    var bridge = try GhostBridge.init(allocator, config);
    defer bridge.deinit();
    
    // Register multiple services
    for (0..10) |i| {
        const service_name = try std.fmt.allocPrint(allocator, "service-{d}", .{i});
        defer allocator.free(service_name);
        
        const endpoint = try std.fmt.allocPrint(allocator, "localhost:{d}", .{50100 + i});
        defer allocator.free(endpoint);
        
        try bridge.registerService(service_name, endpoint, .other);
    }
    
    try std.testing.expect(bridge.services.count() == 10);
    
    // Simulate service health updates
    bridge.updateStats();
    
    // Cleanup all services
    for (0..10) |i| {
        const service_name = try std.fmt.allocPrint(allocator, "service-{d}", .{i});
        defer allocator.free(service_name);
        
        try bridge.unregisterService(service_name);
    }
    
    try std.testing.expect(bridge.services.count() == 0);
}

test "post-quantum security configuration" {
    const allocator = std.testing.allocator;
    
    // Test with post-quantum enabled
    const pq_config = GhostBridgeConfig{
        .port = 50056,
        .enable_post_quantum = true,
    };
    
    var pq_bridge = try GhostBridge.init(allocator, pq_config);
    defer pq_bridge.deinit();
    
    try std.testing.expect(pq_bridge.config.enable_post_quantum);
    
    // Test with post-quantum disabled
    const classical_config = GhostBridgeConfig{
        .port = 50057,
        .enable_post_quantum = false,
    };
    
    var classical_bridge = try GhostBridge.init(allocator, classical_config);
    defer classical_bridge.deinit();
    
    try std.testing.expect(!classical_bridge.config.enable_post_quantum);
}

test "production configuration validation" {
    const allocator = std.testing.allocator;
    
    // Production-grade configuration
    const prod_config = GhostBridgeConfig{
        .address = "0.0.0.0",
        .port = 443,
        .max_connections = 10000,
        .request_timeout_ms = 60000,
        .enable_discovery = true,
        .cert_path = "/etc/ssl/certs/ghostbridge.pem",
        .key_path = "/etc/ssl/private/ghostbridge.key",
        .enable_post_quantum = true,
    };
    
    var bridge = try GhostBridge.init(allocator, prod_config);
    defer bridge.deinit();
    
    try std.testing.expect(bridge.config.port == 443);
    try std.testing.expect(bridge.config.max_connections == 10000);
    try std.testing.expect(bridge.config.request_timeout_ms == 60000);
    try std.testing.expect(bridge.config.enable_discovery);
    try std.testing.expect(bridge.config.enable_post_quantum);
    try std.testing.expectEqualStrings(bridge.config.address, "0.0.0.0");
}

test "memory management and cleanup" {
    const allocator = std.testing.allocator;
    
    const config = GhostBridgeConfig{
        .port = 50058,
    };
    
    var bridge = try GhostBridge.init(allocator, config);
    
    // Register services
    try bridge.registerService("test-service-1", "localhost:50001", .other);
    try bridge.registerService("test-service-2", "localhost:50002", .other);
    
    // Verify services are registered
    try std.testing.expect(bridge.services.count() == 2);
    
    // Cleanup should handle all allocated memory
    bridge.deinit();
    
    // No memory leaks should occur (verified by test allocator)
}