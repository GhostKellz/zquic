//! GhostBridge FFI - gRPC over QUIC transport for Rust services
//!
//! Provides FFI interface for ghostd/walletd to communicate via gRPC over QUIC
//! Now with real implementation using production gRPC-over-QUIC

const std = @import("std");
const zquic = @import("../root.zig");
const GhostBridge = @import("../services/ghostbridge.zig").GhostBridge;
const GhostBridgeConfig = @import("../services/ghostbridge.zig").GhostBridgeConfig;
const GrpcConnection = @import("../services/ghostbridge.zig").GrpcConnection;
const GrpcStream = @import("../services/ghostbridge.zig").GrpcStream;
const GrpcMethod = @import("../services/ghostbridge.zig").GrpcMethod;
const GrpcRequestInternal = @import("../services/ghostbridge.zig").GrpcRequest;
const GrpcResponseInternal = @import("../services/ghostbridge.zig").GrpcResponse;
const ServiceRegistration = @import("../services/ghostbridge.zig").ServiceRegistration;

// Global allocator for FFI - in production, this should be configurable
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

/// Opaque pointer types for FFI safety
/// These map to real implementation types internally
const GhostBridgeOpaque = anyopaque;
const GrpcConnectionOpaque = anyopaque;
const GrpcStreamOpaque = anyopaque;

/// FFI-compatible bridge configuration
pub const BridgeConfig = extern struct {
    /// Listen port for gRPC services
    port: u16,
    /// Maximum concurrent gRPC connections
    max_connections: u32,
    /// gRPC request timeout in milliseconds
    request_timeout_ms: u32,
    /// Enable service discovery (1 = true, 0 = false)
    enable_discovery: u8,
    /// Reserved for future use
    reserved: [32]u8,
};

/// gRPC request structure
pub const GrpcRequest = extern struct {
    /// Service name (null-terminated)
    service: [64]u8,
    /// Method name (null-terminated)
    method: [64]u8,
    /// Request data
    data: [*]const u8,
    /// Data length
    data_len: usize,
    /// Request ID for correlation
    request_id: u64,
};

/// gRPC response structure
pub const GrpcResponse = extern struct {
    /// Response data
    data: [*]u8,
    /// Data length
    data_len: usize,
    /// Status code (0 = OK, >0 = error)
    status: u32,
    /// Error message if status != 0
    error_message: [256]u8,
    /// Response ID (matches request)
    response_id: u64,
};

/// Service registration info
pub const ServiceInfo = extern struct {
    /// Service name
    name: [64]u8,
    /// Endpoint address
    endpoint: [128]u8,
    /// Service type (0 = ghostd, 1 = walletd, 2 = other)
    service_type: u8,
    /// Health status (0 = unknown, 1 = healthy, 2 = unhealthy)
    health_status: u8,
};

/// Initialize GhostBridge with configuration
/// Returns: Opaque bridge pointer or null on failure
pub export fn ghostbridge_init(config: *const BridgeConfig) callconv(.C) ?*GhostBridgeOpaque {
    // Convert FFI config to internal config
    const bridge_config = GhostBridgeConfig{
        .port = config.port,
        .max_connections = config.max_connections,
        .request_timeout_ms = config.request_timeout_ms,
        .enable_discovery = config.enable_discovery != 0,
        .enable_post_quantum = true, // Always enable PQ crypto
    };
    
    // Create real GhostBridge instance
    const bridge = GhostBridge.init(allocator, bridge_config) catch |err| {
        std.log.err("Failed to initialize GhostBridge: {}", .{err});
        return null;
    };
    
    std.log.info("GhostBridge initialized on port {d}", .{config.port});
    return @ptrCast(bridge);
}

/// Destroy GhostBridge and free resources
pub export fn ghostbridge_destroy(bridge: ?*GhostBridgeOpaque) callconv(.C) void {
    if (bridge) |b| {
        const real_bridge: *GhostBridge = @ptrCast(@alignCast(b));
        real_bridge.deinit();
        std.log.info("GhostBridge destroyed", .{});
    }
}

/// Start GhostBridge server
/// Returns: 0 on success, -1 on failure
pub export fn ghostbridge_start(bridge: ?*GhostBridgeOpaque) callconv(.C) c_int {
    if (bridge) |b| {
        const real_bridge: *GhostBridge = @ptrCast(@alignCast(b));
        real_bridge.start() catch |err| {
            std.log.err("Failed to start GhostBridge: {}", .{err});
            return -1;
        };
        return 0;
    }
    return -1;
}

/// Stop GhostBridge server
pub export fn ghostbridge_stop(bridge: ?*GhostBridgeOpaque) callconv(.C) void {
    if (bridge) |b| {
        const real_bridge: *GhostBridge = @ptrCast(@alignCast(b));
        real_bridge.stop();
    }
}

/// Register a service with GhostBridge
/// Returns: 0 on success, -1 on failure
pub export fn ghostbridge_register_service(bridge: ?*GhostBridgeOpaque, name: [*:0]const u8, endpoint: [*:0]const u8) callconv(.C) c_int {
    if (bridge) |b| {
        const real_bridge: *GhostBridge = @ptrCast(@alignCast(b));
        const name_str = std.mem.span(name);
        const endpoint_str = std.mem.span(endpoint);
        
        // Determine service type from name
        const service_type: ServiceRegistration.ServiceType = blk: {
            if (std.mem.eql(u8, name_str, "ghostd")) break :blk .ghostd;
            if (std.mem.eql(u8, name_str, "walletd")) break :blk .walletd;
            if (std.mem.indexOf(u8, name_str, "edge")) |_| break :blk .edge_node;
            break :blk .other;
        };
        
        real_bridge.registerService(name_str, endpoint_str, service_type) catch |err| {
            std.log.err("Failed to register service {s}: {}", .{ name_str, err });
            return -1;
        };
        
        std.log.info("Registered service {s} at {s}", .{ name_str, endpoint_str });
        return 0;
    }
    return -1;
}

/// Unregister a service from GhostBridge
/// Returns: 0 on success, -1 on failure
pub export fn ghostbridge_unregister_service(bridge: ?*GhostBridgeOpaque, name: [*:0]const u8) callconv(.C) c_int {
    if (bridge) |b| {
        const real_bridge: *GhostBridge = @ptrCast(@alignCast(b));
        const name_str = std.mem.span(name);
        
        real_bridge.unregisterService(name_str) catch |err| {
            std.log.err("Failed to unregister service {s}: {}", .{ name_str, err });
            return -1;
        };
        
        return 0;
    }
    return -1;
}

/// Create gRPC connection to a service
/// Returns: Opaque connection pointer or null on failure
pub export fn ghostbridge_create_grpc_connection(bridge: ?*GhostBridgeOpaque, service_name: [*:0]const u8) callconv(.C) ?*GrpcConnectionOpaque {
    if (bridge) |b| {
        const real_bridge: *GhostBridge = @ptrCast(@alignCast(b));
        const name_str = std.mem.span(service_name);
        
        const connection = real_bridge.createConnection(name_str) catch |err| {
            std.log.err("Failed to create connection to {s}: {}", .{ name_str, err });
            return null;
        };
        
        std.log.info("Created gRPC connection to {s}", .{name_str});
        return @ptrCast(connection);
    }
    return null;
}

/// Close gRPC connection
pub export fn ghostbridge_close_grpc_connection(conn: ?*GrpcConnectionOpaque) callconv(.C) void {
    if (conn) |c| {
        const real_conn: *GrpcConnection = @ptrCast(@alignCast(c));
        // Note: Connection cleanup is handled by GhostBridge.closeConnection()
        // This would need the bridge reference to properly clean up
        std.log.info("Closing gRPC connection {d}", .{real_conn.connection_id});
    }
}

/// Send gRPC request
/// Returns: Pointer to response or null on failure (caller must free)
pub export fn ghostbridge_send_grpc_request(conn: ?*GrpcConnectionOpaque, request: *const GrpcRequest) callconv(.C) ?*GrpcResponse {
    if (conn) |c| {
        const real_conn: *GrpcConnection = @ptrCast(@alignCast(c));
        
        // Convert FFI request to internal format
        const service_str = std.mem.span(@as([*:0]const u8, @ptrCast(&request.service)));
        const method_str = std.mem.span(@as([*:0]const u8, @ptrCast(&request.method)));
        const request_data = request.data[0..request.data_len];
        
        const grpc_method = GrpcMethod.init(allocator, service_str, method_str) catch {
            std.log.err("Failed to create gRPC method", .{});
            return null;
        };
        defer grpc_method.deinit(allocator);
        
        // Send unary request
        const internal_response = real_conn.sendUnaryRequest(grpc_method, request_data) catch |err| {
            std.log.err("Failed to send gRPC request: {}", .{err});
            return null;
        };
        
        // Convert internal response to FFI format
        const ffi_response = allocator.create(GrpcResponse) catch return null;
        ffi_response.* = GrpcResponse{
            .data = internal_response.body.ptr,
            .data_len = internal_response.body.len,
            .status = internal_response.status_code,
            .error_message = [_]u8{0} ** 256,
            .response_id = internal_response.response_id,
        };
        
        // Copy status message
        const msg_len = @min(internal_response.status_message.len, 255);
        @memcpy(ffi_response.error_message[0..msg_len], internal_response.status_message[0..msg_len]);
        
        std.log.info("Sent gRPC request to {s}/{s}", .{ service_str, method_str });
        return ffi_response;
    }
    return null;
}

/// Free gRPC response memory
pub export fn ghostbridge_free_grpc_response(response: ?*GrpcResponse) callconv(.C) void {
    if (response) |resp| {
        // Free the response data
        if (resp.data_len > 0) {
            allocator.free(resp.data[0..resp.data_len]);
        }
        allocator.destroy(resp);
    }
}

/// Create bidirectional gRPC stream
/// Returns: Opaque stream pointer or null on failure
pub export fn ghostbridge_create_grpc_stream(conn: ?*GrpcConnectionOpaque, service: [*:0]const u8, method: [*:0]const u8) callconv(.C) ?*GrpcStreamOpaque {
    if (conn) |c| {
        const real_conn: *GrpcConnection = @ptrCast(@alignCast(c));
        const service_str = std.mem.span(service);
        const method_str = std.mem.span(method);
        
        const grpc_method = GrpcMethod.init(allocator, service_str, method_str) catch {
            std.log.err("Failed to create gRPC method for stream", .{});
            return null;
        };
        
        const stream = real_conn.createStream(grpc_method) catch |err| {
            grpc_method.deinit(allocator);
            std.log.err("Failed to create gRPC stream: {}", .{err});
            return null;
        };
        
        std.log.info("Created gRPC stream for {s}/{s}", .{ service_str, method_str });
        return @ptrCast(stream);
    }
    return null;
}

/// Send data on gRPC stream
/// Returns: Number of bytes sent, -1 on error
pub export fn ghostbridge_stream_send(stream: ?*GrpcStreamOpaque, data: [*]const u8, len: usize) callconv(.C) isize {
    if (stream) |s| {
        const real_stream: *GrpcStream = @ptrCast(@alignCast(s));
        const message_data = data[0..len];
        
        real_stream.sendMessage(.stream_data, message_data) catch |err| {
            std.log.err("Failed to send stream data: {}", .{err});
            return -1;
        };
        
        return @intCast(len);
    }
    return -1;
}

/// Receive data from gRPC stream
/// Returns: Number of bytes received, 0 for no data, -1 on error
pub export fn ghostbridge_stream_receive(stream: ?*GrpcStreamOpaque, buffer: [*]u8, max_len: usize) callconv(.C) isize {
    if (stream) |s| {
        const real_stream: *GrpcStream = @ptrCast(@alignCast(s));
        
        if (real_stream.receiveMessage()) |message| {
            defer message.deinit(allocator);
            
            if (message.message_type == .stream_data) {
                const copy_len = @min(message.data.len, max_len);
                @memcpy(buffer[0..copy_len], message.data[0..copy_len]);
                return @intCast(copy_len);
            } else if (message.message_type == .stream_end) {
                return 0; // Stream ended
            }
        } else |err| {
            if (err == error.WouldBlock) {
                return 0; // No data available
            }
            std.log.err("Failed to receive stream data: {}", .{err});
            return -1;
        }
    }
    return -1;
}

/// Close gRPC stream
pub export fn ghostbridge_close_grpc_stream(stream: ?*GrpcStreamOpaque) callconv(.C) void {
    if (stream) |s| {
        const real_stream: *GrpcStream = @ptrCast(@alignCast(s));
        real_stream.close() catch |err| {
            std.log.err("Failed to close gRPC stream: {}", .{err});
        };
        std.log.info("Closed gRPC stream {d}", .{real_stream.stream_id});
    }
}

/// Get list of registered services
/// Returns: Number of services found, -1 on error
pub export fn ghostbridge_get_services(bridge: ?*GhostBridgeOpaque, services: [*]ServiceInfo, max_services: usize) callconv(.C) c_int {
    if (bridge) |b| {
        const real_bridge: *GhostBridge = @ptrCast(@alignCast(b));
        
        // Get services from bridge
        const bridge_services = real_bridge.getServices();
        const count = @min(bridge_services.len, max_services);
        
        // Convert to FFI format
        for (bridge_services[0..count], 0..) |service, i| {
            var service_info = &services[i];
            
            // Clear and copy service name
            @memset(&service_info.name, 0);
            const name_len = @min(service.name.len, 63);
            @memcpy(service_info.name[0..name_len], service.name[0..name_len]);
            
            // Clear and copy endpoint
            @memset(&service_info.endpoint, 0);
            const endpoint_len = @min(service.endpoint.len, 127);
            @memcpy(service_info.endpoint[0..endpoint_len], service.endpoint[0..endpoint_len]);
            
            // Convert service type
            service_info.service_type = switch (service.service_type) {
                .ghostd => 0,
                .walletd => 1,
                .edge_node => 2,
                .other => 3,
            };
            
            // Convert health status
            service_info.health_status = switch (service.health_status) {
                .unknown => 0,
                .healthy => 1,
                .unhealthy => 2,
                .maintenance => 2,
            };
        }
        
        return @intCast(count);
    }
    return -1;
}

/// Check service health
/// Returns: Health status (0 = unknown, 1 = healthy, 2 = unhealthy)
pub export fn ghostbridge_check_service_health(bridge: ?*GhostBridgeOpaque, service_name: [*:0]const u8) callconv(.C) u8 {
    if (bridge) |b| {
        const real_bridge: *GhostBridge = @ptrCast(@alignCast(b));
        const name_str = std.mem.span(service_name);
        
        const health = real_bridge.checkServiceHealth(name_str);
        return switch (health) {
            .unknown => 0,
            .healthy => 1,
            .unhealthy => 2,
            .maintenance => 2,
        };
    }
    return 0;
}

/// Set service health callback
pub export fn ghostbridge_set_health_callback(bridge: ?*GhostBridge, callback: ?*const fn (service_name: [*:0]const u8, status: u8) callconv(.C) void) callconv(.C) void {
    _ = bridge;
    _ = callback;

    // TODO: Implement callback registration
}

/// Get bridge statistics
pub export fn ghostbridge_get_stats(bridge: ?*GhostBridgeOpaque, total_connections: *u64, active_connections: *u32, requests_handled: *u64, errors: *u64) callconv(.C) c_int {
    if (bridge) |b| {
        const real_bridge: *GhostBridge = @ptrCast(@alignCast(b));
        
        // Update stats first
        real_bridge.updateStats();
        
        // Return real statistics
        total_connections.* = real_bridge.stats.total_connections;
        active_connections.* = real_bridge.stats.active_connections;
        requests_handled.* = real_bridge.stats.requests_handled;
        errors.* = real_bridge.stats.errors;
        
        return 0;
    }
    return -1;
}

/// Testing function for FFI validation
pub export fn ghostbridge_test_echo(input: [*:0]const u8) callconv(.C) [*:0]const u8 {
    _ = input;
    return "GhostBridge FFI Test OK";
}
