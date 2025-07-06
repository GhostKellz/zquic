//! GhostBridge - gRPC over QUIC Transport
//!
//! Provides production gRPC relay functionality for GhostChain ecosystem services
//! Enables ghostd ↔ walletd ↔ edge nodes communication over post-quantum QUIC

const std = @import("std");
const zquic = @import("../root.zig");
const zcrypto = @import("zcrypto");

const QuicConnection = zquic.Connection.Connection;
const QuicStream = zquic.Stream.Stream;
const Http3Server = zquic.Http3.Http3Server;
const ServerConfig = zquic.Http3.ServerConfig;
const Error = zquic.Error;

/// GhostBridge configuration
pub const GhostBridgeConfig = struct {
    /// Listen address
    address: []const u8 = "127.0.0.1",
    /// Listen port for gRPC services
    port: u16 = 50051,
    /// Maximum concurrent gRPC connections
    max_connections: u32 = 1000,
    /// gRPC request timeout in milliseconds
    request_timeout_ms: u32 = 30000,
    /// Enable service discovery
    enable_discovery: bool = true,
    /// Certificate path for TLS
    cert_path: ?[]const u8 = null,
    /// Private key path for TLS
    key_path: ?[]const u8 = null,
    /// Enable post-quantum crypto
    enable_post_quantum: bool = true,
};

/// gRPC message types
pub const GrpcMessageType = enum(u8) {
    request = 0,
    response = 1,
    stream_data = 2,
    stream_end = 3,
    grpc_error = 4,
};

/// gRPC frame header
pub const GrpcFrameHeader = packed struct {
    /// Frame type
    message_type: GrpcMessageType,
    /// Compression flag (0 = none, 1 = gzip)
    compressed: u1,
    /// Reserved flags
    reserved: u6,
    /// Message length (network byte order)
    length: u32,
};

/// gRPC method metadata
pub const GrpcMethod = struct {
    service: []const u8,
    method: []const u8,
    full_path: []const u8, // "/service/method"
    
    pub fn init(allocator: std.mem.Allocator, service: []const u8, method: []const u8) !GrpcMethod {
        const full_path = try std.fmt.allocPrint(allocator, "/{s}/{s}", .{ service, method });
        return GrpcMethod{
            .service = try allocator.dupe(u8, service),
            .method = try allocator.dupe(u8, method),
            .full_path = full_path,
        };
    }
    
    pub fn deinit(self: *const GrpcMethod, allocator: std.mem.Allocator) void {
        allocator.free(self.service);
        allocator.free(self.method);
        allocator.free(self.full_path);
    }
};

/// gRPC request context
pub const GrpcRequest = struct {
    method: GrpcMethod,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    request_id: u64,
    timeout_ms: u32,
    
    pub fn init(allocator: std.mem.Allocator, method: GrpcMethod, body: []const u8, request_id: u64) !GrpcRequest {
        return GrpcRequest{
            .method = method,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = try allocator.dupe(u8, body),
            .request_id = request_id,
            .timeout_ms = 30000,
        };
    }
    
    pub fn deinit(self: *GrpcRequest, allocator: std.mem.Allocator) void {
        self.method.deinit(allocator);
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        allocator.free(self.body);
    }
    
    pub fn addHeader(self: *GrpcRequest, allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
        const owned_key = try allocator.dupe(u8, key);
        const owned_value = try allocator.dupe(u8, value);
        try self.headers.put(owned_key, owned_value);
    }
};

/// gRPC response context
pub const GrpcResponse = struct {
    status_code: u32,
    status_message: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    response_id: u64,
    
    pub fn init(allocator: std.mem.Allocator, status_code: u32, body: []const u8, response_id: u64) !GrpcResponse {
        return GrpcResponse{
            .status_code = status_code,
            .status_message = try allocator.dupe(u8, getStatusMessage(status_code)),
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = try allocator.dupe(u8, body),
            .response_id = response_id,
        };
    }
    
    pub fn deinit(self: *GrpcResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.status_message);
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        allocator.free(self.body);
    }
    
    fn getStatusMessage(status_code: u32) []const u8 {
        return switch (status_code) {
            0 => "OK",
            1 => "CANCELLED",
            2 => "UNKNOWN",
            3 => "INVALID_ARGUMENT",
            4 => "DEADLINE_EXCEEDED",
            5 => "NOT_FOUND",
            6 => "ALREADY_EXISTS",
            7 => "PERMISSION_DENIED",
            8 => "RESOURCE_EXHAUSTED",
            9 => "FAILED_PRECONDITION",
            10 => "ABORTED",
            11 => "OUT_OF_RANGE",
            12 => "UNIMPLEMENTED",
            13 => "INTERNAL",
            14 => "UNAVAILABLE",
            15 => "DATA_LOSS",
            16 => "UNAUTHENTICATED",
            else => "UNKNOWN_STATUS",
        };
    }
};

/// Service registration information
pub const ServiceRegistration = struct {
    name: []const u8,
    endpoint: []const u8,
    service_type: ServiceType,
    health_status: HealthStatus,
    last_heartbeat: i64,
    
    pub const ServiceType = enum {
        ghostd,
        walletd,
        edge_node,
        other,
    };
    
    pub const HealthStatus = enum {
        unknown,
        healthy,
        unhealthy,
        maintenance,
    };
    
    pub fn init(allocator: std.mem.Allocator, name: []const u8, endpoint: []const u8, service_type: ServiceType) !ServiceRegistration {
        return ServiceRegistration{
            .name = try allocator.dupe(u8, name),
            .endpoint = try allocator.dupe(u8, endpoint),
            .service_type = service_type,
            .health_status = .unknown,
            .last_heartbeat = std.time.timestamp(),
        };
    }
    
    pub fn deinit(self: *const ServiceRegistration, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.endpoint);
    }
};

/// gRPC stream context
pub const GrpcStream = struct {
    stream_id: u64,
    method: GrpcMethod,
    quic_stream: *QuicStream,
    state: StreamState,
    send_buffer: std.ArrayList(u8),
    recv_buffer: std.ArrayList(u8),
    allocator: std.mem.Allocator,
    
    const StreamState = enum {
        open,
        half_closed_local,
        half_closed_remote,
        closed,
    };
    
    pub fn init(allocator: std.mem.Allocator, stream_id: u64, method: GrpcMethod, quic_stream: *QuicStream) !*GrpcStream {
        const stream = try allocator.create(GrpcStream);
        stream.* = GrpcStream{
            .stream_id = stream_id,
            .method = method,
            .quic_stream = quic_stream,
            .state = .open,
            .send_buffer = std.ArrayList(u8).init(allocator),
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .allocator = allocator,
        };
        return stream;
    }
    
    pub fn deinit(self: *GrpcStream) void {
        self.method.deinit(self.allocator);
        self.send_buffer.deinit();
        self.recv_buffer.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn sendMessage(self: *GrpcStream, message_type: GrpcMessageType, data: []const u8) !void {
        // Create gRPC frame header
        const header = GrpcFrameHeader{
            .message_type = message_type,
            .compressed = 0,
            .reserved = 0,
            .length = std.mem.nativeToBig(u32, @intCast(data.len)),
        };
        
        // Serialize header
        const header_bytes = std.mem.asBytes(&header);
        try self.send_buffer.appendSlice(header_bytes);
        try self.send_buffer.appendSlice(data);
        
        // Send via QUIC stream
        try self.quic_stream.send(self.send_buffer.items);
        self.send_buffer.clearRetainingCapacity();
    }
    
    pub fn receiveMessage(self: *GrpcStream) !?GrpcMessage {
        // Try to receive data from QUIC stream
        var temp_buffer: [8192]u8 = undefined;
        const bytes_received = self.quic_stream.receive(&temp_buffer) catch |err| switch (err) {
            error.WouldBlock => return null,
            else => return err,
        };
        
        if (bytes_received == 0) return null;
        
        try self.recv_buffer.appendSlice(temp_buffer[0..bytes_received]);
        
        // Check if we have a complete message
        if (self.recv_buffer.items.len < @sizeOf(GrpcFrameHeader)) return null;
        
        const header = std.mem.bytesAsValue(GrpcFrameHeader, self.recv_buffer.items[0..@sizeOf(GrpcFrameHeader)]);
        const message_length = std.mem.bigToNative(u32, header.length);
        const total_length = @sizeOf(GrpcFrameHeader) + message_length;
        
        if (self.recv_buffer.items.len < total_length) return null;
        
        // Extract message data
        const message_data = self.recv_buffer.items[@sizeOf(GrpcFrameHeader)..total_length];
        const message = GrpcMessage{
            .message_type = header.message_type,
            .compressed = header.compressed == 1,
            .data = try self.allocator.dupe(u8, message_data),
        };
        
        // Remove processed data from buffer
        std.mem.copy(u8, self.recv_buffer.items, self.recv_buffer.items[total_length..]);
        self.recv_buffer.shrinkRetainingCapacity(self.recv_buffer.items.len - total_length);
        
        return message;
    }
    
    pub fn close(self: *GrpcStream) !void {
        if (self.state != .closed) {
            try self.sendMessage(.stream_end, &[_]u8{});
            self.state = .closed;
        }
    }
};

/// gRPC message
pub const GrpcMessage = struct {
    message_type: GrpcMessageType,
    compressed: bool,
    data: []const u8,
    
    pub fn deinit(self: *const GrpcMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

/// gRPC connection
pub const GrpcConnection = struct {
    connection_id: u64,
    quic_connection: *QuicConnection,
    streams: std.HashMap(u64, *GrpcStream, std.hash_map.DefaultContext(u64), std.hash_map.default_max_load_percentage),
    next_stream_id: u64,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, connection_id: u64, quic_connection: *QuicConnection) !*GrpcConnection {
        const conn = try allocator.create(GrpcConnection);
        conn.* = GrpcConnection{
            .connection_id = connection_id,
            .quic_connection = quic_connection,
            .streams = std.HashMap(u64, *GrpcStream, std.hash_map.DefaultContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .next_stream_id = 1,
            .allocator = allocator,
        };
        return conn;
    }
    
    pub fn deinit(self: *GrpcConnection) void {
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.streams.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn createStream(self: *GrpcConnection, method: GrpcMethod) !*GrpcStream {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 2; // Increment by 2 for client-initiated streams
        
        // Create new QUIC stream
        const quic_stream = try self.quic_connection.openStream(stream_id);
        
        // Create gRPC stream wrapper
        const grpc_stream = try GrpcStream.init(self.allocator, stream_id, method, quic_stream);
        
        try self.streams.put(stream_id, grpc_stream);
        return grpc_stream;
    }
    
    pub fn closeStream(self: *GrpcConnection, stream_id: u64) !void {
        if (self.streams.get(stream_id)) |stream| {
            try stream.close();
            stream.deinit();
            _ = self.streams.remove(stream_id);
        }
    }
    
    pub fn sendUnaryRequest(self: *GrpcConnection, method: GrpcMethod, request_data: []const u8) !GrpcResponse {
        const stream = try self.createStream(method);
        defer self.closeStream(stream.stream_id) catch {};
        
        // Send request
        try stream.sendMessage(.request, request_data);
        
        // Wait for response (simplified - would need proper async handling)
        var attempts: u32 = 0;
        while (attempts < 1000) : (attempts += 1) {
            if (try stream.receiveMessage()) |message| {
                defer message.deinit(self.allocator);
                
                if (message.message_type == .response) {
                    return GrpcResponse.init(self.allocator, 0, message.data, stream.stream_id);
                }
            }
            std.time.sleep(1000000); // 1ms sleep
        }
        
        return Error.ZquicError.NetworkError;
    }
};

/// GhostBridge server statistics
pub const BridgeStats = struct {
    total_connections: u64 = 0,
    active_connections: u32 = 0,
    requests_handled: u64 = 0,
    errors: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    uptime_seconds: u64 = 0,
    start_time: i64,
    
    pub fn init() BridgeStats {
        return BridgeStats{
            .start_time = std.time.timestamp(),
        };
    }
    
    pub fn updateUptime(self: *BridgeStats) void {
        self.uptime_seconds = @intCast(std.time.timestamp() - self.start_time);
    }
};

/// Main GhostBridge implementation
pub const GhostBridge = struct {
    config: GhostBridgeConfig,
    server: ?*Http3Server,
    services: std.StringHashMap(ServiceRegistration),
    connections: std.HashMap(u64, *GrpcConnection, std.hash_map.DefaultContext(u64), std.hash_map.default_max_load_percentage),
    next_connection_id: u64,
    stats: BridgeStats,
    allocator: std.mem.Allocator,
    running: bool,
    
    pub fn init(allocator: std.mem.Allocator, config: GhostBridgeConfig) !*GhostBridge {
        const bridge = try allocator.create(GhostBridge);
        bridge.* = GhostBridge{
            .config = config,
            .server = null,
            .services = std.StringHashMap(ServiceRegistration).init(allocator),
            .connections = std.HashMap(u64, *GrpcConnection, std.hash_map.DefaultContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .next_connection_id = 1,
            .stats = BridgeStats.init(),
            .allocator = allocator,
            .running = false,
        };
        return bridge;
    }
    
    pub fn deinit(self: *GhostBridge) void {
        self.stop();
        
        // Clean up services
        var service_iterator = self.services.iterator();
        while (service_iterator.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.services.deinit();
        
        // Clean up connections
        var conn_iterator = self.connections.iterator();
        while (conn_iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.connections.deinit();
        
        self.allocator.destroy(self);
    }
    
    pub fn start(self: *GhostBridge) !void {
        if (self.running) return;
        
        // Create HTTP/3 server for gRPC-over-QUIC
        const server_config = ServerConfig{
            .address = self.config.address,
            .port = self.config.port,
            .cert_path = self.config.cert_path orelse "ghostbridge.pem",
            .key_path = self.config.key_path orelse "ghostbridge.key",
            .max_concurrent_streams = self.config.max_connections,
            .initial_window_size = 1024 * 1024,
            .enable_0rtt = true,
            .idle_timeout_ms = self.config.request_timeout_ms,
        };
        
        self.server = try Http3Server.init(self.allocator, server_config);
        
        // Register gRPC handler
        // TODO: Integrate with HTTP/3 server routing
        
        self.running = true;
        std.log.info("GhostBridge started on {s}:{d}", .{ self.config.address, self.config.port });
    }
    
    pub fn stop(self: *GhostBridge) void {
        if (!self.running) return;
        
        if (self.server) |server| {
            server.deinit();
            self.allocator.destroy(server);
            self.server = null;
        }
        
        self.running = false;
        std.log.info("GhostBridge stopped", .{});
    }
    
    pub fn registerService(self: *GhostBridge, name: []const u8, endpoint: []const u8, service_type: ServiceRegistration.ServiceType) !void {
        const service = try ServiceRegistration.init(self.allocator, name, endpoint, service_type);
        const owned_name = try self.allocator.dupe(u8, name);
        try self.services.put(owned_name, service);
        
        std.log.info("Registered service '{s}' at {s}", .{ name, endpoint });
    }
    
    pub fn unregisterService(self: *GhostBridge, name: []const u8) !void {
        if (self.services.fetchRemove(name)) |entry| {
            entry.value.deinit(self.allocator);
            self.allocator.free(entry.key);
            std.log.info("Unregistered service '{s}'", .{name});
        }
    }
    
    pub fn createConnection(self: *GhostBridge, service_name: []const u8) !*GrpcConnection {
        // Find service endpoint
        const service = self.services.get(service_name) orelse return Error.ZquicError.InvalidArgument;
        
        // Create QUIC connection to service
        // TODO: Implement actual QUIC connection establishment
        const quic_connection = try self.allocator.create(QuicConnection);
        _ = service; // Will be used when implementing actual connection establishment
        // Initialize connection...
        
        const connection_id = self.next_connection_id;
        self.next_connection_id += 1;
        
        const grpc_connection = try GrpcConnection.init(self.allocator, connection_id, quic_connection);
        try self.connections.put(connection_id, grpc_connection);
        
        self.stats.total_connections += 1;
        self.stats.active_connections += 1;
        
        return grpc_connection;
    }
    
    pub fn closeConnection(self: *GhostBridge, connection_id: u64) void {
        if (self.connections.fetchRemove(connection_id)) |entry| {
            entry.value.deinit();
            self.stats.active_connections -= 1;
        }
    }
    
    pub fn getServices(self: *const GhostBridge) []const ServiceRegistration {
        // TODO: Return array of services
        _ = self;
        return &[_]ServiceRegistration{};
    }
    
    pub fn checkServiceHealth(self: *GhostBridge, service_name: []const u8) ServiceRegistration.HealthStatus {
        if (self.services.getPtr(service_name)) |service| {
            // Update health based on last heartbeat
            const now = std.time.timestamp();
            if (now - service.last_heartbeat > 60) { // 60 seconds timeout
                service.health_status = .unhealthy;
            }
            return service.health_status;
        }
        return .unknown;
    }
    
    pub fn updateStats(self: *GhostBridge) void {
        self.stats.updateUptime();
    }
};

// Unit tests
test "GhostBridge initialization" {
    const allocator = std.testing.allocator;
    
    const config = GhostBridgeConfig{
        .port = 50051,
        .max_connections = 100,
    };
    
    var bridge = try GhostBridge.init(allocator, config);
    defer bridge.deinit();
    
    try std.testing.expect(bridge.config.port == 50051);
    try std.testing.expect(bridge.config.max_connections == 100);
    try std.testing.expect(!bridge.running);
}

test "service registration" {
    const allocator = std.testing.allocator;
    
    const config = GhostBridgeConfig{};
    var bridge = try GhostBridge.init(allocator, config);
    defer bridge.deinit();
    
    try bridge.registerService("ghostd", "localhost:50001", .ghostd);
    try bridge.registerService("walletd", "localhost:50002", .walletd);
    
    try std.testing.expect(bridge.services.count() == 2);
    
    const ghostd_health = bridge.checkServiceHealth("ghostd");
    try std.testing.expect(ghostd_health == .unknown);
    
    try bridge.unregisterService("ghostd");
    try std.testing.expect(bridge.services.count() == 1);
}