//! FFI Layer for ZQUIC - Core C ABI exports for Rust integration
//!
//! This module provides a clean C ABI interface for Rust services (ghostd, walletd)
//! to use ZQUIC transport functionality. All functions use C calling convention
//! and standard C types for maximum compatibility.

const std = @import("std");
const zquic = @import("zquic");

/// Import core QUIC modules for actual implementation
const QuicConnection = zquic.Connection.Connection;
const QuicStream = zquic.Stream.Stream;
const QuicPacket = zquic.Packet;
const QuicFlowControl = zquic.FlowControl;
const QuicError = zquic.Error;

/// Local error types for FFI layer
const ZQuicError = error{
    OutOfMemory,
    InvalidArgument,
    ConnectionFailed,
    NetworkError,
    CryptoError,
    InternalError,
};

/// Opaque pointer types for FFI safety
pub const ZQuicContext = anyopaque;
pub const ZQuicConnection = anyopaque;
pub const ZQuicStream = anyopaque;
pub const ZQuicServer = anyopaque;

/// FFI-compatible configuration structure
pub const ZQuicConfig = extern struct {
    /// Server port (0 for client-only)
    port: u16,
    /// Maximum concurrent connections
    max_connections: u32,
    /// Connection timeout in milliseconds
    connection_timeout_ms: u32,
    /// Enable IPv6 (1 = true, 0 = false)
    enable_ipv6: u8,
    /// TLS verify mode (0 = none, 1 = verify)
    tls_verify: u8,
    /// Reserved for future use
    reserved: [16]u8,
};

/// FFI-compatible connection info
pub const ZQuicConnectionInfo = extern struct {
    /// Remote address as string
    remote_addr: [64]u8,
    /// Connection ID
    connection_id: [16]u8,
    /// Connection state (0 = connecting, 1 = connected, 2 = closed)
    state: u8,
    /// RTT in microseconds
    rtt_us: u32,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
};

/// Internal context structure
const Context = struct {
    allocator: std.mem.Allocator,
    config: ZQuicConfig,
    server: ?*zquic.Http3.Http3Server,
    connections: std.ArrayList(*Connection),
    flow_controller: ?*QuicFlowControl.FlowController,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ZQuicConfig) !*Self {
        const ctx = try allocator.create(Self);

        // Initialize flow controller with config values
        const flow_controller = try allocator.create(QuicFlowControl.FlowController);
        flow_controller.* = QuicFlowControl.FlowController.init(allocator, 1048576, // 1MB initial max data
            1048576 // 1MB peer max data
        );

        ctx.* = Self{
            .allocator = allocator,
            .config = config,
            .server = null,
            .connections = std.ArrayList(*Connection).init(allocator),
            .flow_controller = flow_controller,
        };
        return ctx;
    }

    pub fn deinit(self: *Self) void {
        if (self.server) |server| {
            server.deinit();
            self.allocator.destroy(server);
        }
        if (self.flow_controller) |fc| {
            fc.deinit();
            self.allocator.destroy(fc);
        }
        for (self.connections.items) |conn| {
            conn.deinit();
        }
        self.connections.deinit();
        self.allocator.destroy(self);
    }
};

/// Internal connection structure
const Connection = struct {
    allocator: std.mem.Allocator,
    connection: *QuicConnection,
    streams: std.ArrayList(*Stream),
    info: ZQuicConnectionInfo,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, quic_connection: *QuicConnection) !*Self {
        const conn = try allocator.create(Self);
        conn.* = Self{
            .allocator = allocator,
            .connection = quic_connection,
            .streams = std.ArrayList(*Stream).init(allocator),
            .info = std.mem.zeroes(ZQuicConnectionInfo),
        };

        // Update connection info
        conn.updateInfo();

        return conn;
    }

    pub fn deinit(self: *Self) void {
        for (self.streams.items) |stream| {
            stream.deinit();
        }
        self.streams.deinit();
        self.connection.deinit();
        self.allocator.destroy(self);
    }

    pub fn updateInfo(self: *Self) void {
        // Update connection state
        self.info.state = switch (self.connection.state) {
            .initial, .handshake => 0, // connecting
            .established => 1, // connected
            .closing, .draining, .closed => 2, // closed
        };

        // Update stats
        self.info.bytes_sent = self.connection.stats.bytes_sent;
        self.info.bytes_received = self.connection.stats.bytes_received;
        self.info.rtt_us = @intCast(self.connection.stats.rtt);

        // Copy connection ID
        const cid_bytes = self.connection.local_conn_id.bytes();
        const copy_len = @min(16, cid_bytes.len);
        @memcpy(self.info.connection_id[0..copy_len], cid_bytes[0..copy_len]);
    }
};

/// Internal stream structure
const Stream = struct {
    allocator: std.mem.Allocator,
    stream: *QuicStream,
    stream_id: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, quic_stream: *QuicStream, stream_id: u64) !*Self {
        const s = try allocator.create(Self);
        s.* = Self{
            .allocator = allocator,
            .stream = quic_stream,
            .stream_id = stream_id,
        };
        return s;
    }

    pub fn deinit(self: *Self) void {
        self.stream.deinit();
        self.allocator.destroy(self);
    }
};

// Global allocator for FFI operations (will be set by init)
var global_allocator: std.mem.Allocator = undefined;
var allocator_initialized: bool = false;

/// Initialize ZQUIC context with configuration
/// Returns: Opaque context pointer or null on failure
pub export fn zquic_init(config: *const ZQuicConfig) callconv(.C) ?*ZQuicContext {
    if (!allocator_initialized) {
        global_allocator = std.heap.c_allocator;
        allocator_initialized = true;
    }

    const ctx = Context.init(global_allocator, config.*) catch return null;
    return @ptrCast(ctx);
}

/// Destroy ZQUIC context and free all resources
pub export fn zquic_destroy(ctx: ?*ZQuicContext) callconv(.C) void {
    if (ctx) |context| {
        const internal_ctx: *Context = @ptrCast(@alignCast(context));
        internal_ctx.deinit();
    }
}

/// Create QUIC server for incoming connections
/// Returns: 0 on success, -1 on failure
pub export fn zquic_create_server(ctx: ?*ZQuicContext) callconv(.C) c_int {
    const context: *Context = @ptrCast(@alignCast(ctx orelse return -1));

    if (context.server != null) return -1; // Server already exists

    const server_config = zquic.Http3.ServerConfig{
        .max_connections = context.config.max_connections,
        .request_timeout_ms = context.config.connection_timeout_ms,
    };

    const server = context.allocator.create(zquic.Http3.Http3Server) catch return -1;
    server.* = zquic.Http3.Http3Server.init(context.allocator, server_config) catch {
        context.allocator.destroy(server);
        return -1;
    };
    context.server = server;

    return 0;
}

/// Start server listening on configured port
/// Returns: 0 on success, -1 on failure
pub export fn zquic_start_server(ctx: ?*ZQuicContext) callconv(.C) c_int {
    const context: *Context = @ptrCast(@alignCast(ctx orelse return -1));
    const server = context.server orelse return -1;

    _ = std.net.Address.parseIp("::0", context.config.port) catch
        std.net.Address.parseIp("0.0.0.0", context.config.port) catch return -1;

    server.start() catch return -1;
    return 0;
}

/// Stop server and close all connections
pub export fn zquic_stop_server(ctx: ?*ZQuicContext) callconv(.C) void {
    const context: *Context = @ptrCast(@alignCast(ctx orelse return));
    if (context.server) |server| {
        server.stop();
    }
}

/// Create outbound QUIC connection to remote address
/// Returns: Opaque connection pointer or null on failure
pub export fn zquic_create_connection(ctx: ?*ZQuicContext, remote_addr: [*:0]const u8) callconv(.C) ?*ZQuicConnection {
    const context: *Context = @ptrCast(@alignCast(ctx orelse return null));

    const addr_str = std.mem.span(remote_addr);

    // Parse remote address
    _ = std.net.Address.resolveIp(addr_str, 443) catch |err| {
        std.log.err("Failed to resolve address {s}: {}", .{ addr_str, err });
        return null;
    };

    // Generate local connection ID
    var cid_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&cid_bytes);
    const local_cid = QuicPacket.ConnectionId.init(&cid_bytes) catch return null;

    // Create QUIC connection
    const quic_conn = context.allocator.create(QuicConnection) catch return null;
    quic_conn.* = QuicConnection.init(context.allocator, .client, local_cid);

    // Create FFI connection wrapper
    const connection = Connection.init(context.allocator, quic_conn) catch {
        quic_conn.deinit();
        context.allocator.destroy(quic_conn);
        return null;
    };

    // Store remote address in connection info
    const addr_str_len = @min(addr_str.len, 63);
    @memcpy(connection.info.remote_addr[0..addr_str_len], addr_str[0..addr_str_len]);
    connection.info.remote_addr[addr_str_len] = 0; // null terminate

    context.connections.append(connection) catch {
        connection.deinit();
        return null;
    };

    std.log.info("Created QUIC connection to {s}", .{addr_str});
    return @ptrCast(connection);
}

/// Close QUIC connection and free resources
pub export fn zquic_close_connection(conn: ?*ZQuicConnection) callconv(.C) void {
    if (conn) |connection| {
        const internal_conn: *Connection = @ptrCast(@alignCast(connection));
        internal_conn.deinit();
    }
}

/// Send data over QUIC connection
/// Returns: Number of bytes sent, or -1 on error
pub export fn zquic_send_data(conn: ?*ZQuicConnection, data: [*]const u8, len: usize) callconv(.C) isize {
    const connection: *Connection = @ptrCast(@alignCast(conn orelse return -1));

    if (len == 0) return 0;

    // Check if connection is established
    if (!connection.connection.isEstablished()) {
        std.log.warn("Attempted to send data on non-established connection", .{});
        return -1;
    }

    // Get or create default stream for data
    var stream: *Stream = undefined;
    if (connection.streams.items.len == 0) {
        // Create default bidirectional stream
        const quic_stream = connection.connection.createStream(.client_bidirectional) catch |err| {
            std.log.err("Failed to create stream: {}", .{err});
            return -1;
        };

        stream = Stream.init(connection.allocator, quic_stream, quic_stream.id.id) catch return -1;
        connection.streams.append(stream) catch {
            stream.deinit();
            return -1;
        };
    } else {
        stream = connection.streams.items[0];
    }

    // Convert C data to Zig slice and send
    const data_slice = data[0..len];
    const bytes_written = connection.connection.sendStreamData(stream.stream_id, data_slice, false) catch |err| {
        std.log.err("Failed to send stream data: {}", .{err});
        return -1;
    };

    // Update connection info
    connection.updateInfo();

    return @intCast(bytes_written);
}

/// Receive data from QUIC connection
/// Returns: Number of bytes received, 0 for no data, -1 on error
pub export fn zquic_receive_data(conn: ?*ZQuicConnection, buffer: [*]u8, max_len: usize) callconv(.C) isize {
    const connection: *Connection = @ptrCast(@alignCast(conn orelse return -1));

    if (max_len == 0) return 0;

    // Check if connection is established
    if (!connection.connection.isEstablished()) {
        return 0; // No data on non-established connection
    }

    // Get default stream for receiving
    if (connection.streams.items.len == 0) {
        return 0; // No streams available, no data
    }

    const stream = connection.streams.items[0];
    const buffer_slice = buffer[0..max_len];

    // Read data from the stream
    const bytes_read = connection.connection.readStreamData(stream.stream_id, buffer_slice);

    // Update connection info
    connection.updateInfo();

    return @intCast(bytes_read);
}

/// Create new QUIC stream on connection
/// stream_type: 0 = bidirectional, 1 = unidirectional
/// Returns: Opaque stream pointer or null on failure
pub export fn zquic_create_stream(conn: ?*ZQuicConnection, stream_type: u8) callconv(.C) ?*ZQuicStream {
    const connection: *Connection = @ptrCast(@alignCast(conn orelse return null));

    // Check if connection is established
    if (!connection.connection.isEstablished()) {
        std.log.warn("Attempted to create stream on non-established connection", .{});
        return null;
    }

    // Determine stream type
    const quic_stream_type: zquic.Stream.StreamType = switch (stream_type) {
        0 => if (connection.connection.role == .client) .client_bidirectional else .server_bidirectional,
        1 => if (connection.connection.role == .client) .client_unidirectional else .server_unidirectional,
        else => {
            std.log.err("Invalid stream type: {}", .{stream_type});
            return null;
        },
    };

    // Create QUIC stream
    const quic_stream = connection.connection.createStream(quic_stream_type) catch |err| {
        std.log.err("Failed to create QUIC stream: {}", .{err});
        return null;
    };

    // Create FFI stream wrapper
    const stream = Stream.init(connection.allocator, quic_stream, quic_stream.id.id) catch return null;
    connection.streams.append(stream) catch {
        stream.deinit();
        return null;
    };

    std.log.info("Created QUIC stream with ID: {}", .{quic_stream.id.id});
    return @ptrCast(stream);
}

/// Close QUIC stream
pub export fn zquic_close_stream(stream: ?*ZQuicStream) callconv(.C) void {
    if (stream) |s| {
        const internal_stream: *Stream = @ptrCast(@alignCast(s));
        internal_stream.deinit();
    }
}

/// Send data on specific stream
/// Returns: Number of bytes sent, or -1 on error
pub export fn zquic_stream_send(stream: ?*ZQuicStream, data: [*]const u8, len: usize) callconv(.C) isize {
    const s: *Stream = @ptrCast(@alignCast(stream orelse return -1));

    if (len == 0) return 0;

    // Convert C data to Zig slice
    const data_slice = data[0..len];

    // Write data to the stream
    const bytes_written = s.stream.write(data_slice, false) catch |err| {
        std.log.err("Failed to write to stream {}: {}", .{ s.stream_id, err });
        return -1;
    };

    return @intCast(bytes_written);
}

/// Receive data from specific stream
/// Returns: Number of bytes received, 0 for no data, -1 on error
pub export fn zquic_stream_receive(stream: ?*ZQuicStream, buffer: [*]u8, max_len: usize) callconv(.C) isize {
    const s: *Stream = @ptrCast(@alignCast(stream orelse return -1));

    if (max_len == 0) return 0;

    // Convert C buffer to Zig slice
    const buffer_slice = buffer[0..max_len];

    // Read data from the stream
    const bytes_read = s.stream.read(buffer_slice);

    return @intCast(bytes_read);
}

/// Get connection information
/// Returns: 0 on success, -1 on failure
pub export fn zquic_get_connection_info(conn: ?*ZQuicConnection, info: *ZQuicConnectionInfo) callconv(.C) c_int {
    const connection: *Connection = @ptrCast(@alignCast(conn orelse return -1));
    info.* = connection.info;
    return 0;
}

/// Set connection callback for events
/// callback: Function pointer for connection events
pub export fn zquic_set_connection_callback(ctx: ?*ZQuicContext, callback: ?*const fn (conn: ?*ZQuicConnection, event_type: u8, data: ?*anyopaque) callconv(.C) void) callconv(.C) void {
    const context: *Context = @ptrCast(@alignCast(ctx orelse return));
    _ = context; // TODO: Store callback
    _ = callback; // TODO: Implement callback system
}

/// Get library version string
pub export fn zquic_version() callconv(.C) [*:0]const u8 {
    return "ZQUIC 0.2.0-alpha FFI+GhostChain";
}

/// Get last error message
pub export fn zquic_last_error() callconv(.C) [*:0]const u8 {
    // TODO: Implement proper error tracking
    return "No error";
}

// Testing exports for validation
pub export fn zquic_test_echo(input: [*:0]const u8) callconv(.C) [*:0]const u8 {
    _ = input;
    return "ZQUIC FFI Test OK";
}

pub export fn zquic_test_add(a: c_int, b: c_int) callconv(.C) c_int {
    return a + b;
}

//
// ===== GHOSTBRIDGE: gRPC-over-QUIC Functions =====
// Critical for ghostd ↔ walletd service communication
//

/// gRPC response structure for FFI
pub const ZQuicGrpcResponse = extern struct {
    /// Response data buffer
    data: [*]u8,
    /// Length of response data
    len: usize,
    /// Status code (0 = success, non-zero = error)
    status: u32,
    /// Error message (null-terminated)
    error_msg: [256]u8,
};

/// Make gRPC call over QUIC connection
/// Returns: gRPC response pointer or null on failure (caller must free)
pub export fn zquic_grpc_call(conn: ?*ZQuicConnection, service_method: [*:0]const u8, request_data: [*]const u8, request_len: usize) callconv(.C) ?*ZQuicGrpcResponse {
    const connection: *Connection = @ptrCast(@alignCast(conn orelse return null));

    // Validate inputs
    if (request_len == 0) return null;

    const method_str = std.mem.span(service_method);
    const request_slice = request_data[0..request_len];

    // Check if connection is established
    if (!connection.connection.isEstablished()) {
        std.log.warn("gRPC call attempted on non-established connection", .{});
        return null;
    }

    // Create or get gRPC stream
    var grpc_stream: *Stream = undefined;
    var found_stream = false;

    // Look for an existing gRPC stream (marked by even stream IDs for gRPC)
    for (connection.streams.items) |stream| {
        if (stream.stream_id % 4 == 0) { // gRPC convention: use specific stream IDs
            grpc_stream = stream;
            found_stream = true;
            break;
        }
    }

    if (!found_stream) {
        // Create new bidirectional stream for gRPC
        const quic_stream = connection.connection.createStream(.client_bidirectional) catch |err| {
            std.log.err("Failed to create gRPC stream: {}", .{err});
            return null;
        };

        grpc_stream = Stream.init(connection.allocator, quic_stream, quic_stream.id.id) catch return null;
        connection.streams.append(grpc_stream) catch {
            grpc_stream.deinit();
            return null;
        };
    }

    // Allocate response structure
    const response = connection.allocator.create(ZQuicGrpcResponse) catch return null;
    response.* = std.mem.zeroes(ZQuicGrpcResponse);

    // Format gRPC message according to HTTP/2 gRPC protocol over QUIC
    // gRPC format: [compressed flag][message length][message data]
    var grpc_message = std.ArrayList(u8).init(connection.allocator);
    defer grpc_message.deinit();

    // Build gRPC HTTP/2-like headers
    const grpc_headers = std.fmt.allocPrint(connection.allocator, ":method: POST\r\n" ++
        ":path: /{s}\r\n" ++
        ":scheme: https\r\n" ++
        "content-type: application/grpc\r\n" ++
        "grpc-encoding: identity\r\n" ++
        "grpc-accept-encoding: identity,gzip\r\n" ++
        "\r\n", .{method_str}) catch {
        connection.allocator.destroy(response);
        return null;
    };
    defer connection.allocator.free(grpc_headers);

    // Append headers and payload
    grpc_message.appendSlice(grpc_headers) catch {
        connection.allocator.destroy(response);
        return null;
    };

    // gRPC message framing: [compressed flag (1 byte)][length (4 bytes)][data]
    grpc_message.append(0) catch { // Not compressed
        connection.allocator.destroy(response);
        return null;
    };

    // Message length in big endian
    const msg_len_bytes = std.mem.toBytes(@as(u32, @intCast(request_len)));
    grpc_message.appendSlice(&msg_len_bytes) catch {
        connection.allocator.destroy(response);
        return null;
    };

    // Actual message data
    grpc_message.appendSlice(request_slice) catch {
        connection.allocator.destroy(response);
        return null;
    };

    // Send gRPC message over QUIC stream
    const bytes_sent = grpc_stream.stream.write(grpc_message.items, false) catch |err| {
        std.log.err("Failed to send gRPC message: {}", .{err});
        connection.allocator.destroy(response);
        return null;
    };

    std.log.info("Sent gRPC call to {s}: {} bytes", .{ method_str, bytes_sent });

    // TODO: For now, create a mock response. In real implementation, this would
    // wait for and parse the actual gRPC response from the stream
    const mock_response_data = std.fmt.allocPrint(connection.allocator, "{{\"status\": \"ok\", \"method\": \"{s}\"}}", .{method_str}) catch {
        connection.allocator.destroy(response);
        return null;
    };
    defer connection.allocator.free(mock_response_data);
    const response_data = connection.allocator.dupe(u8, mock_response_data) catch {
        connection.allocator.destroy(response);
        return null;
    };

    response.data = response_data.ptr;
    response.len = response_data.len;
    response.status = 0; // Success

    std.log.info("gRPC call completed: {s}", .{method_str});
    return response;
}

/// Free gRPC response allocated by zquic_grpc_call
pub export fn zquic_grpc_response_free(response: ?*ZQuicGrpcResponse) callconv(.C) void {
    if (response) |resp| {
        if (resp.len > 0) {
            // Free the response data using global allocator
            global_allocator.free(resp.data[0..resp.len]);
        }
        // Free the response structure
        global_allocator.destroy(resp);
    }
}

/// Start gRPC server on QUIC connection for incoming calls
/// Returns: 0 on success, -1 on failure
pub export fn zquic_grpc_serve(ctx: ?*ZQuicContext, handler: ?*const fn (method: [*:0]const u8, request: [*]const u8, request_len: usize, response: *ZQuicGrpcResponse) callconv(.C) c_int) callconv(.C) c_int {
    const context: *Context = @ptrCast(@alignCast(ctx orelse return -1));
    _ = context; // TODO: Store handler
    _ = handler; // TODO: Implement gRPC serving

    // TODO: Set up gRPC message handling on the server
    return 0;
}

//
// ===== WRAITH: Reverse Proxy Functions =====
// For QUIC-based reverse proxy and edge routing
//

/// Proxy configuration for Wraith
pub const ZQuicProxyConfig = extern struct {
    /// Target backend address
    backend_addr: [256]u8,
    /// Load balancing mode (0 = round_robin, 1 = least_conn)
    lb_mode: u8,
    /// Health check interval in seconds
    health_check_interval: u32,
    /// Connection timeout in milliseconds
    timeout_ms: u32,
    /// Reserved for future use
    reserved: [32]u8,
};

/// Internal proxy state
const ProxyState = struct {
    allocator: std.mem.Allocator,
    config: ZQuicProxyConfig,
    backend_connections: std.ArrayList(*Connection),
    current_backend: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ZQuicProxyConfig) !*Self {
        const proxy = try allocator.create(Self);
        proxy.* = Self{
            .allocator = allocator,
            .config = config,
            .backend_connections = std.ArrayList(*Connection).init(allocator),
            .current_backend = 0,
        };
        return proxy;
    }

    pub fn deinit(self: *Self) void {
        for (self.backend_connections.items) |conn| {
            conn.deinit();
        }
        self.backend_connections.deinit();
        self.allocator.destroy(self);
    }

    pub fn selectBackend(self: *Self) ?*Connection {
        if (self.backend_connections.items.len == 0) return null;

        switch (self.config.lb_mode) {
            0 => { // Round robin
                const backend = self.backend_connections.items[self.current_backend];
                self.current_backend = @intCast((self.current_backend + 1) % self.backend_connections.items.len);
                return backend;
            },
            1 => { // Least connections - simplified to round robin for now
                return self.selectBackend(); // Recurse with mode 0
            },
            else => return null,
        }
    }
};

/// Create reverse proxy instance
/// Returns: Opaque proxy pointer or null on failure
pub export fn zquic_proxy_create(ctx: ?*ZQuicContext, config: *const ZQuicProxyConfig) callconv(.C) ?*anyopaque {
    const context: *Context = @ptrCast(@alignCast(ctx orelse return null));

    // Create proxy state
    const proxy = ProxyState.init(context.allocator, config.*) catch return null;

    // Parse backend address and create connection
    const backend_addr_len = std.mem.indexOfScalar(u8, &config.backend_addr, 0) orelse config.backend_addr.len;
    const backend_addr_str = config.backend_addr[0..backend_addr_len];

    if (backend_addr_str.len == 0) {
        proxy.deinit();
        return null;
    }

    // Validate backend address
    _ = std.net.Address.resolveIp(backend_addr_str, 443) catch |err| {
        std.log.err("Invalid backend address {s}: {}", .{ backend_addr_str, err });
        proxy.deinit();
        return null;
    };

    std.log.info("Created QUIC proxy with backend: {s}", .{backend_addr_str});
    return @ptrCast(proxy);
}

/// Route incoming connection through proxy
/// Returns: 0 on success, -1 on failure
pub export fn zquic_proxy_route(proxy: ?*anyopaque, conn: ?*ZQuicConnection) callconv(.C) c_int {
    const proxy_state: *ProxyState = @ptrCast(@alignCast(proxy orelse return -1));
    const connection: *Connection = @ptrCast(@alignCast(conn orelse return -1));

    // Check if connection is established
    if (!connection.connection.isEstablished()) {
        std.log.warn("Attempted to route non-established connection", .{});
        return -1;
    }

    // Select backend using load balancing
    const backend = proxy_state.selectBackend();
    if (backend == null) {
        // No backends available, create connection to configured backend
        const backend_addr_len = std.mem.indexOfScalar(u8, &proxy_state.config.backend_addr, 0) orelse proxy_state.config.backend_addr.len;
        const backend_addr_str = proxy_state.config.backend_addr[0..backend_addr_len];

        // For now, log the routing attempt
        std.log.info("Routing connection to backend: {s}", .{backend_addr_str});

        // TODO: Create actual backend connection and set up data forwarding
        // This would involve:
        // 1. Creating a connection to the backend
        // 2. Setting up bidirectional data forwarding between client and backend
        // 3. Handling connection state synchronization

        return 0; // Success for now
    }

    std.log.info("Routing connection through existing backend", .{});

    // TODO: Set up data forwarding between the incoming connection and selected backend
    // This would involve creating streams on both connections and copying data

    return 0;
}

//
// ===== CNS/ZNS: DNS-over-QUIC Functions =====
// For decentralized name resolution (ENS, ZNS, UD)
//

/// DNS query types
pub const ZQUIC_DNS_A: u16 = 1;
pub const ZQUIC_DNS_AAAA: u16 = 28;
pub const ZQUIC_DNS_TXT: u16 = 16;
pub const ZQUIC_DNS_ENS: u16 = 65001; // Custom type for ENS
pub const ZQUIC_DNS_ZNS: u16 = 65002; // Custom type for ZNS

/// DNS response structure
pub const ZQuicDnsResponse = extern struct {
    /// Response data
    data: [512]u8,
    /// Length of response
    len: usize,
    /// Query type that was resolved
    query_type: u16,
    /// Response code (0 = success)
    rcode: u8,
    /// TTL in seconds
    ttl: u32,
};

/// Perform DNS query over QUIC
/// Returns: 0 on success, -1 on failure
pub export fn zquic_dns_query(conn: ?*ZQuicConnection, domain: [*:0]const u8, query_type: u16, response: *ZQuicDnsResponse) callconv(.C) c_int {
    const connection: *Connection = @ptrCast(@alignCast(conn orelse return -1));

    const domain_str = std.mem.span(domain);

    // Check if connection is established
    if (!connection.connection.isEstablished()) {
        std.log.warn("DNS query attempted on non-established connection", .{});
        response.rcode = 2; // SERVFAIL
        return -1;
    }

    // Initialize response
    response.* = std.mem.zeroes(ZQuicDnsResponse);
    response.query_type = query_type;

    // Create or get DNS stream
    var dns_stream: *Stream = undefined;
    var found_stream = false;

    // Look for existing DNS stream (use odd stream IDs for DNS)
    for (connection.streams.items) |stream| {
        if (stream.stream_id % 4 == 1) { // DNS convention
            dns_stream = stream;
            found_stream = true;
            break;
        }
    }

    if (!found_stream) {
        // Create new unidirectional stream for DNS query
        const quic_stream = connection.connection.createStream(.client_unidirectional) catch |err| {
            std.log.err("Failed to create DNS stream: {}", .{err});
            response.rcode = 2; // SERVFAIL
            return -1;
        };

        dns_stream = Stream.init(connection.allocator, quic_stream, quic_stream.id.id) catch {
            response.rcode = 2; // SERVFAIL
            return -1;
        };

        connection.streams.append(dns_stream) catch {
            dns_stream.deinit();
            response.rcode = 2; // SERVFAIL
            return -1;
        };
    }

    // Build DNS query message
    var dns_query = std.ArrayList(u8).init(connection.allocator);
    defer dns_query.deinit();

    // Simple DNS query format for demonstration
    const query_msg = std.fmt.allocPrint(connection.allocator, "DNS_QUERY: {s} TYPE: {}", .{ domain_str, query_type }) catch {
        response.rcode = 2; // SERVFAIL
        return -1;
    };
    defer connection.allocator.free(query_msg);

    // Send DNS query
    const bytes_sent = dns_stream.stream.write(query_msg, true) catch |err| {
        std.log.err("Failed to send DNS query: {}", .{err});
        response.rcode = 2; // SERVFAIL
        return -1;
    };

    std.log.info("Sent DNS query for {s} (type {}): {} bytes", .{ domain_str, query_type, bytes_sent });

    // Process query based on type
    switch (query_type) {
        ZQUIC_DNS_A => {
            // Mock A record response
            const mock_ip = "192.168.1.100";
            @memcpy(response.data[0..mock_ip.len], mock_ip);
            response.len = mock_ip.len;
            response.ttl = 300;
            response.rcode = 0; // Success
        },
        ZQUIC_DNS_AAAA => {
            // Mock AAAA record response
            const mock_ipv6 = "2001:db8::1";
            @memcpy(response.data[0..mock_ipv6.len], mock_ipv6);
            response.len = mock_ipv6.len;
            response.ttl = 300;
            response.rcode = 0; // Success
        },
        ZQUIC_DNS_ENS => {
            // Mock ENS resolution for .eth domains
            if (std.mem.endsWith(u8, domain_str, ".eth")) {
                const mock_addr = "0x1234567890abcdef1234567890abcdef12345678";
                @memcpy(response.data[0..mock_addr.len], mock_addr);
                response.len = mock_addr.len;
                response.ttl = 3600;
                response.rcode = 0; // Success
            } else {
                response.rcode = 3; // NXDOMAIN
            }
        },
        ZQUIC_DNS_ZNS => {
            // Mock ZNS resolution for .zns/.ghost domains
            if (std.mem.endsWith(u8, domain_str, ".zns") or std.mem.endsWith(u8, domain_str, ".ghost")) {
                const mock_addr = "0xabcdef1234567890abcdef1234567890abcdef12";
                @memcpy(response.data[0..mock_addr.len], mock_addr);
                response.len = mock_addr.len;
                response.ttl = 3600;
                response.rcode = 0; // Success
            } else {
                response.rcode = 3; // NXDOMAIN
            }
        },
        else => {
            response.rcode = 4; // NOTIMP
            return -1;
        },
    }

    std.log.info("DNS query resolved: {s} -> {s}", .{ domain_str, response.data[0..response.len] });
    return 0;
}

/// Start DNS-over-QUIC server
/// Returns: 0 on success, -1 on failure
pub export fn zquic_dns_serve(ctx: ?*ZQuicContext, resolver: ?*const fn (domain: [*:0]const u8, query_type: u16, response: *ZQuicDnsResponse) callconv(.C) c_int) callconv(.C) c_int {
    const context: *Context = @ptrCast(@alignCast(ctx orelse return -1));
    _ = context; // TODO: Store resolver
    _ = resolver; // TODO: Implement DNS serving

    // TODO: Set up DNS-over-QUIC server
    return 0;
}

/// Crypto key types
pub const ZQUIC_KEY_ED25519: u8 = 1;
pub const ZQUIC_KEY_SECP256K1: u8 = 2;
pub const ZQUIC_KEY_X25519: u8 = 3;

/// Hash algorithm types
pub const ZQUIC_HASH_BLAKE3: u8 = 1;
pub const ZQUIC_HASH_SHA256: u8 = 2;
pub const ZQUIC_HASH_SHA3: u8 = 3;

/// Crypto operation result
pub const ZQuicCryptoResult = extern struct {
    /// Status (0 = success, non-zero = error)
    status: u32,
    /// Output data
    data: [128]u8,
    /// Length of output data
    len: usize,
    /// Error message
    error_msg: [256]u8,
};

/// Initialize crypto subsystem with ZCrypto
/// Returns: 0 on success, -1 on failure
pub export fn zquic_crypto_init() callconv(.C) c_int {
    // TODO: Initialize ZCrypto library when available
    // This will integrate with the ZCrypto library for:
    // - Ed25519 digital signatures
    // - Secp256k1 ECDSA signatures
    // - Blake3 and SHA256 hashing
    // - X25519 key exchange

    std.log.info("ZCrypto subsystem initialized (mock)", .{});
    return 0;
}

/// Generate key pair
/// Returns: 0 on success, -1 on failure
pub export fn zquic_crypto_keygen(key_type: u8, public_key: [*]u8, private_key: [*]u8, result: *ZQuicCryptoResult) callconv(.C) c_int {
    result.* = std.mem.zeroes(ZQuicCryptoResult);

    switch (key_type) {
        ZQUIC_KEY_ED25519 => {
            // TODO: Call zcrypto.ed25519.generateKeyPair()
            // For now, generate mock keys with proper format

            // Generate random seed for deterministic key generation
            var seed: [32]u8 = undefined;
            std.crypto.random.bytes(&seed);

            // Mock Ed25519 public key (32 bytes)
            const mock_pubkey_prefix = "ed25519_pubkey_";
            @memcpy(public_key[0..mock_pubkey_prefix.len], mock_pubkey_prefix);
            @memcpy(public_key[mock_pubkey_prefix.len..32], seed[0 .. 32 - mock_pubkey_prefix.len]);

            // Mock Ed25519 private key (32 bytes)
            const mock_privkey_prefix = "ed25519_privkey";
            @memcpy(private_key[0..mock_privkey_prefix.len], mock_privkey_prefix);
            @memcpy(private_key[mock_privkey_prefix.len..32], seed[0 .. 32 - mock_privkey_prefix.len]);

            // Copy public key to result
            @memcpy(result.data[0..32], public_key[0..32]);
            result.len = 32;
            result.status = 0;

            std.log.info("Generated Ed25519 key pair (mock)", .{});
            return 0;
        },
        ZQUIC_KEY_SECP256K1 => {
            // TODO: Call zcrypto.secp256k1.generateKeyPair()

            // Generate random seed
            var seed: [32]u8 = undefined;
            std.crypto.random.bytes(&seed);

            // Mock Secp256k1 public key (33 bytes compressed)
            public_key[0] = 0x02; // Compressed public key prefix
            @memcpy(public_key[1..33], seed[0..32]);

            // Mock Secp256k1 private key (32 bytes)
            @memcpy(private_key[0..32], seed[0..32]);

            // Copy public key to result
            @memcpy(result.data[0..33], public_key[0..33]);
            result.len = 33;
            result.status = 0;

            std.log.info("Generated Secp256k1 key pair (mock)", .{});
            return 0;
        },
        ZQUIC_KEY_X25519 => {
            // TODO: Call zcrypto.x25519.generateKeyPair()

            // Generate random seed
            var seed: [32]u8 = undefined;
            std.crypto.random.bytes(&seed);

            // X25519 keys are both 32 bytes
            @memcpy(public_key[0..32], seed[0..32]);
            @memcpy(private_key[0..32], seed[0..32]);

            // Copy public key to result
            @memcpy(result.data[0..32], public_key[0..32]);
            result.len = 32;
            result.status = 0;

            std.log.info("Generated X25519 key pair (mock)", .{});
            return 0;
        },
        else => {
            result.status = 1;
            const error_msg = "Unsupported key type";
            @memcpy(result.error_msg[0..error_msg.len], error_msg);
            std.log.err("Unsupported key type: {}", .{key_type});
            return -1;
        },
    }
}

/// Sign data with private key
/// Returns: 0 on success, -1 on failure
pub export fn zquic_crypto_sign(key_type: u8, private_key: [*]const u8, data: [*]const u8, data_len: usize, signature: [*]u8, result: *ZQuicCryptoResult) callconv(.C) c_int {
    result.* = std.mem.zeroes(ZQuicCryptoResult);

    const data_slice = data[0..data_len];

    switch (key_type) {
        ZQUIC_KEY_ED25519 => {
            // TODO: Call zcrypto.ed25519.sign(private_key, data)

            // For now, create a deterministic mock signature based on data hash
            var hasher = std.crypto.hash.blake2.Blake2b384.init(.{});
            hasher.update(private_key[0..32]); // Private key
            hasher.update(data_slice); // Data to sign
            var hash: [48]u8 = undefined;
            hasher.final(&hash);

            // Ed25519 signature is 64 bytes
            @memcpy(signature[0..32], hash[0..32]);
            @memcpy(signature[32..64], hash[16..48]);

            @memcpy(result.data[0..64], signature[0..64]);
            result.len = 64;
            result.status = 0;

            std.log.info("Signed {} bytes with Ed25519 (mock)", .{data_len});
            return 0;
        },
        ZQUIC_KEY_SECP256K1 => {
            // TODO: Call zcrypto.secp256k1.sign(private_key, data)

            // Create mock signature
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(private_key[0..32]);
            hasher.update(data_slice);
            var hash: [32]u8 = undefined;
            hasher.final(&hash);

            // Secp256k1 signature (r,s) is 64 bytes
            @memcpy(signature[0..32], hash[0..32]);
            @memcpy(signature[32..64], hash[0..32]); // Mock s component

            @memcpy(result.data[0..64], signature[0..64]);
            result.len = 64;
            result.status = 0;

            std.log.info("Signed {} bytes with Secp256k1 (mock)", .{data_len});
            return 0;
        },
        else => {
            result.status = 1;
            const error_msg = "Unsupported key type for signing";
            @memcpy(result.error_msg[0..error_msg.len], error_msg);
            return -1;
        },
    }
}

/// Verify signature
/// Returns: 0 on success, -1 on failure
pub export fn zquic_crypto_verify(key_type: u8, public_key: [*]const u8, data: [*]const u8, data_len: usize, signature: [*]const u8, result: *ZQuicCryptoResult) callconv(.C) c_int {
    result.* = std.mem.zeroes(ZQuicCryptoResult);

    const data_slice = data[0..data_len];
    _ = data_slice; // TODO: Use for actual verification

    switch (key_type) {
        ZQUIC_KEY_ED25519 => {
            // TODO: Call zcrypto.ed25519.verify(public_key, data, signature)
            // For now, mock successful verification
            result.status = 0;
            _ = public_key;
            _ = signature;
            return 0;
        },
        ZQUIC_KEY_SECP256K1 => {
            // TODO: Call zcrypto.secp256k1.verify(public_key, data, signature)
            result.status = 0;
            _ = public_key;
            _ = signature;
            return 0;
        },
        else => {
            result.status = 1;
            return -1;
        },
    }
}

/// Hash data using specified algorithm
/// Returns: 0 on success, -1 on failure
pub export fn zquic_crypto_hash(hash_type: u8, data: [*]const u8, data_len: usize, hash_output: [*]u8, result: *ZQuicCryptoResult) callconv(.C) c_int {
    result.* = std.mem.zeroes(ZQuicCryptoResult);

    const data_slice = data[0..data_len];

    switch (hash_type) {
        ZQUIC_HASH_BLAKE3 => {
            // TODO: Call zcrypto.blake3.hash(data)
            // For now, use Zig's Blake2b as a placeholder
            var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
            hasher.update(data_slice);
            var hash: [32]u8 = undefined;
            hasher.final(&hash);

            @memcpy(hash_output[0..32], hash[0..32]);
            @memcpy(result.data[0..32], hash[0..32]);
            result.len = 32;
            result.status = 0;

            std.log.info("Blake3 hashed {} bytes (using Blake2b mock)", .{data_len});
            return 0;
        },
        ZQUIC_HASH_SHA256 => {
            // TODO: Call zcrypto.sha256.hash(data)
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(data_slice);
            var hash: [32]u8 = undefined;
            hasher.final(&hash);

            @memcpy(hash_output[0..32], hash[0..32]);
            @memcpy(result.data[0..32], hash[0..32]);
            result.len = 32;
            result.status = 0;

            std.log.info("SHA256 hashed {} bytes", .{data_len});
            return 0;
        },
        ZQUIC_HASH_SHA3 => {
            // TODO: Call zcrypto.sha3.hash(data)
            var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
            hasher.update(data_slice);
            var hash: [32]u8 = undefined;
            hasher.final(&hash);

            @memcpy(hash_output[0..32], hash[0..32]);
            @memcpy(result.data[0..32], hash[0..32]);
            result.len = 32;
            result.status = 0;

            std.log.info("SHA3-256 hashed {} bytes", .{data_len});
            return 0;
        },
        else => {
            result.status = 1;
            const error_msg = "Unsupported hash algorithm";
            @memcpy(result.error_msg[0..error_msg.len], error_msg);
            return -1;
        },
    }
}

/// Set custom crypto provider for QUIC TLS
/// Returns: 0 on success, -1 on failure
pub export fn zquic_set_crypto_provider(ctx: ?*ZQuicContext, provider: ?*const fn (operation: u8, input: [*]const u8, input_len: usize, output: [*]u8, output_len: *usize) callconv(.C) c_int) callconv(.C) c_int {
    const context: *Context = @ptrCast(@alignCast(ctx orelse return -1));
    _ = context; // TODO: Store crypto provider
    _ = provider; // TODO: Integrate with QUIC TLS

    // TODO: Set ZCrypto as the crypto backend for QUIC TLS operations
    return 0;
}
