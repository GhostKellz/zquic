//! Enhanced HTTP/3 server implementation
//!
//! Production-ready HTTP/3 server with routing, middleware, and advanced features

const std = @import("std");
const Error = @import("../utils/error.zig");
const Frame = @import("frame.zig");
const QpackDecoder = @import("qpack.zig").QpackDecoder;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Router = @import("router.zig").Router;
const HandlerFn = @import("router.zig").HandlerFn;
const Middleware = @import("middleware.zig");
const Connection = @import("../core/connection.zig").Connection;
const Stream = @import("../core/stream.zig");

/// Server configuration
pub const ServerConfig = struct {
    max_connections: u32 = 1000,
    max_streams_per_connection: u32 = 100,
    request_timeout_ms: u32 = 30000,
    keep_alive_timeout_ms: u32 = 60000,
    max_request_body_size: usize = 1024 * 1024, // 1MB
    enable_push: bool = false,
    enable_compression: bool = true,
    compression_level: u8 = 6,
    static_files_root: ?[]const u8 = null,
    enable_cors: bool = false,
    cors_origins: []const []const u8 = &[_][]const u8{},
    enable_security_headers: bool = true,
};

/// Server statistics
pub const ServerStats = struct {
    connections_active: u32 = 0,
    connections_total: u64 = 0,
    requests_handled: u64 = 0,
    requests_per_second: f64 = 0.0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    errors_count: u64 = 0,
    start_time: i64,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .start_time = std.time.timestamp(),
        };
    }

    pub fn uptime(self: *const Self) i64 {
        return std.time.timestamp() - self.start_time;
    }

    pub fn incrementRequest(self: *Self) void {
        self.requests_handled += 1;
    }

    pub fn incrementError(self: *Self) void {
        self.errors_count += 1;
    }

    pub fn addBytesReceived(self: *Self, bytes: usize) void {
        self.bytes_received += bytes;
    }

    pub fn addBytesSent(self: *Self, bytes: usize) void {
        self.bytes_sent += bytes;
    }
};

/// Connection context for managing HTTP/3 connections
pub const ConnectionContext = struct {
    connection: *Connection,
    active_requests: std.HashMap(u64, *ActiveRequest, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    last_activity: i64,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, connection: *Connection) Self {
        return Self{
            .connection = connection,
            .active_requests = std.HashMap(u64, *ActiveRequest, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .last_activity = std.time.timestamp(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iterator = self.active_requests.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.active_requests.deinit();
    }

    pub fn updateActivity(self: *Self) void {
        self.last_activity = std.time.timestamp();
    }

    pub fn isExpired(self: *const Self, timeout_ms: u32) bool {
        const now = std.time.timestamp();
        return (now - self.last_activity) > (timeout_ms / 1000);
    }
};

/// Active request tracking
pub const ActiveRequest = struct {
    request: Request,
    response: Response,
    start_time: i64,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, stream_id: u64, connection_id: []const u8) Self {
        return Self{
            .request = Request.init(allocator, stream_id, connection_id),
            .response = Response.init(allocator, stream_id),
            .start_time = std.time.microTimestamp(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.request.deinit();
        self.response.deinit();
    }

    pub fn duration(self: *const Self) i64 {
        return std.time.microTimestamp() - self.start_time;
    }
};

/// Enhanced HTTP/3 server
pub const Http3Server = struct {
    allocator: std.mem.Allocator,
    qpack_decoder: QpackDecoder,
    qpack_encoder: QpackEncoder,
    router: Router,
    config: ServerConfig,
    stats: ServerStats,
    connections: std.HashMap([]const u8, *ConnectionContext, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    middleware_stack: std.ArrayList(Middleware.MiddlewareFn),
    running: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) !Self {
        var server = Self{
            .allocator = allocator,
            .qpack_decoder = QpackDecoder.init(allocator, 4096),
            .qpack_encoder = QpackEncoder.init(allocator),
            .router = Router.init(allocator),
            .config = config,
            .stats = ServerStats.init(),
            .connections = std.HashMap([]const u8, *ConnectionContext, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .middleware_stack = std.ArrayList(Middleware.MiddlewareFn).init(allocator),
        };

        // Setup default middleware
        try server.setupDefaultMiddleware();

        return server;
    }

    pub fn deinit(self: *Self) void {
        self.qpack_decoder.deinit();
        self.qpack_encoder.deinit();
        self.router.deinit();

        // Clean up connections
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.connections.deinit();
        self.middleware_stack.deinit();
    }

    fn setupDefaultMiddleware(self: *Self) !void {
        // Security headers (if enabled)
        if (self.config.enable_security_headers) {
            var security = Middleware.SecurityMiddleware.init(self.allocator);
            try self.middleware_stack.append(security.middleware());
        }

        // CORS (if enabled)
        if (self.config.enable_cors) {
            var cors = Middleware.CorsMiddleware.init(self.allocator);
            defer cors.deinit();
            try self.middleware_stack.append(cors.middleware());
        }

        // Compression (if enabled)
        if (self.config.enable_compression) {
            const compression = Middleware.CompressionMiddleware.init(self.allocator, self.config.compression_level, 256 // min size
            );
            try self.middleware_stack.append(compression.middleware());
        }

        // Static files (if configured)
        if (self.config.static_files_root) |static_root| {
            const static_middleware = Middleware.StaticMiddleware.init(self.allocator, static_root);
            try self.middleware_stack.append(static_middleware.middleware());
        }

        // Logging
        const logging = Middleware.LoggingMiddleware.init(self.allocator, .info);
        try self.middleware_stack.append(logging.middleware());
    }

    /// Start the server
    pub fn start(self: *Self) !void {
        self.running = true;
        std.log.info("HTTP/3 server started with {} middleware(s)", .{self.middleware_stack.items.len});
    }

    /// Stop the server
    pub fn stop(self: *Self) void {
        self.running = false;
        std.log.info("HTTP/3 server stopped", .{});
    }

    /// Register a new connection
    pub fn registerConnection(self: *Self, connection: *Connection) ![]const u8 {
        const conn_id = try self.allocator.dupe(u8, connection.local_conn_id.bytes());
        const context = try self.allocator.create(ConnectionContext);
        context.* = ConnectionContext.init(self.allocator, connection);

        try self.connections.put(conn_id, context);
        self.stats.connections_active += 1;
        self.stats.connections_total += 1;

        std.log.info("Registered HTTP/3 connection: {s}", .{std.fmt.fmtSliceHexLower(conn_id)});
        return conn_id;
    }

    /// Unregister a connection
    pub fn unregisterConnection(self: *Self, connection_id: []const u8) void {
        if (self.connections.fetchRemove(connection_id)) |entry| {
            entry.value.deinit();
            self.allocator.destroy(entry.value);
            self.allocator.free(entry.key);
            self.stats.connections_active -= 1;
        }
    }

    /// Process incoming HTTP/3 frames
    pub fn processFrame(self: *Self, connection_id: []const u8, stream_id: u64, frame: Frame.Frame) !void {
        const context = self.connections.get(connection_id) orelse {
            std.log.warn("Frame received for unknown connection: {s}", .{std.fmt.fmtSliceHexLower(connection_id)});
            return Error.ZquicError.ConnectionClosed;
        };

        context.updateActivity();

        switch (frame.frame_type) {
            .headers => try self.processHeadersFrame(context, stream_id, frame.payload),
            .data => try self.processDataFrame(context, stream_id, frame.payload),
            .settings => try self.processSettingsFrame(context, frame.payload),
            else => {
                std.log.debug("Unhandled frame type: {}", .{frame.frame_type});
            },
        }
    }

    fn processHeadersFrame(self: *Self, context: *ConnectionContext, stream_id: u64, payload: []const u8) !void {
        // Get or create active request
        var active_request = try self.getOrCreateActiveRequest(context, stream_id);

        // Decode headers using QPACK
        const header_fields = try self.qpack_decoder.decode(payload, self.allocator);
        defer self.allocator.free(header_fields);

        // Parse request from headers
        try active_request.request.parseFromHeaders(header_fields);

        // If this completes the request headers, process the request
        try self.processRequest(active_request);
    }

    fn processDataFrame(self: *Self, context: *ConnectionContext, stream_id: u64, payload: []const u8) !void {
        if (context.active_requests.get(stream_id)) |active_request| {
            // Append data to request body
            try active_request.request.appendBody(payload);
            self.stats.addBytesReceived(payload.len);

            // Check body size limit
            if (active_request.request.getBody().len > self.config.max_request_body_size) {
                active_request.response.setStatus(.payload_too_large);
                try active_request.response.text("Request body too large");
                try self.sendResponse(context, active_request);
                return;
            }
        }
    }

    fn processSettingsFrame(_: *Self, _: *ConnectionContext, _: []const u8) !void {
        // Process HTTP/3 settings
        std.log.debug("Received HTTP/3 SETTINGS frame", .{});
    }

    fn getOrCreateActiveRequest(self: *Self, context: *ConnectionContext, stream_id: u64) !*ActiveRequest {
        if (context.active_requests.get(stream_id)) |request| {
            return request;
        }

        // Create new active request
        const active_request = try self.allocator.create(ActiveRequest);
        const conn_id_bytes = context.connection.local_conn_id.bytes();
        active_request.* = ActiveRequest.init(self.allocator, stream_id, conn_id_bytes);

        try context.active_requests.put(stream_id, active_request);
        return active_request;
    }

    fn processRequest(self: *Self, active_request: *ActiveRequest) !void {
        self.stats.incrementRequest();

        // Handle request through router
        self.router.handleRequest(&active_request.request, &active_request.response) catch |err| {
            self.stats.incrementError();

            // Handle errors
            active_request.response.setStatus(.internal_server_error);
            try active_request.response.text("Internal Server Error");

            std.log.err("Request processing error: {}", .{err});
        };
    }

    fn sendResponse(self: *Self, context: *ConnectionContext, active_request: *ActiveRequest) !void {
        if (active_request.response.isSent()) {
            return; // Already sent
        }

        // Generate HTTP/3 frames for the response
        const frames = try active_request.response.generateFrames(self.allocator);
        defer {
            for (frames) |frame| {
                self.allocator.free(frame.payload);
            }
            self.allocator.free(frames);
        }

        // Send frames through QUIC connection
        for (frames) |frame| {
            try self.sendFrameToConnection(context.connection, active_request.response.stream_id, frame);
        }

        active_request.response.markSent();
        self.stats.addBytesSent(active_request.response.getBodySize());

        // Log response
        std.log.info("HTTP/3 response sent: {s} {s} - {}μs", .{
            active_request.request.method.toString(),
            active_request.request.path,
            active_request.duration(),
        });
    }

    fn sendFrameToConnection(self: *Self, connection: *Connection, stream_id: u64, frame: Frame.Frame) !void {
        // Get or create the QUIC stream for this HTTP/3 stream
        const stream = try connection.getOrCreateStream(stream_id);
        
        // Encode the frame with type and length
        var frame_data = std.ArrayList(u8).init(self.allocator);
        defer frame_data.deinit();
        
        // Write frame type (1 byte)
        try frame_data.append(@as(u8, @intCast(@intFromEnum(frame.frame_type))));
        
        // Write payload length (variable-length integer)
        try self.writeVarint(&frame_data, frame.payload.len);
        
        // Write payload
        try frame_data.appendSlice(frame.payload);
        
        // Send the frame data to the QUIC stream
        const bytes_written = try stream.write(frame_data.items, false);
        self.stats.addBytesSent(bytes_written);
        
        std.log.debug("Sent HTTP/3 frame type {} ({} bytes) on stream {}", .{
            frame.frame_type, bytes_written, stream_id
        });
    }
    
    /// Write a variable-length integer as defined in RFC 9000
    fn writeVarint(self: *Self, writer: *std.ArrayList(u8), value: usize) !void {
        _ = self;
        
        if (value < 64) {
            try writer.append(@intCast(value));
        } else if (value < 16384) {
            try writer.append(@intCast(0x40 | (value >> 8)));
            try writer.append(@intCast(value & 0xFF));
        } else if (value < 1073741824) {
            try writer.append(@intCast(0x80 | (value >> 24)));
            try writer.append(@intCast((value >> 16) & 0xFF));
            try writer.append(@intCast((value >> 8) & 0xFF));
            try writer.append(@intCast(value & 0xFF));
        } else {
            try writer.append(@intCast(0xC0 | (value >> 56)));
            try writer.append(@intCast((value >> 48) & 0xFF));
            try writer.append(@intCast((value >> 40) & 0xFF));
            try writer.append(@intCast((value >> 32) & 0xFF));
            try writer.append(@intCast((value >> 24) & 0xFF));
            try writer.append(@intCast((value >> 16) & 0xFF));
            try writer.append(@intCast((value >> 8) & 0xFF));
            try writer.append(@intCast(value & 0xFF));
        }
    }

    /// Add middleware to the server
    pub fn use(self: *Self, middleware: Middleware.MiddlewareFn) !void {
        try self.middleware_stack.append(middleware);
    }

    /// Add route handlers
    pub fn get(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.router.get(pattern, handler);
    }

    pub fn post(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.router.post(pattern, handler);
    }

    pub fn put(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.router.put(pattern, handler);
    }

    pub fn delete(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.router.delete(pattern, handler);
    }

    /// Set custom error handler
    pub fn setErrorHandler(self: *Self, handler: *const fn (*Request, *Response, Error.ZquicError) Error.ZquicError!void) void {
        self.router.setErrorHandler(handler);
    }

    /// Set custom 404 handler
    pub fn setNotFoundHandler(self: *Self, handler: HandlerFn) void {
        self.router.setNotFoundHandler(handler);
    }

    /// Get server statistics
    pub fn getStats(self: *const Self) ServerStats {
        return self.stats;
    }

    /// Cleanup expired connections
    pub fn cleanupExpiredConnections(self: *Self) void {
        var to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();

        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.*.isExpired(self.config.keep_alive_timeout_ms)) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |conn_id| {
            self.unregisterConnection(conn_id);
            std.log.info("Cleaned up expired connection: {s}", .{std.fmt.fmtSliceHexLower(conn_id)});
        }
    }

    /// Health check endpoint
    pub fn healthCheck(self: *const Self) bool {
        return self.running and self.stats.connections_active < self.config.max_connections;
    }
};

/// QPACK Encoder (basic implementation)
pub const QpackEncoder = struct {
    dynamic_table: std.ArrayList(HeaderField),
    allocator: std.mem.Allocator,

    const Self = @This();
    const HeaderField = @import("qpack.zig").HeaderField;

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .dynamic_table = std.ArrayList(HeaderField).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.dynamic_table.items) |*field| {
            field.deinit();
        }
        self.dynamic_table.deinit();
    }

    pub fn encode(self: *Self, headers: []const HeaderField, allocator: std.mem.Allocator) ![]u8 {
        _ = self;
        _ = headers;
        // Simplified: return empty encoded data
        return try allocator.alloc(u8, 0);
    }
};

test "server initialization" {
    const config = ServerConfig{};
    var server = try Http3Server.init(std.testing.allocator, config);
    defer server.deinit();

    try std.testing.expect(!server.running);
    try std.testing.expect(server.stats.connections_active == 0);
}

test "server stats tracking" {
    var stats = ServerStats.init();

    stats.incrementRequest();
    stats.incrementError();
    stats.addBytesReceived(100);
    stats.addBytesSent(200);

    try std.testing.expect(stats.requests_handled == 1);
    try std.testing.expect(stats.errors_count == 1);
    try std.testing.expect(stats.bytes_received == 100);
    try std.testing.expect(stats.bytes_sent == 200);
}
