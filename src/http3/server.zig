//! HTTP/3 Server Implementation
//!
//! High-performance HTTP/3 server without external dependencies

const std = @import("std");
const Error = @import("../utils/error.zig");
const Time = @import("../utils/time.zig");
const Frame = @import("frame.zig");
const QpackDecoder = @import("qpack.zig").QpackDecoder;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Router = @import("router.zig").Router;
const HandlerFn = @import("router.zig").HandlerFn;
const NextFn = @import("router.zig").NextFn;
const Middleware = @import("middleware.zig");
const Connection = @import("../core/connection.zig").Connection;
const Stream = @import("../core/stream.zig");
const PrometheusMetrics = @import("../monitoring/prometheus_exporter.zig").PrometheusMetrics;

/// Server configuration for high performance
pub const SuperServerConfig = struct {
    max_connections: u32 = 100_000, // 100k concurrent connections
    max_streams_per_connection: u32 = 1000, // 1k streams per connection
    request_timeout_ms: u32 = 5000, // 5s timeout for fast responses
    keep_alive_timeout_ms: u32 = 30000, // 30s keep-alive
    max_request_body_size: usize = 10 * 1024 * 1024, // 10MB for large uploads
    enable_push: bool = true, // HTTP/3 server push
    enable_compression: bool = true,
    compression_level: u8 = 6,
    static_files_root: ?[]const u8 = null,
    enable_cors: bool = true,
    cors_origins: []const []const u8 = &[_][]const u8{"*"}, // Allow all origins
    enable_security_headers: bool = true,

    // Performance settings
    request_batch_size: u32 = 64, // Process 64 requests in batch
    response_batch_size: u32 = 64, // Send 64 responses in batch
    worker_threads: u32 = 0, // Auto-detect CPU cores
    enable_zero_copy: bool = true, // Zero-copy optimizations
};

/// Legacy alias for compatibility
pub const ServerConfig = SuperServerConfig;

/// Server statistics with atomic counters
pub const SuperServerStats = struct {
    connections_active: std.atomic.Value(u32),
    connections_total: std.atomic.Value(u64),
    requests_handled: std.atomic.Value(u64),
    requests_per_second: std.atomic.Value(u64),
    bytes_sent: std.atomic.Value(u64),
    bytes_received: std.atomic.Value(u64),
    errors_count: std.atomic.Value(u64),
    start_time: i64,
    peak_rps: std.atomic.Value(u64),
    avg_response_time_us: std.atomic.Value(u64),

    const Self = @This();

    pub fn init() Self {
        return Self{
            .connections_active = std.atomic.Value(u32).init(0),
            .connections_total = std.atomic.Value(u64).init(0),
            .requests_handled = std.atomic.Value(u64).init(0),
            .requests_per_second = std.atomic.Value(u64).init(0),
            .bytes_sent = std.atomic.Value(u64).init(0),
            .bytes_received = std.atomic.Value(u64).init(0),
            .errors_count = std.atomic.Value(u64).init(0),
            .start_time = Time.nowSeconds(),
            .peak_rps = std.atomic.Value(u64).init(0),
            .avg_response_time_us = std.atomic.Value(u64).init(0),
        };
    }

    /// Get uptime in seconds
    pub fn uptime(self: *const Self) i64 {
        return Time.nowSeconds() - self.start_time;
    }

    /// Increment request counter atomically
    pub fn incrementRequest(self: *Self) void {
        _ = self.requests_handled.fetchAdd(1, .acq_rel);
    }

    /// Increment error counter atomically
    pub fn incrementError(self: *Self) void {
        _ = self.errors_count.fetchAdd(1, .acq_rel);
    }

    /// Add bytes received atomically
    pub fn addBytesReceived(self: *Self, bytes: u64) void {
        _ = self.bytes_received.fetchAdd(bytes, .acq_rel);
    }

    /// Add bytes sent atomically
    pub fn addBytesSent(self: *Self, bytes: u64) void {
        _ = self.bytes_sent.fetchAdd(bytes, .acq_rel);
    }
};

/// HTTP/3 Server with async processing pipeline
pub const SuperHttp3Server = struct {
    config: SuperServerConfig,
    stats: SuperServerStats,
    allocator: std.mem.Allocator,

    // Request/response queues
    request_queue: std.ArrayListUnmanaged(Request),
    response_queue: std.ArrayListUnmanaged(Response),

    is_running: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: SuperServerConfig) !Self {
        return Self{
            .config = config,
            .stats = SuperServerStats.init(),
            .allocator = allocator,
            .request_queue = .empty,
            .response_queue = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.request_queue.deinit(self.allocator);
        self.response_queue.deinit(self.allocator);
    }

    /// Run the HTTP/3 server
    pub fn runSuperServer(self: *Self) !void {
        self.is_running = true;

        // Main server loop
        while (self.is_running) {
            try self.manageConnections();
            Time.sleep(std.time.ns_per_ms);
        }
    }

    fn manageConnections(self: *Self) !void {
        // Process pending requests
        while (self.request_queue.items.len > 0) {
            _ = self.request_queue.orderedRemove(0);
            // Process request...
        }
    }
};

/// Connection context for managing HTTP/3 connections
pub const ConnectionContext = struct {
    connection: *Connection,
    active_requests: std.AutoHashMapUnmanaged(u64, *ActiveRequest),
    last_activity: i64,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, connection: *Connection) Self {
        return Self{
            .connection = connection,
            .active_requests = .empty,
            .last_activity = Time.nowSeconds(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iterator = self.active_requests.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.active_requests.deinit(self.allocator);
    }

    pub fn updateActivity(self: *Self) void {
        self.last_activity = Time.nowSeconds();
    }

    pub fn isExpired(self: *const Self, timeout_ms: u32) bool {
        const now = Time.nowSeconds();
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
            .start_time = Time.nowMicros(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.request.deinit();
        self.response.deinit();
    }

    pub fn duration(self: *const Self) i64 {
        return Time.nowMicros() - self.start_time;
    }
};

/// Enhanced HTTP/3 server
pub const Http3Server = struct {
    allocator: std.mem.Allocator,
    qpack_decoder: QpackDecoder,
    router: Router,
    config: SuperServerConfig,
    stats: SuperServerStats,
    connections: std.StringHashMapUnmanaged(*ConnectionContext),
    middleware_stack: std.ArrayListUnmanaged(Middleware.MiddlewareFn),
    middleware_config: Middleware.MiddlewareConfig,
    running: bool = false,
    metrics: ?*PrometheusMetrics = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: SuperServerConfig) !Self {
        var server = Self{
            .allocator = allocator,
            .qpack_decoder = QpackDecoder.init(allocator, 4096),
            .router = Router.init(allocator),
            .config = config,
            .stats = SuperServerStats.init(),
            .connections = .empty,
            .middleware_stack = .empty,
            .middleware_config = Middleware.MiddlewareConfig{},
            .metrics = null,
        };

        // Setup default middleware
        try server.setupDefaultMiddleware();

        return server;
    }

    pub fn deinit(self: *Self) void {
        self.qpack_decoder.deinit(self.allocator);
        self.router.deinit();

        // Clean up connections
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.connections.deinit(self.allocator);
        self.middleware_stack.deinit(self.allocator);
    }

    fn setupDefaultMiddleware(self: *Self) !void {
        // Configure middleware_config based on server settings
        self.middleware_config.security_hsts_enabled = self.config.enable_security_headers;
        self.middleware_config.compression_enabled = self.config.enable_compression;
        if (self.config.static_files_root) |static_root| {
            self.middleware_config.static_root_dir = static_root;
        }

        // Security headers (if enabled)
        if (self.config.enable_security_headers) {
            var security = Middleware.SecurityMiddleware.init(self.allocator);
            const handler = security.middleware();
            try self.middleware_stack.append(self.allocator, handler);
            try self.router.use(handler);
        }

        // CORS (if enabled)
        if (self.config.enable_cors) {
            var cors = Middleware.CorsMiddleware.init(self.allocator);
            defer cors.deinit();
            const handler = cors.middleware();
            try self.middleware_stack.append(self.allocator, handler);
            try self.router.use(handler);
        }

        // Compression (if enabled)
        if (self.config.enable_compression) {
            const compression = Middleware.CompressionMiddleware.init(self.allocator, self.config.compression_level, 256 // min size
            );
            self.middleware_config.compression_min_size = 256;
            const handler = compression.middleware();
            try self.middleware_stack.append(self.allocator, handler);
            try self.router.use(handler);
        }

        // Static files (if configured)
        if (self.config.static_files_root) |static_root| {
            const static_middleware = Middleware.StaticMiddleware.init(self.allocator, static_root);
            const handler = static_middleware.middleware();
            try self.middleware_stack.append(self.allocator, handler);
            try self.router.use(handler);
        }

        // Logging
        const logging = Middleware.LoggingMiddleware.init(self.allocator, .info);
        const handler = logging.middleware();
        try self.middleware_stack.append(self.allocator, handler);
        try self.router.use(handler);
    }

    /// Start the server
    pub fn start(self: *Self) !void {
        self.running = true;
        std.log.info("HTTP/3 server started with {} middleware(s)", .{self.middleware_stack.items.len});
    }

    pub fn attachPrometheus(self: *Self, metrics: *PrometheusMetrics) void {
        self.metrics = metrics;
    }

    /// Stop the server
    pub fn stop(self: *Self) void {
        self.running = false;
        std.log.info("HTTP/3 server stopped", .{});
    }

    /// Register a new connection
    pub fn registerConnection(self: *Self, connection: *Connection) ![]const u8 {
        const conn_id = try self.allocator.dupe(u8, connection.super_connection.local_conn_id.bytes());
        errdefer self.allocator.free(conn_id);

        const context = try self.allocator.create(ConnectionContext);
        errdefer self.allocator.destroy(context);

        context.* = ConnectionContext.init(self.allocator, connection);

        try self.connections.put(self.allocator, conn_id, context);
        _ = self.stats.connections_active.fetchAdd(1, .acq_rel);
        _ = self.stats.connections_total.fetchAdd(1, .acq_rel);
        if (self.metrics) |metrics| {
            metrics.recordHttp3ConnectionOpened();
        }

        std.log.info("Registered HTTP/3 connection: {any}", .{conn_id});
        return conn_id;
    }

    /// Unregister a connection
    pub fn unregisterConnection(self: *Self, connection_id: []const u8) void {
        if (self.connections.fetchRemove(connection_id)) |entry| {
            entry.value.deinit();
            self.allocator.destroy(entry.value);
            self.allocator.free(entry.key);
            _ = self.stats.connections_active.fetchSub(1, .acq_rel);
            if (self.metrics) |metrics| {
                metrics.recordHttp3ConnectionClosed();
            }
        }
    }

    /// Process incoming HTTP/3 frames
    pub fn processFrame(self: *Self, connection_id: []const u8, stream_id: u64, frame: Frame.Frame) !void {
        const context = self.connections.get(connection_id) orelse {
            std.log.warn("Frame received for unknown connection: {any}", .{connection_id});
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

        // For requests without body (GET, HEAD, etc), process and respond immediately.
        // For requests with body (POST, PUT, PATCH), wait for DATA frames in processDataFrame.
        if (!active_request.request.expectsBody()) {
            try self.processRequest(active_request);
            try self.sendResponse(context, active_request);
        }
        // Body-bearing requests: handler runs only after body is complete (processDataFrame)
    }

    fn processDataFrame(self: *Self, context: *ConnectionContext, stream_id: u64, payload: []const u8) !void {
        if (context.active_requests.get(stream_id)) |active_request| {
            // Append data to request body
            try active_request.request.appendBody(payload);
            self.stats.addBytesReceived(payload.len);

            const body_len = active_request.request.getBody().len;

            // Check body size limit
            if (body_len > self.config.max_request_body_size) {
                active_request.response.setStatus(.payload_too_large);
                try active_request.response.text("Request body too large");
                try self.sendResponse(context, active_request);
                return;
            }

            // Check if body is complete based on Content-Length
            if (active_request.request.getContentLength()) |expected_len| {
                if (body_len >= expected_len) {
                    // Body is complete, process and send response
                    try self.processRequest(active_request);
                    try self.sendResponse(context, active_request);
                }
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
        const conn_id_bytes = context.connection.super_connection.local_conn_id.bytes();
        active_request.* = ActiveRequest.init(self.allocator, stream_id, conn_id_bytes);

        try context.active_requests.put(self.allocator, stream_id, active_request);
        return active_request;
    }

    fn processRequest(self: *Self, active_request: *ActiveRequest) !void {
        self.stats.incrementRequest();

        // Set middleware config on request for handlers to access
        active_request.request.middleware_config = @ptrCast(&self.middleware_config);

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
        std.log.info("HTTP/3 response sent: {s} {s} - {}us", .{
            active_request.request.method.toString(),
            active_request.request.path,
            active_request.duration(),
        });

        self.recordPrometheusSample(active_request);

        // Clean up completed request to prevent memory leak
        const stream_id = active_request.response.stream_id;
        active_request.deinit();
        self.allocator.destroy(active_request);
        _ = context.active_requests.remove(stream_id);
    }

    fn sendFrameToConnection(self: *Self, connection: *Connection, stream_id: u64, frame: Frame.Frame) !void {
        // Use the existing request stream - HTTP/3 responses MUST go on the same stream as the request
        const stream = connection.getStream(stream_id) orelse return Error.ZquicError.StreamNotFound;

        // Encode the frame with type and length
        var frame_data: std.ArrayListUnmanaged(u8) = .empty;
        defer frame_data.deinit(self.allocator);
        try frame_data.ensureTotalCapacity(self.allocator, 64);

        // Write frame type (1 byte)
        try frame_data.append(self.allocator, @as(u8, @intCast(@backingInt(frame.frame_type))));

        // Write payload length (variable-length integer)
        try self.writeVarint(&frame_data, frame.payload.len);

        // Write payload
        try frame_data.appendSlice(self.allocator, frame.payload);

        // Send the frame data to the QUIC stream
        const bytes_written = try stream.write(frame_data.items, false);
        self.stats.addBytesSent(bytes_written);

        std.log.debug("Sent HTTP/3 frame type {} ({} bytes) on stream {}", .{ frame.frame_type, bytes_written, stream_id });
    }

    /// Write a variable-length integer as defined in RFC 9000
    fn writeVarint(self: *Self, writer: *std.ArrayListUnmanaged(u8), value: usize) !void {
        if (value < 64) {
            try writer.append(self.allocator, @intCast(value));
        } else if (value < 16384) {
            try writer.append(self.allocator, @intCast(0x40 | (value >> 8)));
            try writer.append(self.allocator, @intCast(value & 0xFF));
        } else if (value < 1073741824) {
            try writer.append(self.allocator, @intCast(0x80 | (value >> 24)));
            try writer.append(self.allocator, @intCast((value >> 16) & 0xFF));
            try writer.append(self.allocator, @intCast((value >> 8) & 0xFF));
            try writer.append(self.allocator, @intCast(value & 0xFF));
        } else {
            try writer.append(self.allocator, @intCast(0xC0 | (value >> 56)));
            try writer.append(self.allocator, @intCast((value >> 48) & 0xFF));
            try writer.append(self.allocator, @intCast((value >> 40) & 0xFF));
            try writer.append(self.allocator, @intCast((value >> 32) & 0xFF));
            try writer.append(self.allocator, @intCast((value >> 24) & 0xFF));
            try writer.append(self.allocator, @intCast((value >> 16) & 0xFF));
            try writer.append(self.allocator, @intCast((value >> 8) & 0xFF));
            try writer.append(self.allocator, @intCast(value & 0xFF));
        }
    }

    /// Add middleware to the server
    pub fn use(self: *Self, middleware: Middleware.MiddlewareFn) !void {
        try self.middleware_stack.append(self.allocator, middleware);
        try self.router.use(middleware);
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
    pub fn getStats(self: *const Self) SuperServerStats {
        return self.stats;
    }

    /// Cleanup expired connections
    pub fn cleanupExpiredConnections(self: *Self) void {
        var to_remove: std.ArrayListUnmanaged([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);
        to_remove.ensureTotalCapacity(self.allocator, 10) catch return;

        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.*.isExpired(self.config.keep_alive_timeout_ms)) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |conn_id| {
            self.unregisterConnection(conn_id);
            std.log.info("Cleaned up expired connection: {any}", .{conn_id});
        }
    }

    /// Health check endpoint
    pub fn healthCheck(self: *const Self) bool {
        return self.running and self.stats.connections_active.load(.acquire) < self.config.max_connections;
    }

    fn recordPrometheusSample(self: *Self, active_request: *ActiveRequest) void {
        if (self.metrics) |metrics| {
            const req_size = active_request.request.getBody().len;
            const resp_size = active_request.response.getBodySize();
            const status_code = @backingInt(active_request.response.status);
            const success = status_code < 500;
            metrics.recordHttp3Request(req_size, resp_size, active_request.duration(), success);
        }
    }
};

test "server initialization" {
    const config = SuperServerConfig{};
    var server = try Http3Server.init(std.testing.allocator, config);
    defer server.deinit();

    try std.testing.expect(!server.running);
    try std.testing.expect(server.stats.connections_active.load(.acquire) == 0);
}

test "server.use registers middleware with router" {
    const config = SuperServerConfig{
        .enable_security_headers = false,
        .enable_cors = false,
        .enable_compression = false,
        .static_files_root = null,
    };

    var server = try Http3Server.init(std.testing.allocator, config);
    defer server.deinit();

    var middleware_seen = false;

    const test_middleware = struct {
        fn flag(req: *Request, res: *Response, next: NextFn) Error.ZquicError!void {
            const flag_ptr: *bool = @ptrCast(@alignCast(req.context.user_data orelse return Error.ZquicError.InternalError));
            flag_ptr.* = true;
            try next(req, res);
        }
    };

    try server.use(test_middleware.flag);

    const handler = struct {
        fn ok(_: *Request, res: *Response) Error.ZquicError!void {
            try res.text("ok");
        }
    }.ok;

    try server.get("/health", handler);

    var request = Request.init(std.testing.allocator, 1, "conn-1");
    defer request.deinit();
    request.method = .GET;
    request.uri = try request.allocator.dupe(u8, "/health");
    request.path = try request.allocator.dupe(u8, "/health");
    request.context.user_data = &middleware_seen;

    var response = Response.init(std.testing.allocator, request.context.stream_id);
    defer response.deinit();

    try server.router.handleRequest(&request, &response);
    try std.testing.expect(middleware_seen);
    try std.testing.expect(std.mem.eql(u8, response.getBody(), "ok"));
}

test "server rejects oversized request body and cleans up active request" {
    const allocator = std.testing.allocator;
    var server = try Http3Server.init(allocator, .{
        .max_request_body_size = 4,
        .enable_security_headers = false,
        .enable_cors = false,
        .enable_compression = false,
        .static_files_root = null,
    });
    defer server.deinit();

    var connection = try Connection.init(allocator, .server, .{});
    defer connection.deinit();

    try connection.queueStreamEvent(.{ .new_stream = .{
        .stream_id = 0,
        .stream_type = .client_bidirectional,
    } });
    try connection.processPendingStreamEvents();
    const stream = connection.getStream(0).?;

    var context = ConnectionContext.init(allocator, &connection);
    defer context.deinit();

    const active_request = try allocator.create(ActiveRequest);
    active_request.* = ActiveRequest.init(allocator, 0, "conn-body-limit");
    try context.active_requests.put(allocator, 0, active_request);

    try server.processDataFrame(&context, 0, "abcde");

    try std.testing.expect(context.active_requests.get(0) == null);
    try std.testing.expect(stream.write_buffer.items.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, stream.write_buffer.items, "Request body too large") != null);
    try std.testing.expectEqual(@as(u64, 5), server.stats.bytes_received.load(.acquire));
}

test "server stats tracking" {
    var stats = SuperServerStats.init();

    stats.incrementRequest();
    stats.incrementError();
    stats.addBytesReceived(100);
    stats.addBytesSent(200);

    try std.testing.expect(stats.requests_handled.load(.acquire) == 1);
    try std.testing.expect(stats.errors_count.load(.acquire) == 1);
    try std.testing.expect(stats.bytes_received.load(.acquire) == 100);
    try std.testing.expect(stats.bytes_sent.load(.acquire) == 200);
}
