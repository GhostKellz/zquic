//! Enhanced HTTP/3 server example
//!
//! Demonstrates the full-featured HTTP/3 server with routing, middleware, and advanced features

const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🚀 Enhanced ZQUIC HTTP/3 Server Example\n", .{});

    // Create server configuration
    const config = zquic.Http3.ServerConfig{
        .max_connections = 500,
        .max_streams_per_connection = 50,
        .request_timeout_ms = 30000,
        .keep_alive_timeout_ms = 60000,
        .max_request_body_size = 2 * 1024 * 1024, // 2MB
        .enable_push = true,
        .enable_compression = true,
        .compression_level = 6,
        .static_files_root = "./public",
        .enable_cors = true,
        .enable_security_headers = true,
    };

    // Initialize enhanced HTTP/3 server
    var server = try zquic.Http3.Http3Server.init(allocator, config);
    defer server.deinit();

    // Add custom middleware
    const auth_middleware = zquic.Http3.Middleware.AuthMiddleware.init(allocator, "my-secret-key");
    try server.use(auth_middleware.middleware());

    var rate_limit = zquic.Http3.Middleware.RateLimitMiddleware.init(allocator, 100, 60); // 100 requests per minute
    defer rate_limit.deinit();
    try server.use(rate_limit.middleware());

    // Define route handlers
    try server.get("/", homeHandler);
    try server.get("/health", healthHandler);
    try server.get("/api/users/:id", getUserHandler);
    try server.post("/api/users", createUserHandler);
    try server.put("/api/users/:id", updateUserHandler);
    try server.delete("/api/users/:id", deleteUserHandler);
    try server.get("/api/stats", statsHandler);
    try server.post("/api/upload", uploadHandler);

    // WebSocket-like streaming endpoint
    try server.get("/stream", streamHandler);

    // Set custom error handlers
    server.setNotFoundHandler(notFoundHandler);
    server.setErrorHandler(errorHandler);

    // Start server
    try server.start();
    defer server.stop();

    // Simulate HTTP/3 connection setup
    const local_cid = try zquic.Packet.ConnectionId.init(&[_]u8{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x08 });
    var connection = zquic.Connection.Connection.init(allocator, .server, local_cid);
    defer connection.deinit();

    connection.state = .established;
    const conn_id = try server.registerConnection(&connection);
    defer server.unregisterConnection(conn_id);

    std.debug.print("Server initialized with connection ID: {s}\n", .{std.fmt.fmtSliceHexLower(conn_id)});

    // Simulate incoming HTTP/3 requests
    try simulateRequests(&server, conn_id, allocator);

    // Display server statistics
    const stats = server.getStats();
    std.debug.print("\n📊 Server Statistics:\n", .{});
    std.debug.print("  Active connections: {}\n", .{stats.connections_active});
    std.debug.print("  Total connections: {}\n", .{stats.connections_total});
    std.debug.print("  Requests handled: {}\n", .{stats.requests_handled});
    std.debug.print("  Bytes sent: {}\n", .{stats.bytes_sent});
    std.debug.print("  Bytes received: {}\n", .{stats.bytes_received});
    std.debug.print("  Errors: {}\n", .{stats.errors_count});
    std.debug.print("  Uptime: {}s\n", .{stats.uptime()});

    std.debug.print("✅ Enhanced HTTP/3 server example completed!\n", .{});
}

/// Simulate various HTTP/3 requests
fn simulateRequests(server: *zquic.Http3.Http3Server, conn_id: []const u8, allocator: std.mem.Allocator) !void {
    std.debug.print("\n🔄 Simulating HTTP/3 requests...\n", .{});

    // Simulate GET / request
    try simulateGetRequest(server, conn_id, 1, "/", allocator);

    // Simulate API requests
    try simulateGetRequest(server, conn_id, 2, "/api/users/123", allocator);
    try simulatePostRequest(server, conn_id, 3, "/api/users", "{\"name\": \"Alice\", \"email\": \"alice@example.com\"}", allocator);

    // Simulate health check
    try simulateGetRequest(server, conn_id, 4, "/health", allocator);

    // Simulate 404
    try simulateGetRequest(server, conn_id, 5, "/nonexistent", allocator);

    // Simulate stats request
    try simulateGetRequest(server, conn_id, 6, "/api/stats", allocator);
}

fn simulateGetRequest(server: *zquic.Http3.Http3Server, conn_id: []const u8, stream_id: u64, path: []const u8, allocator: std.mem.Allocator) !void {
    // Create HEADERS frame
    const headers_payload = try createHeadersPayload(allocator, "GET", path, null);
    defer allocator.free(headers_payload);

    const headers_frame = zquic.Http3.Frame.Frame{
        .frame_type = .headers,
        .payload = headers_payload,
    };

    try server.processFrame(conn_id, stream_id, headers_frame);
    std.debug.print("  → GET {s}\n", .{path});
}

fn simulatePostRequest(server: *zquic.Http3.Http3Server, conn_id: []const u8, stream_id: u64, path: []const u8, body: []const u8, allocator: std.mem.Allocator) !void {
    // Create HEADERS frame
    const headers_payload = try createHeadersPayload(allocator, "POST", path, "application/json");
    defer allocator.free(headers_payload);

    const headers_frame = zquic.Http3.Frame.Frame{
        .frame_type = .headers,
        .payload = headers_payload,
    };

    try server.processFrame(conn_id, stream_id, headers_frame);

    // Create DATA frame
    const data_frame = zquic.Http3.Frame.Frame{
        .frame_type = .data,
        .payload = try allocator.dupe(u8, body),
    };
    defer allocator.free(data_frame.payload);

    try server.processFrame(conn_id, stream_id, data_frame);
    std.debug.print("  → POST {s} ({}B body)\n", .{ path, body.len });
}

fn createHeadersPayload(allocator: std.mem.Allocator, method: []const u8, path: []const u8, content_type: ?[]const u8) ![]u8 {
    // Simplified QPACK encoding (in reality, this would be properly encoded)
    var headers = std.ArrayList(u8).init(allocator);

    // Add pseudo-headers
    try headers.appendSlice(":method ");
    try headers.appendSlice(method);
    try headers.appendSlice("\n:path ");
    try headers.appendSlice(path);
    try headers.appendSlice("\n:scheme https\n:authority example.com\n");

    // Add content-type if provided
    if (content_type) |ct| {
        try headers.appendSlice("content-type ");
        try headers.appendSlice(ct);
        try headers.appendSlice("\n");
    }

    return headers.toOwnedSlice();
}

// Route Handlers

fn homeHandler(request: *zquic.Http3.Request, response: *zquic.Http3.Response) zquic.Error.ZquicError!void {
    _ = request;

    const html =
        \\<!DOCTYPE html>
        \\<html>
        \\<head>
        \\    <title>ZQUIC HTTP/3 Server</title>
        \\    <style>
        \\        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        \\        .header { text-align: center; color: #333; }
        \\        .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        \\        .feature { padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
        \\        .stats { background: #f5f5f5; padding: 15px; border-radius: 8px; }
        \\    </style>
        \\</head>
        \\<body>
        \\    <div class="header">
        \\        <h1>🚀 ZQUIC HTTP/3 Server</h1>
        \\        <p>Production-ready HTTP/3 implementation in Zig</p>
        \\    </div>
        \\    
        \\    <div class="features">
        \\        <div class="feature">
        \\            <h3>⚡ High Performance</h3>
        \\            <p>Zero-copy operations, minimal allocations, async networking</p>
        \\        </div>
        \\        <div class="feature">
        \\            <h3>🛡️ Security</h3>
        \\            <p>TLS 1.3, security headers, CORS support</p>
        \\        </div>
        \\        <div class="feature">
        \\            <h3>🔧 Middleware</h3>
        \\            <p>Authentication, rate limiting, compression, logging</p>
        \\        </div>
        \\        <div class="feature">
        \\            <h3>🎯 Routing</h3>
        \\            <p>Pattern matching, parameter extraction, RESTful APIs</p>
        \\        </div>
        \\    </div>
        \\    
        \\    <div class="stats">
        \\        <h3>📊 Quick Links</h3>
        \\        <ul>
        \\            <li><a href="/health">Health Check</a></li>
        \\            <li><a href="/api/stats">Server Statistics</a></li>
        \\            <li><a href="/api/users/123">Sample User API</a></li>
        \\        </ul>
        \\    </div>
        \\</body>
        \\</html>
    ;

    try response.html(html);
}

fn healthHandler(request: *zquic.Http3.Request, response: *zquic.Http3.Response) zquic.Error.ZquicError!void {
    _ = request;

    response.setStatus(.ok);
    try response.text("{\"status\": \"healthy\", \"timestamp\": 1703462400, \"uptime_seconds\": 3600, \"version\": \"1.0.0\", \"http3_enabled\": true}");
}

fn getUserHandler(request: *zquic.Http3.Request, response: *zquic.Http3.Response) zquic.Error.ZquicError!void {
    const user_id = zquic.Http3.Router.getParam(request, "id") orelse "unknown";

    var buffer: [256]u8 = undefined;
    const json_response = std.fmt.bufPrint(&buffer, "{{\"id\": \"{s}\", \"name\": \"John Doe\", \"email\": \"john@example.com\", \"created_at\": \"2024-01-01T00:00:00Z\", \"active\": true}}", .{user_id}) catch {
        response.setStatus(.internal_server_error);
        try response.text("Response too large");
        return;
    };

    try response.text(json_response);
}

fn createUserHandler(request: *zquic.Http3.Request, response: *zquic.Http3.Response) zquic.Error.ZquicError!void {
    const body = request.getBody();

    if (body.len == 0) {
        response.setStatus(.bad_request);
        try response.text("Request body required");
        return;
    }

    var buffer: [256]u8 = undefined;
    const json_response = std.fmt.bufPrint(&buffer, "{{\"id\": \"new-user-456\", \"name\": \"Created User\", \"email\": \"created@example.com\", \"created_at\": \"2024-12-24T00:00:00Z\", \"body_size\": {}}}", .{body.len}) catch {
        response.setStatus(.internal_server_error);
        try response.text("Response too large");
        return;
    };

    response.setStatus(.created);
    try response.text(json_response);
}

fn updateUserHandler(request: *zquic.Http3.Request, response: *zquic.Http3.Response) zquic.Error.ZquicError!void {
    const user_id = zquic.Http3.Router.getParam(request, "id") orelse "unknown";
    const body = request.getBody();

    var buffer: [256]u8 = undefined;
    const json_response = std.fmt.bufPrint(&buffer, "{{\"id\": \"{s}\", \"name\": \"Updated User\", \"email\": \"updated@example.com\", \"updated_at\": \"2024-12-24T00:00:00Z\", \"body_size\": {}}}", .{ user_id, body.len }) catch {
        response.setStatus(.internal_server_error);
        try response.text("Response too large");
        return;
    };

    try response.text(json_response);
}

fn deleteUserHandler(request: *zquic.Http3.Request, response: *zquic.Http3.Response) zquic.Error.ZquicError!void {
    const user_id = zquic.Http3.Router.getParam(request, "id") orelse "unknown";

    response.setStatus(.no_content);
    try response.setHeader("x-deleted-user", user_id);
}

fn statsHandler(request: *zquic.Http3.Request, response: *zquic.Http3.Response) zquic.Error.ZquicError!void {
    _ = request;

    const stats_json =
        \\{
        \\    "server_info": {
        \\        "name": "ZQUIC HTTP/3 Server",
        \\        "version": "1.0.0",
        \\        "protocol": "HTTP/3",
        \\        "start_time": "2024-12-24T00:00:00Z"
        \\    },
        \\    "metrics": {
        \\        "connections_active": 1,
        \\        "connections_total": 5,
        \\        "requests_handled": 25,
        \\        "bytes_sent": 51200,
        \\        "bytes_received": 12800,
        \\        "errors_count": 0,
        \\        "uptime_seconds": 7200
        \\    },
        \\    "features": {
        \\        "routing": true,
        \\        "middleware": true,
        \\        "compression": true,
        \\        "server_push": true,
        \\        "tls_1_3": true
        \\    }
        \\}
    ;

    try response.text(stats_json);
}

fn uploadHandler(request: *zquic.Http3.Request, response: *zquic.Http3.Response) zquic.Error.ZquicError!void {
    const body = request.getBody();
    const content_type = request.getContentType() orelse "application/octet-stream";

    var buffer: [512]u8 = undefined;
    const json_response = std.fmt.bufPrint(&buffer, "{{\"uploaded\": true, \"size\": {}, \"content_type\": \"{s}\", \"upload_id\": \"upload-123456\", \"timestamp\": {}}}", .{ body.len, content_type, std.time.timestamp() }) catch {
        response.setStatus(.internal_server_error);
        try response.text("Response too large");
        return;
    };

    response.setStatus(.created);
    try response.text(json_response);
}

fn streamHandler(request: *zquic.Http3.Request, response: *zquic.Http3.Response) zquic.Error.ZquicError!void {
    _ = request;

    // Simulate streaming data
    try response.setHeader("content-type", "text/plain");
    try response.setHeader("cache-control", "no-cache");

    var i: u32 = 0;
    while (i < 5) {
        try response.writeFormat("data: Streaming message {} at {}\n\n", .{ i + 1, std.time.timestamp() });
        i += 1;
    }
}

fn notFoundHandler(request: *zquic.Http3.Request, response: *zquic.Http3.Response) zquic.Error.ZquicError!void {
    var buffer: [512]u8 = undefined;
    const json_response = std.fmt.bufPrint(&buffer, "{{\"error\": \"Not Found\", \"message\": \"The requested resource was not found\", \"path\": \"{s}\", \"method\": \"{s}\", \"timestamp\": {}}}", .{ request.path, request.method.toString(), std.time.timestamp() }) catch {
        response.setStatus(.internal_server_error);
        try response.text("Response too large");
        return;
    };

    response.setStatus(.not_found);
    try response.text(json_response);
}

fn errorHandler(request: *zquic.Http3.Request, response: *zquic.Http3.Response, error_code: zquic.Error.ZquicError) zquic.Error.ZquicError!void {
    _ = request;

    var buffer: [256]u8 = undefined;
    const error_name = switch (error_code) {
        else => "InternalError",
    };
    const json_response = std.fmt.bufPrint(&buffer, "{{\"error\": \"Internal Server Error\", \"message\": \"An unexpected error occurred\", \"error_code\": \"{s}\", \"timestamp\": {}}}", .{ error_name, std.time.timestamp() }) catch {
        response.setStatus(.internal_server_error);
        try response.text("Error response too large");
        return;
    };

    response.setStatus(.internal_server_error);
    try response.text(json_response);
}
