//! HTTP/3 middleware system
//!
//! Common middleware implementations for HTTP/3 server

const std = @import("std");
const Error = @import("../utils/error.zig");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Router = @import("router.zig");
const NextFn = Router.NextFn;
pub const MiddlewareFn = Router.MiddlewareFn;

var static_root_dir: []const u8 = "./public";
var static_cache_control: []const u8 = "public, max-age=3600";

/// CORS (Cross-Origin Resource Sharing) middleware
pub const CorsMiddleware = struct {
    allowed_origins: std.ArrayListUnmanaged([]const u8),
    allowed_methods: std.ArrayListUnmanaged([]const u8),
    allowed_headers: std.ArrayListUnmanaged([]const u8),
    allow_credentials: bool,
    max_age: ?u32,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        var cors_middleware = Self{
            .allowed_origins = .{},
            .allowed_methods = .{},
            .allowed_headers = .{},
            .allow_credentials = false,
            .max_age = null,
            .allocator = allocator,
        };

        // Default values
        cors_middleware.addOrigin("*") catch {};
        cors_middleware.addMethod("GET") catch {};
        cors_middleware.addMethod("POST") catch {};
        cors_middleware.addMethod("PUT") catch {};
        cors_middleware.addMethod("DELETE") catch {};
        cors_middleware.addMethod("OPTIONS") catch {};
        cors_middleware.addHeader("Content-Type") catch {};
        cors_middleware.addHeader("Authorization") catch {};

        return cors_middleware;
    }

    pub fn deinit(self: *Self) void {
        for (self.allowed_origins.items) |origin| {
            self.allocator.free(origin);
        }
        for (self.allowed_methods.items) |method| {
            self.allocator.free(method);
        }
        for (self.allowed_headers.items) |header| {
            self.allocator.free(header);
        }
        self.allowed_origins.deinit(self.allocator);
        self.allowed_methods.deinit(self.allocator);
        self.allowed_headers.deinit(self.allocator);
    }

    pub fn addOrigin(self: *Self, origin: []const u8) !void {
        try self.allowed_origins.append(self.allocator, try self.allocator.dupe(u8, origin));
    }

    pub fn addMethod(self: *Self, method: []const u8) !void {
        try self.allowed_methods.append(self.allocator, try self.allocator.dupe(u8, method));
    }

    pub fn addHeader(self: *Self, header: []const u8) !void {
        try self.allowed_headers.append(self.allocator, try self.allocator.dupe(u8, header));
    }

    pub fn middleware(self: *const Self) MiddlewareFn {
        // Instead of capturing in closure, we return a function that uses global state
        // This is a simplified approach - real implementation would need proper closure handling
        _ = self;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Set CORS headers (simplified)
                try response.setHeader("Access-Control-Allow-Origin", "*");
                try response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
                try response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

                // Handle preflight OPTIONS request
                if (request.method == .OPTIONS) {
                    response.setStatus(.ok);
                    return;
                }

                try next(request, response);
            }
        }.handle;
    }
};

/// Authentication middleware
pub const AuthMiddleware = struct {
    secret_key: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, secret_key: []const u8) Self {
        return Self{
            .secret_key = secret_key,
            .allocator = allocator,
        };
    }

    pub fn middleware(self: *const Self) MiddlewareFn {
        _ = self;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Check for Authorization header
                if (request.getHeader("authorization")) |auth_header| {
                    if (std.mem.startsWith(u8, auth_header, "Bearer ")) {
                        const token = auth_header[7..];

                        // Simplified token validation
                        if (token.len > 0) {
                            try next(request, response);
                            return;
                        }
                    }
                }

                // Unauthorized
                response.setStatus(.unauthorized);
                try response.setHeader("WWW-Authenticate", "Bearer");
                try response.text("{\"error\": \"Unauthorized\", \"message\": \"Valid authentication token required\"}");
            }
        }.handle;
    }
};

/// Logging middleware
pub const LoggingMiddleware = struct {
    log_level: LogLevel,
    allocator: std.mem.Allocator,

    const LogLevel = enum {
        debug,
        info,
        warn,
        err,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, log_level: LogLevel) Self {
        return Self{
            .log_level = log_level,
            .allocator = allocator,
        };
    }

    pub fn middleware(self: *const Self) MiddlewareFn {
        _ = self;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                const ts_start = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
                const start_time = @divTrunc((@as(i128, ts_start.sec) * std.time.ns_per_s + ts_start.nsec), 1000);

                // Log request
                std.log.info("HTTP/3 {s} {s} - Stream {}", .{ request.method.toString(), request.path, request.context.stream_id });

                try next(request, response);

                // Log response
                const ts_end = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
                const end_time = @divTrunc((@as(i128, ts_end.sec) * std.time.ns_per_s + ts_end.nsec), 1000);
                const duration = end_time - start_time;
                std.log.info("HTTP/3 {s} {s} {} - {}μs", .{ request.method.toString(), request.path, response.status.getCode(), duration });
            }
        }.handle;
    }
};

/// Rate limiting middleware
pub const RateLimitMiddleware = struct {
    max_requests: u32,
    window_seconds: u32,
    client_requests: std.AutoHashMapUnmanaged(u64, RequestWindow),
    allocator: std.mem.Allocator,

    const RequestWindow = struct {
        count: u32,
        window_start: i64,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, max_requests: u32, window_seconds: u32) Self {
        return Self{
            .max_requests = max_requests,
            .window_seconds = window_seconds,
            .client_requests = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.client_requests.deinit(self.allocator);
    }

    pub fn middleware(_: *Self) MiddlewareFn {
        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Check rate limit (simplified implementation)
                // In a real implementation, would track request.context.stream_id
                const is_allowed = true;

                if (!is_allowed) {
                    response.setStatus(.too_many_requests);
                    try response.setHeader("Retry-After", "60");
                    try response.text("{\"error\": \"Rate limit exceeded\", \"message\": \"Too many requests\"}");
                    return;
                }

                try next(request, response);
            }
        }.handle;
    }
};

/// Compression middleware (simplified)
pub const CompressionMiddleware = struct {
    compression_level: u8,
    min_size: usize,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, compression_level: u8, min_size: usize) Self {
        return Self{
            .compression_level = compression_level,
            .min_size = min_size,
            .allocator = allocator,
        };
    }

    pub fn middleware(self: *const Self) MiddlewareFn {
        _ = self;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                try next(request, response);

                // Check if client accepts compression (simplified)
                if (request.getHeader("accept-encoding")) |encoding| {
                    if (std.mem.indexOf(u8, encoding, "gzip") != null) {
                        // Would implement actual compression here
                        try response.setHeader("Content-Encoding", "gzip");
                    }
                }
            }
        }.handle;
    }
};

/// Security headers middleware
pub const SecurityMiddleware = struct {
    enable_hsts: bool,
    hsts_max_age: u32,
    enable_xss_protection: bool,
    enable_content_type_options: bool,
    enable_frame_options: bool,
    csp_policy: ?[]const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .enable_hsts = true,
            .hsts_max_age = 31536000, // 1 year
            .enable_xss_protection = true,
            .enable_content_type_options = true,
            .enable_frame_options = true,
            .csp_policy = null,
            .allocator = allocator,
        };
    }

    pub fn setCSP(self: *Self, policy: []const u8) !void {
        if (self.csp_policy) |old_policy| {
            self.allocator.free(old_policy);
        }
        self.csp_policy = try self.allocator.dupe(u8, policy);
    }

    pub fn deinit(self: *Self) void {
        if (self.csp_policy) |policy| {
            self.allocator.free(policy);
        }
    }

    pub fn middleware(self: *const Self) MiddlewareFn {
        _ = self;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                try next(request, response);

                // Add security headers (simplified)
                try response.setHeader("X-Content-Type-Options", "nosniff");
                try response.setHeader("X-Frame-Options", "DENY");
                try response.setHeader("X-XSS-Protection", "1; mode=block");
                try response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
            }
        }.handle;
    }
};

/// Static file serving middleware
pub const StaticMiddleware = struct {
    root_dir: []const u8,
    cache_control: []const u8,
    enable_directory_listing: bool,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, root_dir: []const u8) Self {
        return Self{
            .root_dir = root_dir,
            .cache_control = "public, max-age=3600",
            .enable_directory_listing = false,
            .allocator = allocator,
        };
    }

    pub fn middleware(self: *const Self) MiddlewareFn {
        static_root_dir = self.root_dir;
        static_cache_control = self.cache_control;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Only handle GET requests for files
                if (request.method != .GET) {
                    try next(request, response);
                    return;
                }

                var path_buffer: [512]u8 = undefined;
                const file_path = buildStaticFilePath(&path_buffer, static_root_dir, request.path) catch {
                    try next(request, response);
                    return;
                };

                // Try to serve the file
                response.sendFile(file_path) catch |err| switch (err) {
                    error.FileNotFound => {
                        try next(request, response);
                        return;
                    },
                    // For any other file system errors, just pass to next middleware
                    else => {
                        try next(request, response);
                        return;
                    },
                };

                // Set cache headers
                try response.setHeader("Cache-Control", static_cache_control);
            }
        }.handle;
    }
};

fn buildStaticFilePath(buffer: []u8, root_dir: []const u8, request_path: []const u8) Error.ZquicError![]const u8 {
    var used: usize = 0;

    if (root_dir.len > buffer.len) return Error.ZquicError.BufferTooSmall;
    @memcpy(buffer[0..root_dir.len], root_dir);
    used += root_dir.len;

    if (root_dir.len == 0 or root_dir[root_dir.len - 1] != '/') {
        if (used >= buffer.len) return Error.ZquicError.BufferTooSmall;
        buffer[used] = '/';
        used += 1;
    }

    const trimmed = if (request_path.len > 0 and request_path[0] == '/') request_path[1..] else request_path;
    if (used + trimmed.len > buffer.len) return Error.ZquicError.BufferTooSmall;
    @memcpy(buffer[used .. used + trimmed.len], trimmed);
    used += trimmed.len;

    return buffer[0..used];
}

test "cors middleware creation" {
    var cors = CorsMiddleware.init(std.testing.allocator);
    defer cors.deinit();

    try std.testing.expect(cors.allowed_origins.items.len > 0);
    try std.testing.expect(cors.allowed_methods.items.len > 0);
}

test "auth middleware creation" {
    const auth = AuthMiddleware.init(std.testing.allocator, "test-secret");

    try std.testing.expect(std.mem.eql(u8, auth.secret_key, "test-secret"));
}

test "logging middleware creation" {
    const logging = LoggingMiddleware.init(std.testing.allocator, .info);

    try std.testing.expect(logging.log_level == .info);
}
