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

/// CORS (Cross-Origin Resource Sharing) middleware
pub const CorsMiddleware = struct {
    allowed_origins: std.ArrayList([]const u8),
    allowed_methods: std.ArrayList([]const u8),
    allowed_headers: std.ArrayList([]const u8),
    allow_credentials: bool,
    max_age: ?u32,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        var cors_middleware = Self{
            .allowed_origins = std.ArrayList([]const u8).init(allocator),
            .allowed_methods = std.ArrayList([]const u8).init(allocator),
            .allowed_headers = std.ArrayList([]const u8).init(allocator),
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
        self.allowed_origins.deinit();
        self.allowed_methods.deinit();
        self.allowed_headers.deinit();
    }

    pub fn addOrigin(self: *Self, origin: []const u8) !void {
        try self.allowed_origins.append(try self.allocator.dupe(u8, origin));
    }

    pub fn addMethod(self: *Self, method: []const u8) !void {
        try self.allowed_methods.append(try self.allocator.dupe(u8, method));
    }

    pub fn addHeader(self: *Self, header: []const u8) !void {
        try self.allowed_headers.append(try self.allocator.dupe(u8, header));
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
                const start_time = std.time.microTimestamp();

                // Log request
                std.log.info("HTTP/3 {s} {s} - Stream {}", .{ request.method.toString(), request.path, request.context.stream_id });

                try next(request, response);

                // Log response
                const duration = std.time.microTimestamp() - start_time;
                std.log.info("HTTP/3 {s} {s} {} - {}μs", .{ request.method.toString(), request.path, response.status.getCode(), duration });
            }
        }.handle;
    }
};

/// Rate limiting middleware
pub const RateLimitMiddleware = struct {
    max_requests: u32,
    window_seconds: u32,
    client_requests: std.HashMap(u64, RequestWindow, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
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
            .client_requests = std.HashMap(u64, RequestWindow, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.client_requests.deinit();
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
        _ = self;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Only handle GET requests for files
                if (request.method != .GET) {
                    try next(request, response);
                    return;
                }

                // Construct file path (simplified - would use self.root_dir)
                var path_buffer: [512]u8 = undefined;
                const file_path = std.fmt.bufPrint(&path_buffer, "./public{s}", .{request.path}) catch {
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
                try response.setHeader("Cache-Control", "public, max-age=3600");
            }
        }.handle;
    }
};

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
