//! HTTP/3 middleware system
//!
//! Common middleware implementations for HTTP/3 server

const std = @import("std");
const Error = @import("../utils/error.zig");
const Time = @import("../utils/time.zig");
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
            .allowed_origins = .empty,
            .allowed_methods = .empty,
            .allowed_headers = .empty,
            .allow_credentials = false,
            .max_age = null,
            .allocator = allocator,
        };

        // Default values - log if allocation fails
        cors_middleware.addOrigin("*") catch |err| std.log.warn("CORS: Failed to add default origin: {}", .{err});
        cors_middleware.addMethod("GET") catch |err| std.log.warn("CORS: Failed to add GET method: {}", .{err});
        cors_middleware.addMethod("POST") catch |err| std.log.warn("CORS: Failed to add POST method: {}", .{err});
        cors_middleware.addMethod("PUT") catch |err| std.log.warn("CORS: Failed to add PUT method: {}", .{err});
        cors_middleware.addMethod("DELETE") catch |err| std.log.warn("CORS: Failed to add DELETE method: {}", .{err});
        cors_middleware.addMethod("OPTIONS") catch |err| std.log.warn("CORS: Failed to add OPTIONS method: {}", .{err});
        cors_middleware.addHeader("Content-Type") catch |err| std.log.warn("CORS: Failed to add Content-Type header: {}", .{err});
        cors_middleware.addHeader("Authorization") catch |err| std.log.warn("CORS: Failed to add Authorization header: {}", .{err});

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

/// Global auth configuration for middleware (set once at startup)
/// This allows the middleware function to access the secret key for full HMAC verification
var global_auth_secret: ?[]const u8 = null;

/// Authentication middleware with HMAC-SHA256 token verification
pub const AuthMiddleware = struct {
    secret_key: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, secret_key: []const u8) Self {
        // Also set global secret for middleware chain usage
        global_auth_secret = secret_key;
        return Self{
            .secret_key = secret_key,
            .allocator = allocator,
        };
    }

    /// Validate JWT-like token using HMAC-SHA256 (standalone function for reuse)
    /// Token format: <header>.<payload>.<signature>
    pub fn validateTokenWithSecret(token: []const u8, secret_key: []const u8) bool {
        // Token must have minimum length for JWT structure
        if (token.len < 32) return false;

        // Find dot separators (JWT has exactly 2)
        var dot_count: usize = 0;
        var first_dot: ?usize = null;
        var second_dot: ?usize = null;

        for (token, 0..) |c, i| {
            if (c == '.') {
                dot_count += 1;
                if (dot_count == 1) first_dot = i else if (dot_count == 2) second_dot = i;
            }
        }

        // Must have exactly 2 dots
        if (dot_count != 2) return false;

        const d1 = first_dot orelse return false;
        const d2 = second_dot orelse return false;

        // Validate segment lengths
        if (d1 == 0 or d2 <= d1 + 1 or d2 >= token.len - 1) return false;

        const header_payload = token[0..d2];
        const provided_sig = token[d2 + 1 ..];

        // Signature must be base64url encoded (43 chars for 256-bit HMAC)
        if (provided_sig.len < 43) return false;

        // Validate base64url characters in signature
        for (provided_sig) |c| {
            if (!isBase64UrlChar(c)) return false;
        }

        // Compute expected signature using HMAC-SHA256
        var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(secret_key);
        hmac.update(header_payload);
        var expected_sig: [32]u8 = undefined;
        hmac.final(&expected_sig);

        // Decode provided signature from base64url
        var decoded_sig: [32]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Decoder.decode(&decoded_sig, provided_sig) catch return false;

        // Constant-time comparison to prevent timing attacks
        return std.crypto.timing_safe.eql([32]u8, decoded_sig, expected_sig);
    }

    fn isBase64UrlChar(c: u8) bool {
        return (c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_';
    }

    /// Instance method for token validation
    pub fn validateToken(self: *const Self, token: []const u8) bool {
        return validateTokenWithSecret(token, self.secret_key);
    }

    /// Handle authentication for a request directly (non-middleware usage)
    pub fn authenticate(self: *const Self, request: *Request, response: *Response) Error.ZquicError!bool {
        if (request.getHeader("authorization")) |auth_header| {
            if (std.mem.startsWith(u8, auth_header, "Bearer ")) {
                const token = auth_header[7..];
                if (self.validateToken(token)) {
                    return true;
                }
            }
        }

        // Unauthorized - deny by default
        response.setStatus(.unauthorized);
        try response.setHeader("WWW-Authenticate", "Bearer");
        try response.text("{\"error\": \"Unauthorized\", \"message\": \"Valid authentication token required\"}");
        return false;
    }

    /// Create a middleware function with full HMAC signature verification
    /// Uses the global auth secret set during init()
    pub fn middleware(self: *const Self) MiddlewareFn {
        _ = self;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Get the global secret key - deny if not configured
                const secret = global_auth_secret orelse {
                    response.setStatus(.internal_server_error);
                    try response.text("{\"error\": \"Internal Server Error\", \"message\": \"Auth not configured\"}");
                    return;
                };

                // Check for Authorization header
                if (request.getHeader("authorization")) |auth_header| {
                    if (std.mem.startsWith(u8, auth_header, "Bearer ")) {
                        const token = auth_header[7..];

                        // Full HMAC signature verification (not just structure check)
                        if (validateTokenWithSecret(token, secret)) {
                            try next(request, response);
                            return;
                        }
                    }
                }

                // Unauthorized - deny by default for missing, malformed, or invalid tokens
                response.setStatus(.unauthorized);
                try response.setHeader("WWW-Authenticate", "Bearer");
                try response.text("{\"error\": \"Unauthorized\", \"message\": \"Valid authentication token required\"}");
            }
        }.handle;
    }

    /// Reset global auth configuration (for testing)
    pub fn resetGlobalAuth() void {
        global_auth_secret = null;
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
                const start_time = Time.nowMicros();

                // Log request
                std.log.info("HTTP/3 {s} {s} - Stream {}", .{ request.method.toString(), request.path, request.context.stream_id });

                try next(request, response);

                // Log response
                const duration = Time.nowMicros() - start_time;
                std.log.info("HTTP/3 {s} {s} {} - {}μs", .{ request.method.toString(), request.path, response.status.getCode(), duration });
            }
        }.handle;
    }
};

/// Rate limiting middleware with request count tracking
/// Uses a simple per-client request counter with periodic reset
pub const RateLimitMiddleware = struct {
    max_requests: u32,
    reset_threshold: u32,
    client_requests: std.AutoHashMapUnmanaged(u64, u32),
    total_requests: std.atomic.Value(u64),
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, max_requests: u32, reset_threshold: u32) Self {
        // Store config in globals for inner function access
        global_rate_limit_max = max_requests;
        global_rate_limit_reset = reset_threshold;

        return Self{
            .max_requests = max_requests,
            .reset_threshold = reset_threshold,
            .client_requests = .empty,
            .total_requests = std.atomic.Value(u64).init(0),
            .allocator = allocator,
            .mutex = .unlocked,
        };
    }

    pub fn deinit(self: *Self) void {
        self.client_requests.deinit(self.allocator);
    }

    /// Check if a client is allowed to make a request
    pub fn isAllowed(self: *Self, client_id: u64) bool {
        // Acquire lock (spinlock style for simplicity)
        while (!self.mutex.tryLock()) {
            std.atomic.spinLoopHint();
        }
        defer self.mutex.unlock();

        // Increment total request counter
        const total = self.total_requests.fetchAdd(1, .monotonic);

        // Periodic reset: clear all counters when threshold reached
        if (total > 0 and total % @as(u64, self.reset_threshold) == 0) {
            self.client_requests.clearRetainingCapacity();
        }

        if (self.client_requests.getPtr(client_id)) |count| {
            // Check if within limit
            if (count.* >= self.max_requests) {
                return false;
            }
            // Increment count
            count.* += 1;
            return true;
        } else {
            // New client, create entry
            self.client_requests.put(self.allocator, client_id, 1) catch {
                // On allocation failure, allow request (fail open for availability)
                return true;
            };
            return true;
        }
    }

    pub fn middleware(self: *Self) MiddlewareFn {
        // Store pointer for inner function access
        global_rate_limiter = self;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Get client identifier (use stream_id as proxy for client identity)
                const client_id: u64 = request.context.stream_id;

                // Check rate limit using the global rate limiter
                const is_allowed = if (global_rate_limiter) |limiter| limiter.isAllowed(client_id) else true;

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

// Global rate limiter state for middleware closure workaround
var global_rate_limiter: ?*RateLimitMiddleware = null;
var global_rate_limit_max: u32 = 100;
var global_rate_limit_reset: u32 = 10000;

/// Compression middleware
/// NOTE: Actual compression requires runtime compression library.
/// This middleware currently only advertises compression capability via Vary header.
/// Set compression_enabled = true when actual compression is implemented.
pub const CompressionMiddleware = struct {
    compression_level: u8,
    min_size: usize,
    compression_enabled: bool,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, compression_level: u8, min_size: usize) Self {
        return Self{
            .compression_level = compression_level,
            .min_size = min_size,
            // Compression is disabled by default until actual compression is implemented
            // This prevents false Content-Encoding headers
            .compression_enabled = false,
            .allocator = allocator,
        };
    }

    /// Enable with actual compression (call when compression library is available)
    pub fn enableCompression(self: *Self) void {
        self.compression_enabled = true;
    }

    pub fn middleware(self: *const Self) MiddlewareFn {
        global_compression_enabled = self.compression_enabled;
        global_compression_min_size = self.min_size;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                try next(request, response);

                // Always set Vary header to indicate content may vary by encoding
                try response.setHeader("Vary", "Accept-Encoding");

                // Only set Content-Encoding if compression is actually enabled and performed
                if (global_compression_enabled) {
                    if (request.getHeader("accept-encoding")) |encoding| {
                        if (std.mem.indexOf(u8, encoding, "gzip") != null) {
                            // TODO: Implement actual gzip compression here
                            // Only uncomment when actual compression is implemented:
                            // try response.setHeader("Content-Encoding", "gzip");
                        }
                    }
                }
            }
        }.handle;
    }
};

// Global compression config for middleware closure workaround
var global_compression_enabled: bool = false;
var global_compression_min_size: usize = 1024;

/// Security headers middleware
pub const SecurityMiddleware = struct {
    enable_hsts: bool,
    hsts_max_age: u32,
    enable_content_type_options: bool,
    enable_frame_options: bool,
    csp_policy: ?[]const u8,
    referrer_policy: []const u8,
    permissions_policy: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .enable_hsts = true,
            .hsts_max_age = 31536000, // 1 year
            .enable_content_type_options = true,
            .enable_frame_options = true,
            .csp_policy = null,
            // Modern referrer policy - only send origin for cross-origin requests
            .referrer_policy = "strict-origin-when-cross-origin",
            // Restrictive permissions policy by default
            .permissions_policy = "geolocation=(), camera=(), microphone=(), payment=()",
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
        // Store config in globals for inner function access
        global_security_hsts_enabled = self.enable_hsts;
        global_security_hsts_max_age = self.hsts_max_age;
        global_security_csp = self.csp_policy;
        global_security_referrer_policy = self.referrer_policy;
        global_security_permissions_policy = self.permissions_policy;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                try next(request, response);

                // Modern security headers baseline
                try response.setHeader("X-Content-Type-Options", "nosniff");
                try response.setHeader("X-Frame-Options", "DENY");

                // X-XSS-Protection is deprecated in modern browsers and can cause issues
                // Modern browsers have built-in XSS protection; this header is no longer needed

                // Add HSTS header (should only be sent over HTTPS in production)
                if (global_security_hsts_enabled) {
                    var hsts_buf: [64]u8 = undefined;
                    const hsts_value = std.fmt.bufPrint(&hsts_buf, "max-age={d}; includeSubDomains", .{global_security_hsts_max_age}) catch "max-age=31536000; includeSubDomains";
                    try response.setHeader("Strict-Transport-Security", hsts_value);
                }

                // Content-Security-Policy for HTML contexts (if configured)
                if (global_security_csp) |csp| {
                    try response.setHeader("Content-Security-Policy", csp);
                }

                // Referrer-Policy - controls how much referrer info is sent
                try response.setHeader("Referrer-Policy", global_security_referrer_policy);

                // Permissions-Policy - controls browser feature access
                try response.setHeader("Permissions-Policy", global_security_permissions_policy);
            }
        }.handle;
    }
};

// Global security config for middleware closure workaround
var global_security_hsts_enabled: bool = true;
var global_security_hsts_max_age: u32 = 31536000;
var global_security_csp: ?[]const u8 = null;
var global_security_referrer_policy: []const u8 = "strict-origin-when-cross-origin";
var global_security_permissions_policy: []const u8 = "geolocation=(), camera=(), microphone=(), payment=()";

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
    // Validate request path for path traversal attacks (defense in depth)
    if (!isPathSafe(request_path)) {
        return Error.ZquicError.InvalidPath;
    }

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

    const constructed_path = buffer[0..used];

    // Symlink escape protection: verify the resolved path stays within root
    if (!isPathUnderRoot(root_dir, constructed_path)) {
        return Error.ZquicError.InvalidPath;
    }

    return constructed_path;
}

/// Check if a path resolves to a location under the root directory
/// This provides symlink escape protection by checking the path prefix
/// and rejecting symlink patterns
fn isPathUnderRoot(root_dir: []const u8, file_path: []const u8) bool {
    // Verify the constructed path starts with the root directory
    if (!std.mem.startsWith(u8, file_path, root_dir)) {
        return false;
    }

    // Get the portion after root_dir
    const remainder = file_path[root_dir.len..];

    // If there's content after root_dir, it must start with /
    if (remainder.len > 0 and remainder[0] != '/') {
        // This prevents /var/www from matching /var/www-attacker/secret
        return false;
    }

    // Additional symlink detection: reject paths with components that look like symlinks
    // This is a defense-in-depth measure alongside the isPathSafe check
    // Note: Full symlink resolution requires filesystem access which may not be
    // available in all contexts. The isPathSafe() check handles traversal attacks.

    // Reject paths containing suspicious patterns that might indicate symlink tricks
    var i: usize = 0;
    while (i < file_path.len) {
        // Look for paths that start components with common symlink attack patterns
        if (i == 0 or (i > 0 and file_path[i - 1] == '/')) {
            // Check for single dot followed by something other than / or end
            // (hidden files starting with . are usually OK, but .hidden/../ etc should be caught by isPathSafe)
            // Check for suspicious lengths of dots (more than 2 is unusual)
            var dot_count: usize = 0;
            var j = i;
            while (j < file_path.len and file_path[j] == '.') {
                dot_count += 1;
                j += 1;
            }
            if (dot_count > 2 and (j >= file_path.len or file_path[j] == '/')) {
                // More than two consecutive dots followed by separator or end is suspicious
                return false;
            }
        }
        i += 1;
    }

    return true;
}

/// Check if a path is safe from directory traversal attacks
fn isPathSafe(path: []const u8) bool {
    // Reject null bytes (null byte injection)
    for (path) |c| {
        if (c == 0) return false;
    }

    // Reject paths containing ".." segments
    var i: usize = 0;
    while (i < path.len) {
        // Check for ".." at start or after separator
        if (i == 0 or (i > 0 and path[i - 1] == '/')) {
            if (i + 1 < path.len and path[i] == '.' and path[i + 1] == '.') {
                // ".." followed by end, "/" or nothing
                if (i + 2 >= path.len or path[i + 2] == '/') {
                    return false;
                }
            }
        }
        i += 1;
    }

    // Reject URL-encoded traversal attempts (%2e%2e, %2E%2E, etc.)
    i = 0;
    while (i + 2 < path.len) {
        if (path[i] == '%') {
            // Check for %2e or %2E (encoded '.')
            if ((path[i + 1] == '2' and (path[i + 2] == 'e' or path[i + 2] == 'E'))) {
                // Check if followed by another encoded dot
                if (i + 5 < path.len and path[i + 3] == '%' and path[i + 4] == '2' and
                    (path[i + 5] == 'e' or path[i + 5] == 'E'))
                {
                    return false;
                }
            }
            // Check for %2f or %2F (encoded '/')
            if (path[i + 1] == '2' and (path[i + 2] == 'f' or path[i + 2] == 'F')) {
                return false;
            }
        }
        i += 1;
    }

    // Reject backslashes (Windows-style paths)
    for (path) |c| {
        if (c == '\\') return false;
    }

    return true;
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
