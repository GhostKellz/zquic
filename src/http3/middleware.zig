//! HTTP/3 middleware system
//!
//! Common middleware implementations for HTTP/3 server
//!
//! Middleware configuration is passed through the Request object to avoid
//! process-global state and enable multiple server instances with different
//! configurations to run concurrently.

const std = @import("std");
const Error = @import("../utils/error.zig");
const Time = @import("../utils/time.zig");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const StatusCode = @import("response.zig").StatusCode;
const Router = @import("router.zig");
const NextFn = Router.NextFn;
pub const MiddlewareFn = Router.MiddlewareFn;

/// Centralized middleware configuration passed through Request context.
/// This replaces process-global variables to support multiple server instances.
pub const MiddlewareConfig = struct {
    // Auth configuration
    auth_secret: ?[]const u8 = null,

    // Rate limiting - pointer to server-owned instance
    rate_limiter: ?*RateLimitMiddleware = null,

    // Compression
    compression_enabled: bool = false,
    compression_min_size: usize = 1024,

    // Security headers
    security_hsts_enabled: bool = true,
    security_hsts_max_age: u32 = 31536000,
    security_csp: ?[]const u8 = null,
    security_referrer_policy: []const u8 = "strict-origin-when-cross-origin",
    security_permissions_policy: []const u8 = "geolocation=(), camera=(), microphone=(), payment=()",

    // Static files
    static_root_dir: []const u8 = "./public",
    static_cache_control: []const u8 = "public, max-age=3600",
};

/// Get middleware config from request, casting from anyopaque.
/// Returns default config if not set.
fn getConfig(request: *const Request) MiddlewareConfig {
    if (request.middleware_config) |config_ptr| {
        const config: *const MiddlewareConfig = @ptrCast(@alignCast(config_ptr));
        return config.*;
    }
    return MiddlewareConfig{}; // Return defaults if not configured
}

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

/// Authentication middleware with HMAC-SHA256 token verification
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
    /// Uses auth_secret from request.middleware_config
    pub fn middleware(self: *const Self) MiddlewareFn {
        _ = self;

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Get config from request context
                const config = getConfig(request);

                // Get the secret key - deny if not configured
                const secret = config.auth_secret orelse {
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
        _ = self; // Config is passed via request.middleware_config

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Get config from request context
                const config = getConfig(request);

                // Get client identifier from connection ID, not stream ID.
                // Using stream_id would allow bypass by opening new streams.
                // Connection ID is per-client and persists across streams.
                const client_id: u64 = hashConnectionId(request.context.connection_id);

                // Check rate limit using the configured rate limiter
                const is_allowed = if (config.rate_limiter) |limiter| limiter.isAllowed(client_id) else true;

                if (!is_allowed) {
                    response.setStatus(.too_many_requests);
                    try response.setHeader("Retry-After", "60");
                    try response.text("{\"error\": \"Rate limit exceeded\", \"message\": \"Too many requests\"}");
                    return;
                }

                try next(request, response);
            }

            /// Hash connection ID bytes to u64 for rate limit key
            fn hashConnectionId(conn_id: []const u8) u64 {
                if (conn_id.len == 0) return 0;
                // Simple FNV-1a hash for connection ID
                var hash: u64 = 0xcbf29ce484222325; // FNV offset basis
                for (conn_id) |byte| {
                    hash ^= byte;
                    hash *%= 0x100000001b3; // FNV prime
                }
                return hash;
            }
        }.handle;
    }
};

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
        _ = self; // Config is passed via request.middleware_config

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Get config from request context
                const config = getConfig(request);

                try next(request, response);

                // Always set Vary header to indicate content may vary by encoding
                try response.setHeader("Vary", "Accept-Encoding");

                // Only set Content-Encoding if compression is actually enabled and performed
                if (config.compression_enabled) {
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
        _ = self; // Config is passed via request.middleware_config

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Get config from request context
                const config = getConfig(request);

                try next(request, response);

                // Modern security headers baseline
                try response.setHeader("X-Content-Type-Options", "nosniff");
                try response.setHeader("X-Frame-Options", "DENY");

                // X-XSS-Protection is deprecated in modern browsers and can cause issues
                // Modern browsers have built-in XSS protection; this header is no longer needed

                // Add HSTS header (should only be sent over HTTPS in production)
                if (config.security_hsts_enabled) {
                    var hsts_buf: [64]u8 = undefined;
                    const hsts_value = std.fmt.bufPrint(&hsts_buf, "max-age={d}; includeSubDomains", .{config.security_hsts_max_age}) catch "max-age=31536000; includeSubDomains";
                    try response.setHeader("Strict-Transport-Security", hsts_value);
                }

                // Content-Security-Policy for HTML contexts (if configured)
                if (config.security_csp) |csp| {
                    try response.setHeader("Content-Security-Policy", csp);
                }

                // Referrer-Policy - controls how much referrer info is sent
                try response.setHeader("Referrer-Policy", config.security_referrer_policy);

                // Permissions-Policy - controls browser feature access
                try response.setHeader("Permissions-Policy", config.security_permissions_policy);
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
        _ = self; // Config is passed via request.middleware_config

        return struct {
            fn handle(request: *Request, response: *Response, next: NextFn) Error.ZquicError!void {
                // Get config from request context
                const config = getConfig(request);

                // Only handle GET requests for files
                if (request.method != .GET) {
                    try next(request, response);
                    return;
                }

                var path_buffer: [512]u8 = undefined;
                const file_path = buildStaticFilePath(&path_buffer, config.static_root_dir, request.path) catch {
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
                try response.setHeader("Cache-Control", config.static_cache_control);
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

/// Check if a path resolves to a location under the root directory.
/// Uses filesystem checks to detect symlinks that could escape the root.
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

    // Check each path component for symlinks that could escape root
    // Build path incrementally and check each component
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var current_len: usize = 0;

    // Start with root_dir
    if (root_dir.len > path_buf.len) return false;
    @memcpy(path_buf[0..root_dir.len], root_dir);
    current_len = root_dir.len;

    // Process each component of remainder
    var iter = std.mem.splitScalar(u8, remainder, '/');
    while (iter.next()) |component| {
        if (component.len == 0) continue;

        // Skip . components
        if (std.mem.eql(u8, component, ".")) continue;

        // Reject .. components (should be caught by isPathSafe, but double-check)
        if (std.mem.eql(u8, component, "..")) return false;

        // Add separator if needed
        if (current_len > 0 and path_buf[current_len - 1] != '/') {
            if (current_len >= path_buf.len) return false;
            path_buf[current_len] = '/';
            current_len += 1;
        }

        // Add component
        if (current_len + component.len > path_buf.len) return false;
        @memcpy(path_buf[current_len..][0..component.len], component);
        current_len += component.len;

        // Check if this path component is a symlink using statx syscall
        // We need a null-terminated path for the syscall
        if (current_len >= path_buf.len) return false;
        path_buf[current_len] = 0;
        const path_z: [*:0]const u8 = @ptrCast(path_buf[0..current_len :0].ptr);

        var statx_buf: std.os.linux.Statx = undefined;
        const rc = std.os.linux.statx(
            std.os.linux.AT.FDCWD,
            path_z,
            std.os.linux.AT.SYMLINK_NOFOLLOW, // Don't follow symlinks
            .{ .TYPE = true }, // We only need the type/mode
            &statx_buf,
        );

        const err = std.os.linux.errno(rc);
        if (err != .SUCCESS) {
            // Path doesn't exist or can't be accessed - allow, will fail later
            continue;
        }

        // Check if this is a symlink: (mode & S.IFMT) == S.IFLNK
        if ((statx_buf.mode & std.os.linux.S.IFMT) == std.os.linux.S.IFLNK) {
            // Path contains a symlink - reject for safety
            // A symlink could point outside the root directory
            std.log.warn("Rejected path containing symlink: {s}", .{path_buf[0..current_len]});
            return false;
        }
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

fn testNextMarksCreated(_: *Request, response: *Response) Error.ZquicError!void {
    response.setStatus(.created);
}

fn writeTestJwt(buffer: []u8, secret: []const u8, header_payload: []const u8) ![]const u8 {
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(secret);
    hmac.update(header_payload);
    var sig: [32]u8 = undefined;
    hmac.final(&sig);

    var sig_buf: [std.base64.url_safe_no_pad.Encoder.calcSize(32)]u8 = undefined;
    const encoded_sig = std.base64.url_safe_no_pad.Encoder.encode(&sig_buf, &sig);
    return try std.fmt.bufPrint(buffer, "{s}.{s}", .{ header_payload, encoded_sig });
}

test "auth middleware rejects structure-valid token with bad signature" {
    const secret = "test-secret";
    const auth = AuthMiddleware.init(std.testing.allocator, secret);
    const middleware = auth.middleware();

    var request = Request.init(std.testing.allocator, 1, "client-a");
    defer request.deinit();
    var response = Response.init(std.testing.allocator, 1);
    defer response.deinit();

    const config = MiddlewareConfig{ .auth_secret = secret };
    request.middleware_config = &config;

    var token_buf: [256]u8 = undefined;
    const token = try writeTestJwt(&token_buf, "wrong-secret", "aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb");
    var auth_header_buf: [300]u8 = undefined;
    const auth_header = try std.fmt.bufPrint(&auth_header_buf, "Bearer {s}", .{token});
    try request.headers.add("authorization", auth_header);

    try middleware(&request, &response, testNextMarksCreated);
    try std.testing.expectEqual(StatusCode.unauthorized, response.status);
    try std.testing.expect(response.headers.get("WWW-Authenticate") != null);
}

test "auth middleware accepts correctly signed token" {
    const secret = "test-secret";
    const auth = AuthMiddleware.init(std.testing.allocator, secret);
    const middleware = auth.middleware();

    var request = Request.init(std.testing.allocator, 1, "client-a");
    defer request.deinit();
    var response = Response.init(std.testing.allocator, 1);
    defer response.deinit();

    const config = MiddlewareConfig{ .auth_secret = secret };
    request.middleware_config = &config;

    var token_buf: [256]u8 = undefined;
    const token = try writeTestJwt(&token_buf, secret, "aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb");
    var auth_header_buf: [300]u8 = undefined;
    const auth_header = try std.fmt.bufPrint(&auth_header_buf, "Bearer {s}", .{token});
    try request.headers.add("authorization", auth_header);

    try middleware(&request, &response, testNextMarksCreated);
    try std.testing.expectEqual(StatusCode.created, response.status);
}

test "logging middleware creation" {
    const logging = LoggingMiddleware.init(std.testing.allocator, .info);

    try std.testing.expect(logging.log_level == .info);
}

test "static path rejects traversal and encoded separator payloads" {
    var path_buffer: [512]u8 = undefined;

    try std.testing.expectError(Error.ZquicError.InvalidPath, buildStaticFilePath(&path_buffer, "/srv/www", "/../secret"));
    try std.testing.expectError(Error.ZquicError.InvalidPath, buildStaticFilePath(&path_buffer, "/srv/www", "/%2e%2e/secret"));
    try std.testing.expectError(Error.ZquicError.InvalidPath, buildStaticFilePath(&path_buffer, "/srv/www", "/safe%2f..%2fsecret"));
    try std.testing.expectError(Error.ZquicError.InvalidPath, buildStaticFilePath(&path_buffer, "/srv/www", "/safe\\secret"));

    const safe_path = try buildStaticFilePath(&path_buffer, "/srv/www", "/assets/app.css");
    try std.testing.expectEqualStrings("/srv/www/assets/app.css", safe_path);
}

test "static path rejects symlink components under root" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var root_buf: [128]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/static-root-{d}", .{std.crypto.random.int(u64)});
    try std.fs.cwd().makePath(root);
    defer std.fs.cwd().deleteTree(root) catch {};

    var link_buf: [160]u8 = undefined;
    const link_path = try std.fmt.bufPrint(&link_buf, "{s}/escape", .{root});
    var link_z_buf: [161]u8 = undefined;
    const link_z = try std.fmt.bufPrintZ(&link_z_buf, "{s}", .{link_path});
    const target_z: [:0]const u8 = "/etc/passwd";
    const rc = std.os.linux.symlink(target_z.ptr, link_z.ptr);
    if (std.os.linux.errno(rc) != .SUCCESS) return error.SkipZigTest;

    var path_buffer: [512]u8 = undefined;
    try std.testing.expectError(Error.ZquicError.InvalidPath, buildStaticFilePath(&path_buffer, root, "/escape"));
}
