//! HTTP/3 routing system
//!
//! Path-based routing with pattern matching and parameter extraction

const std = @import("std");
const Error = @import("../utils/error.zig");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Method = @import("request.zig").Method;

/// Route handler function type
pub const HandlerFn = *const fn (*Request, *Response) Error.ZquicError!void;

/// Middleware function type
pub const MiddlewareFn = *const fn (*Request, *Response, NextFn) Error.ZquicError!void;
pub const NextFn = *const fn (*Request, *Response) Error.ZquicError!void;

/// Route parameters extracted from path
pub const RouteParams = struct {
    params: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .params = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iterator = self.params.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.params.deinit();
    }

    pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
        return self.params.get(key);
    }

    pub fn put(self: *Self, key: []const u8, value: []const u8) !void {
        const owned_key = try self.allocator.dupe(u8, key);
        const owned_value = try self.allocator.dupe(u8, value);
        try self.params.put(owned_key, owned_value);
    }
};

/// Route pattern matching and parameter extraction
pub const RoutePattern = struct {
    pattern: []const u8,
    segments: std.ArrayList(Segment),
    allocator: std.mem.Allocator,

    const Segment = struct {
        kind: enum { literal, parameter, wildcard },
        value: []const u8, // For literal segments, the literal value; for parameters, the parameter name
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pattern: []const u8) !Self {
        var route = Self{
            .pattern = try allocator.dupe(u8, pattern),
            .segments = std.ArrayList(Segment).init(allocator),
            .allocator = allocator,
        };

        try route.parsePattern();
        return route;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.pattern);
        for (self.segments.items) |segment| {
            self.allocator.free(segment.value);
        }
        self.segments.deinit();
    }

    fn parsePattern(self: *Self) !void {
        var segments_iter = std.mem.splitScalar(u8, self.pattern, '/');

        while (segments_iter.next()) |segment| {
            if (segment.len == 0) continue; // Skip empty segments from leading/trailing slashes

            if (std.mem.startsWith(u8, segment, ":")) {
                // Parameter segment: :id, :name, etc.
                const param_name = segment[1..];
                try self.segments.append(Segment{
                    .kind = .parameter,
                    .value = try self.allocator.dupe(u8, param_name),
                });
            } else if (std.mem.eql(u8, segment, "*")) {
                // Wildcard segment
                try self.segments.append(Segment{
                    .kind = .wildcard,
                    .value = try self.allocator.dupe(u8, "*"),
                });
            } else {
                // Literal segment
                try self.segments.append(Segment{
                    .kind = .literal,
                    .value = try self.allocator.dupe(u8, segment),
                });
            }
        }
    }

    /// Match a path against this pattern and extract parameters
    pub fn match(self: *const Self, path: []const u8, params: *RouteParams) bool {
        var path_segments = std.mem.splitScalar(u8, path, '/');
        var pattern_index: usize = 0;

        while (path_segments.next()) |path_segment| {
            if (path_segment.len == 0) continue; // Skip empty segments

            if (pattern_index >= self.segments.items.len) {
                return false; // More path segments than pattern segments
            }

            const pattern_segment = self.segments.items[pattern_index];

            switch (pattern_segment.kind) {
                .literal => {
                    if (!std.mem.eql(u8, path_segment, pattern_segment.value)) {
                        return false; // Literal doesn't match
                    }
                },
                .parameter => {
                    // Extract parameter value
                    params.put(pattern_segment.value, path_segment) catch return false;
                },
                .wildcard => {
                    // Wildcard matches everything remaining
                    return true;
                },
            }

            pattern_index += 1;
        }

        // Check if we matched all pattern segments (unless last was wildcard)
        return pattern_index == self.segments.items.len or
            (pattern_index == self.segments.items.len - 1 and
                self.segments.items[pattern_index].kind == .wildcard);
    }
};

/// Individual route definition
pub const Route = struct {
    method: Method,
    pattern: RoutePattern,
    handler: HandlerFn,
    middleware: std.ArrayList(MiddlewareFn),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, method: Method, pattern: []const u8, handler: HandlerFn) !Self {
        return Self{
            .method = method,
            .pattern = try RoutePattern.init(allocator, pattern),
            .handler = handler,
            .middleware = std.ArrayList(MiddlewareFn).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pattern.deinit();
        self.middleware.deinit();
    }

    pub fn addMiddleware(self: *Self, middleware: MiddlewareFn) !void {
        try self.middleware.append(middleware);
    }

    /// Check if this route matches the request
    pub fn matches(self: *const Self, method: Method, path: []const u8) bool {
        if (self.method != method) return false;

        var temp_params = RouteParams.init(self.allocator);
        defer temp_params.deinit();

        return self.pattern.match(path, &temp_params);
    }

    /// Execute route with middleware chain
    pub fn execute(self: *const Self, request: *Request, response: *Response) Error.ZquicError!void {
        // Extract route parameters
        var params = RouteParams.init(self.allocator);
        defer params.deinit();

        _ = self.pattern.match(request.path, &params);

        // Add parameters to request context
        request.context.user_data = &params;

        // Execute middleware chain
        if (self.middleware.items.len > 0) {
            try self.executeMiddleware(0, request, response);
        } else {
            try self.handler(request, response);
        }
    }

    fn executeMiddleware(self: *const Self, index: usize, request: *Request, response: *Response) Error.ZquicError!void {
        if (index >= self.middleware.items.len) {
            return self.handler(request, response);
        }

        const next_fn: NextFn = struct {
            fn next(req: *Request, res: *Response) Error.ZquicError!void {
                // This is a simplified next function - in a real implementation,
                // we'd need to capture the route and index in a closure
                _ = req;
                _ = res;
                return Error.ZquicError.Http3Error; // Placeholder
            }
        }.next;

        try self.middleware.items[index](request, response, next_fn);
    }
};

/// Router for managing routes and handling requests
pub const Router = struct {
    routes: std.ArrayList(Route),
    global_middleware: std.ArrayList(MiddlewareFn),
    not_found_handler: ?HandlerFn,
    error_handler: ?*const fn (*Request, *Response, Error.ZquicError) Error.ZquicError!void,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .routes = std.ArrayList(Route).init(allocator),
            .global_middleware = std.ArrayList(MiddlewareFn).init(allocator),
            .not_found_handler = null,
            .error_handler = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.routes.items) |*route| {
            route.deinit();
        }
        self.routes.deinit();
        self.global_middleware.deinit();
    }

    /// Add a route
    pub fn addRoute(self: *Self, method: Method, pattern: []const u8, handler: HandlerFn) !void {
        const route = try Route.init(self.allocator, method, pattern, handler);
        try self.routes.append(route);
    }

    /// Convenience methods for common HTTP methods
    pub fn get(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.GET, pattern, handler);
    }

    pub fn post(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.POST, pattern, handler);
    }

    pub fn put(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.PUT, pattern, handler);
    }

    pub fn delete(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.DELETE, pattern, handler);
    }

    pub fn patch(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.PATCH, pattern, handler);
    }

    pub fn options(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.OPTIONS, pattern, handler);
    }

    /// Add global middleware (applies to all routes)
    pub fn use(self: *Self, middleware: MiddlewareFn) !void {
        try self.global_middleware.append(middleware);
    }

    /// Set custom 404 handler
    pub fn setNotFoundHandler(self: *Self, handler: HandlerFn) void {
        self.not_found_handler = handler;
    }

    /// Set custom error handler
    pub fn setErrorHandler(self: *Self, handler: *const fn (*Request, *Response, Error.ZquicError) Error.ZquicError!void) void {
        self.error_handler = handler;
    }

    /// Handle an incoming request
    pub fn handleRequest(self: *Self, request: *Request, response: *Response) Error.ZquicError!void {
        // Find matching route
        for (self.routes.items) |*route| {
            if (route.matches(request.method, request.path)) {
                // Execute global middleware first, then route
                return self.executeWithErrorHandling(request, response, route);
            }
        }

        // No route found - handle 404
        if (self.not_found_handler) |handler| {
            try handler(request, response);
        } else {
            response.setStatus(.not_found);
            try response.text("404 - Not Found");
        }
    }

    fn executeWithErrorHandling(self: *Self, request: *Request, response: *Response, route: *Route) Error.ZquicError!void {
        route.execute(request, response) catch |err| {
            if (self.error_handler) |handler| {
                try handler(request, response, err);
            } else {
                // Default error handling
                response.setStatus(.internal_server_error);
                try response.text("500 - Internal Server Error");
            }
        };
    }

    /// Get route parameter from request
    pub fn getParam(request: *const Request, name: []const u8) ?[]const u8 {
        if (request.context.user_data) |data| {
            const params: *RouteParams = @ptrCast(@alignCast(data));
            return params.get(name);
        }
        return null;
    }
};

test "route pattern matching" {
    var pattern = try RoutePattern.init(std.testing.allocator, "/users/:id/posts/:post_id");
    defer pattern.deinit();

    var params = RouteParams.init(std.testing.allocator);
    defer params.deinit();

    try std.testing.expect(pattern.match("/users/123/posts/456", &params));
    try std.testing.expect(std.mem.eql(u8, params.get("id").?, "123"));
    try std.testing.expect(std.mem.eql(u8, params.get("post_id").?, "456"));

    try std.testing.expect(!pattern.match("/users/123", &params));
    try std.testing.expect(!pattern.match("/invalid/path", &params));
}

test "route creation and matching" {
    const allocator = std.testing.allocator;

    const testHandler = struct {
        fn handler(req: *Request, res: *Response) Error.ZquicError!void {
            _ = req;
            try res.text("Hello World");
        }
    }.handler;

    var route = try Route.init(allocator, .GET, "/test", testHandler);
    defer route.deinit();

    try std.testing.expect(route.matches(.GET, "/test"));
    try std.testing.expect(!route.matches(.POST, "/test"));
    try std.testing.expect(!route.matches(.GET, "/other"));
}

test "router functionality" {
    const allocator = std.testing.allocator;

    var router = Router.init(allocator);
    defer router.deinit();

    const testHandler = struct {
        fn handler(req: *Request, res: *Response) Error.ZquicError!void {
            _ = req;
            try res.text("Test Response");
        }
    }.handler;

    try router.get("/test", testHandler);
    try router.post("/api/users", testHandler);

    // Test route count
    try std.testing.expect(router.routes.items.len == 2);
}
