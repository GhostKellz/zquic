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
    segments: std.ArrayListUnmanaged(Segment),
    allocator: std.mem.Allocator,

    const Segment = struct {
        kind: enum { literal, parameter, wildcard },
        value: []const u8, // For literal segments, the literal value; for parameters, the parameter name
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pattern: []const u8) !Self {
        var route = Self{
            .pattern = try allocator.dupe(u8, pattern),
            .segments = .{},
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
        self.segments.deinit(self.allocator);
    }

    fn parsePattern(self: *Self) !void {
        var segments_iter = std.mem.splitScalar(u8, self.pattern, '/');

        while (segments_iter.next()) |segment| {
            if (segment.len == 0) continue; // Skip empty segments from leading/trailing slashes

            if (std.mem.startsWith(u8, segment, ":")) {
                // Parameter segment: :id, :name, etc.
                const param_name = segment[1..];
                try self.segments.append(self.allocator, Segment{
                    .kind = .parameter,
                    .value = try self.allocator.dupe(u8, param_name),
                });
            } else if (std.mem.eql(u8, segment, "*")) {
                // Wildcard segment
                try self.segments.append(self.allocator, Segment{
                    .kind = .wildcard,
                    .value = try self.allocator.dupe(u8, "*"),
                });
            } else {
                // Literal segment
                try self.segments.append(self.allocator, Segment{
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
    middleware: std.ArrayListUnmanaged(MiddlewareFn),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, method: Method, pattern: []const u8, handler: HandlerFn) !Self {
        return Self{
            .method = method,
            .pattern = try RoutePattern.init(allocator, pattern),
            .handler = handler,
            .middleware = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pattern.deinit();
        self.middleware.deinit(self.allocator);
    }

    pub fn addMiddleware(self: *Self, middleware: MiddlewareFn) !void {
        try self.middleware.append(self.allocator, middleware);
    }

    pub fn addMiddlewareSlice(self: *Self, middleware: []const MiddlewareFn) !void {
        for (middleware) |fn_ptr| {
            try self.middleware.append(self.allocator, fn_ptr);
        }
    }

    /// Check if this route matches the request
    pub fn matches(self: *const Self, method: Method, path: []const u8) bool {
        if (self.method != method) return false;

        var temp_params = RouteParams.init(self.allocator);
        defer temp_params.deinit();

        return self.pattern.match(path, &temp_params);
    }
};

/// Router for managing routes and handling requests
pub const Router = struct {
    routes: std.ArrayListUnmanaged(Route),
    global_middleware: std.ArrayListUnmanaged(MiddlewareFn),
    not_found_handler: ?HandlerFn,
    error_handler: ?*const fn (*Request, *Response, Error.ZquicError) Error.ZquicError!void,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .routes = .{},
            .global_middleware = .{},
            .not_found_handler = null,
            .error_handler = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.routes.items) |*route| {
            route.deinit();
        }
        self.routes.deinit(self.allocator);
        self.global_middleware.deinit(self.allocator);
    }

    /// Add a route
    pub fn addRoute(self: *Self, method: Method, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRouteWithMiddleware(method, pattern, handler, &.{});
    }

    pub fn addRouteWithMiddleware(self: *Self, method: Method, pattern: []const u8, handler: HandlerFn, middleware: []const MiddlewareFn) !void {
        var route = try Route.init(self.allocator, method, pattern, handler);
        errdefer route.deinit();
        try route.addMiddlewareSlice(middleware);
        try self.routes.append(self.allocator, route);
    }

    /// Convenience methods for common HTTP methods
    pub fn get(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.GET, pattern, handler);
    }

    pub fn getWithMiddleware(self: *Self, pattern: []const u8, handler: HandlerFn, middleware: []const MiddlewareFn) !void {
        try self.addRouteWithMiddleware(.GET, pattern, handler, middleware);
    }

    pub fn post(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.POST, pattern, handler);
    }

    pub fn postWithMiddleware(self: *Self, pattern: []const u8, handler: HandlerFn, middleware: []const MiddlewareFn) !void {
        try self.addRouteWithMiddleware(.POST, pattern, handler, middleware);
    }

    pub fn put(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.PUT, pattern, handler);
    }

    pub fn putWithMiddleware(self: *Self, pattern: []const u8, handler: HandlerFn, middleware: []const MiddlewareFn) !void {
        try self.addRouteWithMiddleware(.PUT, pattern, handler, middleware);
    }

    pub fn delete(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.DELETE, pattern, handler);
    }

    pub fn deleteWithMiddleware(self: *Self, pattern: []const u8, handler: HandlerFn, middleware: []const MiddlewareFn) !void {
        try self.addRouteWithMiddleware(.DELETE, pattern, handler, middleware);
    }

    pub fn patch(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.PATCH, pattern, handler);
    }

    pub fn patchWithMiddleware(self: *Self, pattern: []const u8, handler: HandlerFn, middleware: []const MiddlewareFn) !void {
        try self.addRouteWithMiddleware(.PATCH, pattern, handler, middleware);
    }

    pub fn options(self: *Self, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.OPTIONS, pattern, handler);
    }

    pub fn optionsWithMiddleware(self: *Self, pattern: []const u8, handler: HandlerFn, middleware: []const MiddlewareFn) !void {
        try self.addRouteWithMiddleware(.OPTIONS, pattern, handler, middleware);
    }

    /// Add global middleware (applies to all routes)
    pub fn use(self: *Self, middleware: MiddlewareFn) !void {
        try self.global_middleware.append(self.allocator, middleware);
    }

    /// Attach middleware to an existing route pattern/method pair
    pub fn addRouteMiddleware(self: *Self, method: Method, pattern: []const u8, middleware: MiddlewareFn) Error.ZquicError!void {
        const route = self.findRoute(method, pattern) orelse return Error.ZquicError.InvalidArgument;
        try route.addMiddleware(middleware);
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

        if (self.global_middleware.items.len > 0) {
            var fallback = try Route.init(self.allocator, request.method, request.path, notFoundThunk);
            defer fallback.deinit();
            try self.executeWithErrorHandling(request, response, &fallback);
            return;
        }

        try self.handleNotFound(request, response);
    }

    fn executeWithErrorHandling(self: *Self, request: *Request, response: *Response, route: *Route) Error.ZquicError!void {
        var exec_ctx = ExecutionContext.init(self, self.allocator, route, request, response, self.global_middleware.items);
        defer exec_ctx.deinit();

        const previous_state = request.context.router_state;
        request.context.router_state = exec_ctx.asOpaque();
        defer request.context.router_state = previous_state;

        exec_ctx.dispatch() catch |err| {
            if (self.error_handler) |handler| {
                try handler(request, response, err);
            } else {
                response.setStatus(.internal_server_error);
                try response.text("500 - Internal Server Error");
            }
        };
    }

    fn handleNotFound(self: *Self, request: *Request, response: *Response) Error.ZquicError!void {
        if (self.not_found_handler) |handler| {
            try handler(request, response);
        } else {
            response.setStatus(.not_found);
            try response.text("404 - Not Found");
        }
    }

    /// Get route parameter from request
    pub fn getParam(request: *const Request, name: []const u8) ?[]const u8 {
        if (ExecutionContext.fromRequest(request)) |ctx| {
            return ctx.params.get(name);
        }
        return null;
    }

    fn findRoute(self: *Self, method: Method, pattern: []const u8) ?*Route {
        for (self.routes.items) |*route| {
            if (route.method == method and std.mem.eql(u8, route.pattern.pattern, pattern)) {
                return route;
            }
        }
        return null;
    }
};

const ExecutionContext = struct {
    const magic_value: u64 = 0x5a5155435f4d5743; // "ZQUC_MWC"

    allocator: std.mem.Allocator,
    router: *Router,
    route: *const Route,
    request: *Request,
    response: *Response,
    global_middleware: []const MiddlewareFn,
    next_index: usize = 0,
    completed: bool = false,
    params: RouteParams,
    magic: u64 = magic_value,

    fn init(
        router: *Router,
        allocator: std.mem.Allocator,
        route: *const Route,
        request: *Request,
        response: *Response,
        global_middleware: []const MiddlewareFn,
    ) ExecutionContext {
        var ctx = ExecutionContext{
            .allocator = allocator,
            .router = router,
            .route = route,
            .request = request,
            .response = response,
            .global_middleware = global_middleware,
            .params = RouteParams.init(allocator),
        };
        _ = ctx.route.pattern.match(request.path, &ctx.params);
        return ctx;
    }

    fn deinit(self: *ExecutionContext) void {
        self.params.deinit();
        self.magic = 0;
    }

    fn dispatch(self: *ExecutionContext) Error.ZquicError!void {
        if (self.totalMiddleware() == 0) {
            self.completed = true;
            return self.route.handler(self.request, self.response);
        }
        return self.runNext();
    }

    fn runNext(self: *ExecutionContext) Error.ZquicError!void {
        if (self.completed) {
            return Error.ZquicError.Http3Error;
        }

        if (self.next_index < self.global_middleware.len) {
            const idx = self.next_index;
            self.next_index += 1;
            return self.global_middleware[idx](self.request, self.response, middlewareNext);
        }

        const local_index = self.next_index - self.global_middleware.len;
        if (local_index < self.route.middleware.items.len) {
            const idx = local_index;
            self.next_index += 1;
            return self.route.middleware.items[idx](self.request, self.response, middlewareNext);
        }

        self.completed = true;
        return self.route.handler(self.request, self.response);
    }

    fn totalMiddleware(self: *const ExecutionContext) usize {
        return self.global_middleware.len + self.route.middleware.items.len;
    }

    fn asOpaque(self: *ExecutionContext) *anyopaque {
        return @ptrCast(self);
    }

    fn fromRequest(request: *const Request) ?*const ExecutionContext {
        if (request.context.router_state) |state_ptr| {
            const ctx: *ExecutionContext = @ptrCast(@alignCast(state_ptr));
            if (ctx.magic == magic_value) return ctx;
        }
        return null;
    }

    fn fromMutableRequest(request: *Request) ?*ExecutionContext {
        if (request.context.router_state) |state_ptr| {
            const ctx: *ExecutionContext = @ptrCast(@alignCast(state_ptr));
            if (ctx.magic == magic_value) return ctx;
        }
        return null;
    }
};

fn middlewareNext(request: *Request, response: *Response) Error.ZquicError!void {
    const ctx = ExecutionContext.fromMutableRequest(request) orelse return Error.ZquicError.Http3Error;
    std.debug.assert(ctx.response == response);
    return ctx.runNext();
}

fn notFoundThunk(request: *Request, response: *Response) Error.ZquicError!void {
    const ctx = ExecutionContext.fromRequest(request) orelse return Error.ZquicError.Http3Error;
    return ctx.router.handleNotFound(request, response);
}

/// Test-only helper for configuring request paths without relying on private APIs.
fn setTestRequestPath(request: *Request, path: []const u8) !void {
    if (request.uri.len > 0) {
        request.allocator.free(request.uri);
    }
    if (request.path.len > 0) {
        request.allocator.free(request.path);
    }
    request.uri = try request.allocator.dupe(u8, path);
    request.path = try request.allocator.dupe(u8, path);

    if (request.query_string) |qs| {
        request.allocator.free(qs);
        request.query_string = null;
    }
}

const TestHelpers = struct {
    const MiddlewareState = struct {
        log: *std.ArrayList(u8),
    };

    fn stateFromRequest(request: *Request) *MiddlewareState {
        const state_ptr = request.context.user_data orelse unreachable;
        return @ptrCast(@alignCast(state_ptr));
    }

    fn appendLog(request: *Request, value: u8) Error.ZquicError!void {
        stateFromRequest(request).log.append(value) catch |err| {
            return Error.ErrorHandling.mapStdError(err);
        };
    }
};

test "route pattern matching" {
    var pattern = try RoutePattern.init(std.testing.allocator, "/users/:id/posts/:post_id");
    defer pattern.deinit();

    var params = std.StringHashMap([]const u8).init(std.testing.allocator);
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

test "router middleware executes global then route" {
    const allocator = std.testing.allocator;

    var router = Router.init(allocator);
    defer router.deinit();

    const middleware = struct {
        fn globalFirst(req: *Request, res: *Response, next: NextFn) Error.ZquicError!void {
            try TestHelpers.appendLog(req, 'A');
            try next(req, res);
        }

        fn globalSecond(req: *Request, res: *Response, next: NextFn) Error.ZquicError!void {
            try TestHelpers.appendLog(req, 'B');
            try next(req, res);
        }

        fn routeLogger(req: *Request, res: *Response, next: NextFn) Error.ZquicError!void {
            try TestHelpers.appendLog(req, 'R');
            try next(req, res);
        }

        fn handler(req: *Request, res: *Response) Error.ZquicError!void {
            try TestHelpers.appendLog(req, 'H');
            try res.text("ok");
        }
    };

    try router.use(middleware.globalFirst);
    try router.use(middleware.globalSecond);
    try router.getWithMiddleware("/test", middleware.handler, &.{middleware.routeLogger});

    var request = Request.init(allocator, 1, "conn");
    defer request.deinit();
    try setTestRequestPath(&request, "/test");

    var response = Response.init(allocator, 1);
    defer response.deinit();

    var call_order = std.ArrayList(u8).init(allocator);
    defer call_order.deinit();

    var state = TestHelpers.MiddlewareState{ .log = &call_order };
    request.context.user_data = &state;

    try router.handleRequest(&request, &response);
    try std.testing.expectEqualStrings("ABRH", call_order.items);
}

test "router middleware can short circuit handler" {
    const allocator = std.testing.allocator;

    var router = Router.init(allocator);
    defer router.deinit();

    const middleware = struct {
        fn globalLogger(req: *Request, res: *Response, next: NextFn) Error.ZquicError!void {
            try TestHelpers.appendLog(req, 'G');
            try next(req, res);
        }

        fn terminatingRoute(req: *Request, res: *Response, next: NextFn) Error.ZquicError!void {
            _ = next;
            try TestHelpers.appendLog(req, 'R');
            res.setStatus(.forbidden);
            try res.text("blocked");
        }

        fn handler(req: *Request, res: *Response) Error.ZquicError!void {
            try TestHelpers.appendLog(req, 'H');
            try res.text("ok");
        }
    };

    try router.use(middleware.globalLogger);
    try router.get("/test", middleware.handler);
    try router.addRouteMiddleware(.GET, "/test", middleware.terminatingRoute);

    var request = Request.init(allocator, 2, "conn");
    defer request.deinit();
    try setTestRequestPath(&request, "/test");

    var response = Response.init(allocator, 2);
    defer response.deinit();

    var call_order = std.ArrayList(u8).init(allocator);
    defer call_order.deinit();

    var state = TestHelpers.MiddlewareState{ .log = &call_order };
    request.context.user_data = &state;

    try router.handleRequest(&request, &response);
    try std.testing.expectEqualStrings("GR", call_order.items);
    try std.testing.expect(response.status == .forbidden);
}
