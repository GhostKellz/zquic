//! HTTP/3 integration tests exercising router and frame generation

const std = @import("std");
const zquic = @import("zquic");

const Http3 = zquic.Http3;
const Error = zquic.Error;
const NextFn = *const fn (*Http3.Request, *Http3.Response) Error.ZquicError!void;
const MiddlewareLog = std.ArrayListUnmanaged(u8);

const MiddlewareTest = struct {
    fn attachLog(request: *Http3.Request, log: *MiddlewareLog) void {
        request.context.user_data = log;
    }

    fn append(request: *Http3.Request, value: u8) Error.ZquicError!void {
        const state_ptr = request.context.user_data orelse return Error.ZquicError.InternalError;
        const log: *MiddlewareLog = @ptrCast(@alignCast(state_ptr));
        log.append(request.allocator, value) catch |err| {
            return Error.ErrorHandling.mapStdError(err);
        };
    }
};

fn buildHeaderFields(allocator: std.mem.Allocator, headers: []const struct { name: []const u8, value: []const u8 }) ![]Http3.HeaderField {
    var list = try allocator.alloc(Http3.HeaderField, headers.len);
    errdefer allocator.free(list);

    var i: usize = 0;
    while (i < headers.len) : (i += 1) {
        list[i] = try Http3.HeaderField.init(allocator, headers[i].name, headers[i].value);
    }
    return list;
}

test "integration: http3 server routes request to handler" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try Http3.Http3Server.init(allocator, .{});
    defer server.deinit();

    const handler = struct {
        fn handle(req: *Http3.Request, res: *Http3.Response) Error.ZquicError!void {
            if (!std.mem.eql(u8, req.path, "/status")) {
                return Error.ZquicError.Http3Error;
            }
            try res.text("ok");
        }
    }.handle;

    try server.get("/status", handler);

    var request = Http3.Request.init(allocator, 1, "conn-1");
    defer request.deinit();

    const header_fields = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/status" },
        .{ .name = ":authority", .value = "localhost" },
    });
    defer {
        for (header_fields) |*field| {
            field.deinit();
        }
        allocator.free(header_fields);
    }

    try request.parseFromHeaders(header_fields);

    var response = Http3.Response.init(allocator, request.context.stream_id);
    defer response.deinit();

    try server.router.handleRequest(&request, &response);

    try std.testing.expect(std.mem.eql(u8, response.getBody(), "ok"));
    try std.testing.expect(!response.isSent());

    const frames = try response.generateFrames(allocator);
    defer {
        for (frames) |frame| {
            allocator.free(frame.payload);
        }
        allocator.free(frames);
    }

    try std.testing.expect(frames.len == 2);
    try std.testing.expect(frames[0].frame_type == Http3.FrameType.headers);
    try std.testing.expect(frames[1].frame_type == Http3.FrameType.data);
    try std.testing.expect(std.mem.eql(u8, frames[1].payload, "ok"));
}

test "integration: middleware executes in order" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try Http3.Http3Server.init(allocator, .{});
    defer server.deinit();

    const middleware = struct {
        fn globalA(req: *Http3.Request, res: *Http3.Response, next: NextFn) Error.ZquicError!void {
            try MiddlewareTest.append(req, 'A');
            try next(req, res);
        }

        fn globalB(req: *Http3.Request, res: *Http3.Response, next: NextFn) Error.ZquicError!void {
            try MiddlewareTest.append(req, 'B');
            try next(req, res);
        }

        fn routeLogger(req: *Http3.Request, res: *Http3.Response, next: NextFn) Error.ZquicError!void {
            try MiddlewareTest.append(req, 'R');
            try next(req, res);
        }

        fn handler(req: *Http3.Request, res: *Http3.Response) Error.ZquicError!void {
            try MiddlewareTest.append(req, 'H');
            try res.text("ok");
        }
    };

    try server.use(middleware.globalA);
    try server.use(middleware.globalB);
    try server.router.getWithMiddleware("/test", middleware.handler, &.{middleware.routeLogger});

    var request = Http3.Request.init(allocator, 10, "conn-mid");
    defer request.deinit();

    const header_fields = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/test" },
        .{ .name = ":authority", .value = "localhost" },
    });
    defer {
        for (header_fields) |*field| {
            field.deinit();
        }
        allocator.free(header_fields);
    }

    try request.parseFromHeaders(header_fields);

    var response = Http3.Response.init(allocator, request.context.stream_id);
    defer response.deinit();

    var call_log = MiddlewareLog{};
    defer call_log.deinit(allocator);
    MiddlewareTest.attachLog(&request, &call_log);

    try server.router.handleRequest(&request, &response);

    try std.testing.expectEqualStrings("ABRH", call_log.items);
    try std.testing.expect(std.mem.eql(u8, response.getBody(), "ok"));
}

test "integration: middleware short circuits handler" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try Http3.Http3Server.init(allocator, .{});
    defer server.deinit();

    const middleware = struct {
        fn global(req: *Http3.Request, res: *Http3.Response, next: NextFn) Error.ZquicError!void {
            try MiddlewareTest.append(req, 'G');
            try next(req, res);
        }

        fn blocker(req: *Http3.Request, res: *Http3.Response, next: NextFn) Error.ZquicError!void {
            _ = next;
            try MiddlewareTest.append(req, 'R');
            res.setStatus(.forbidden);
            try res.text("blocked");
        }

        fn handler(req: *Http3.Request, res: *Http3.Response) Error.ZquicError!void {
            try MiddlewareTest.append(req, 'H');
            try res.text("ok");
        }
    };

    try server.use(middleware.global);
    try server.get("/test", middleware.handler);
    try server.router.addRouteMiddleware(.GET, "/test", middleware.blocker);

    var request = Http3.Request.init(allocator, 11, "conn-short");
    defer request.deinit();

    const header_fields = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/test" },
        .{ .name = ":authority", .value = "localhost" },
    });
    defer {
        for (header_fields) |*field| {
            field.deinit();
        }
        allocator.free(header_fields);
    }

    try request.parseFromHeaders(header_fields);

    var response = Http3.Response.init(allocator, request.context.stream_id);
    defer response.deinit();

    var call_log = MiddlewareLog{};
    defer call_log.deinit(allocator);
    MiddlewareTest.attachLog(&request, &call_log);

    try server.router.handleRequest(&request, &response);

    try std.testing.expectEqualStrings("GR", call_log.items);
    try std.testing.expect(response.status == .forbidden);
    try std.testing.expect(std.mem.eql(u8, response.getBody(), "blocked"));
}

test "integration: route middleware isolation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try Http3.Http3Server.init(allocator, .{});
    defer server.deinit();

    const middleware = struct {
        fn global(req: *Http3.Request, res: *Http3.Response, next: NextFn) Error.ZquicError!void {
            try MiddlewareTest.append(req, 'G');
            try next(req, res);
        }

        fn alpha(req: *Http3.Request, res: *Http3.Response, next: NextFn) Error.ZquicError!void {
            try MiddlewareTest.append(req, 'A');
            try next(req, res);
        }

        fn beta(req: *Http3.Request, res: *Http3.Response, next: NextFn) Error.ZquicError!void {
            try MiddlewareTest.append(req, 'B');
            try next(req, res);
        }

        fn alphaHandler(req: *Http3.Request, res: *Http3.Response) Error.ZquicError!void {
            try MiddlewareTest.append(req, 'H');
            try res.text("alpha");
        }

        fn betaHandler(req: *Http3.Request, res: *Http3.Response) Error.ZquicError!void {
            try MiddlewareTest.append(req, 'H');
            try res.text("beta");
        }
    };

    try server.use(middleware.global);
    try server.router.getWithMiddleware("/alpha", middleware.alphaHandler, &.{middleware.alpha});
    try server.router.getWithMiddleware("/beta", middleware.betaHandler, &.{middleware.beta});

    var alpha_request = Http3.Request.init(allocator, 12, "conn-alpha");
    defer alpha_request.deinit();
    const alpha_headers = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/alpha" },
        .{ .name = ":authority", .value = "localhost" },
    });
    defer {
        for (alpha_headers) |*field| field.deinit();
        allocator.free(alpha_headers);
    }
    try alpha_request.parseFromHeaders(alpha_headers);

    var alpha_response = Http3.Response.init(allocator, alpha_request.context.stream_id);
    defer alpha_response.deinit();

    var alpha_log = MiddlewareLog{};
    defer alpha_log.deinit(allocator);
    MiddlewareTest.attachLog(&alpha_request, &alpha_log);

    try server.router.handleRequest(&alpha_request, &alpha_response);
    try std.testing.expectEqualStrings("GAH", alpha_log.items);
    try std.testing.expect(std.mem.eql(u8, alpha_response.getBody(), "alpha"));

    var beta_request = Http3.Request.init(allocator, 13, "conn-beta");
    defer beta_request.deinit();
    const beta_headers = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/beta" },
        .{ .name = ":authority", .value = "localhost" },
    });
    defer {
        for (beta_headers) |*field| field.deinit();
        allocator.free(beta_headers);
    }
    try beta_request.parseFromHeaders(beta_headers);

    var beta_response = Http3.Response.init(allocator, beta_request.context.stream_id);
    defer beta_response.deinit();

    var beta_log = MiddlewareLog{};
    defer beta_log.deinit(allocator);
    MiddlewareTest.attachLog(&beta_request, &beta_log);

    try server.router.handleRequest(&beta_request, &beta_response);
    try std.testing.expectEqualStrings("GBH", beta_log.items);
    try std.testing.expect(std.mem.eql(u8, beta_response.getBody(), "beta"));
}

test "integration: router error handler captures failures" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try Http3.Http3Server.init(allocator, .{});
    defer server.deinit();

    var error_called = false;

    const handler = struct {
        fn fail(_: *Http3.Request, _: *Http3.Response) Error.ZquicError!void {
            return Error.ZquicError.InternalError;
        }
    }.fail;

    const error_handler = struct {
        fn handle(req: *Http3.Request, res: *Http3.Response, err: Error.ZquicError) Error.ZquicError!void {
            switch (err) {
                inline else => {},
            }
            if (req.context.user_data) |flag_ptr| {
                const flag: *bool = @ptrCast(@alignCast(flag_ptr));
                flag.* = true;
            }
            res.setStatus(.internal_server_error);
            try res.text("boom");
        }
    }.handle;

    server.router.setErrorHandler(error_handler);
    try server.get("/explode", handler);

    var request = Http3.Request.init(allocator, 20, "conn-error");
    defer request.deinit();
    const headers = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/explode" },
        .{ .name = ":authority", .value = "localhost" },
    });
    defer {
        for (headers) |*field| field.deinit();
        allocator.free(headers);
    }
    try request.parseFromHeaders(headers);
    request.context.user_data = &error_called;

    var response = Http3.Response.init(allocator, request.context.stream_id);
    defer response.deinit();

    try server.router.handleRequest(&request, &response);

    try std.testing.expect(error_called);
    try std.testing.expect(response.status == .internal_server_error);
    try std.testing.expect(std.mem.eql(u8, response.getBody(), "boom"));
}

test "integration: static middleware serves files" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const io = std.testing.io;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.createDirPath(io, "static");
    try tmp_dir.dir.writeFile(io, .{ .sub_path = "static/index.txt", .data = "hello quic" });

    const root_path: [:0]const u8 = try tmp_dir.dir.realPathFileAlloc(io, "static", allocator);
    defer allocator.free(root_path);

    var server = try Http3.Http3Server.init(allocator, .{
        .static_files_root = root_path,
        .enable_security_headers = false,
        .enable_cors = false,
        .enable_compression = false,
    });
    defer server.deinit();

    var request = Http3.Request.init(allocator, 30, "conn-static");
    defer request.deinit();
    const headers = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/index.txt" },
        .{ .name = ":authority", .value = "localhost" },
    });
    defer {
        for (headers) |*field| field.deinit();
        allocator.free(headers);
    }
    try request.parseFromHeaders(headers);

    var response = Http3.Response.init(allocator, request.context.stream_id);
    defer response.deinit();

    try server.router.handleRequest(&request, &response);

    try std.testing.expect(std.mem.eql(u8, response.getBody(), "hello quic"));
    try std.testing.expect(response.status == .ok);
    try std.testing.expectEqualStrings("hello quic", response.getBody());
    try std.testing.expect(std.mem.eql(u8, response.headers.get("cache-control") orelse "", "public, max-age=3600"));
}
