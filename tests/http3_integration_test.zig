//! HTTP/3 integration tests exercising router and frame generation

const std = @import("std");
const zquic = @import("zquic");

const Http3 = zquic.Http3;
const Error = zquic.Error;
const NextFn = *const fn (*Http3.Request, *Http3.Response) Error.ZquicError!void;
const MiddlewareLog = std.ArrayListUnmanaged(u8);

const QpackFixtureHeader = struct {
    name: []const u8,
    value: []const u8,
};

const QpackFixture = struct {
    name: []const u8,
    description: []const u8,
    expected_result: []const u8,
    dynamic_table: []const u8,
    max_header_count: ?usize = null,
    max_header_block_size: ?usize = null,
    encoded_hex: []const u8,
    expected_headers: []const QpackFixtureHeader = &.{},
};

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

fn replayQpackFixture(comptime fixture_json: []const u8) !void {
    const parsed = try std.json.parseFromSlice(QpackFixture, std.testing.allocator, fixture_json, .{});
    defer parsed.deinit();
    const fixture = parsed.value;

    try std.testing.expect(std.mem.eql(u8, fixture.dynamic_table, "disabled"));
    try std.testing.expectEqual(@as(usize, 0), fixture.encoded_hex.len % 2);

    var encoded_buffer: [4096]u8 = undefined;
    const encoded = try std.fmt.hexToBytes(&encoded_buffer, fixture.encoded_hex);

    var decoder = Http3.QpackDecoder.init(std.testing.allocator, 0);
    defer decoder.deinit(std.testing.allocator);
    if (fixture.max_header_count) |max| decoder.max_header_count = max;
    if (fixture.max_header_block_size) |max| decoder.max_header_block_size = max;

    if (std.mem.eql(u8, fixture.expected_result, "accept")) {
        const decoded = try decoder.decode(encoded, std.testing.allocator);
        defer {
            for (decoded) |*field| field.deinit();
            std.testing.allocator.free(decoded);
        }

        try std.testing.expectEqual(fixture.expected_headers.len, decoded.len);
        for (fixture.expected_headers, 0..) |expected, index| {
            try std.testing.expectEqualStrings(expected.name, decoded[index].name);
            try std.testing.expectEqualStrings(expected.value, decoded[index].value);
        }
    } else if (std.mem.eql(u8, fixture.expected_result, "reject")) {
        try std.testing.expectError(Error.ZquicError.HeaderError, decoder.decode(encoded, std.testing.allocator));
    } else if (std.mem.eql(u8, fixture.expected_result, "reject_invalid_data")) {
        try std.testing.expectError(Error.ZquicError.InvalidData, decoder.decode(encoded, std.testing.allocator));
    } else {
        return Error.ZquicError.InvalidArgument;
    }
}

test "integration: http3 server routes request to handler" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

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
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

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

    var call_log = MiddlewareLog.empty;
    defer call_log.deinit(allocator);
    MiddlewareTest.attachLog(&request, &call_log);

    try server.router.handleRequest(&request, &response);

    try std.testing.expectEqualStrings("ABRH", call_log.items);
    try std.testing.expect(std.mem.eql(u8, response.getBody(), "ok"));
}

test "integration: middleware short circuits handler" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

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

    var call_log = MiddlewareLog.empty;
    defer call_log.deinit(allocator);
    MiddlewareTest.attachLog(&request, &call_log);

    try server.router.handleRequest(&request, &response);

    try std.testing.expectEqualStrings("GR", call_log.items);
    try std.testing.expect(response.status == .forbidden);
    try std.testing.expect(std.mem.eql(u8, response.getBody(), "blocked"));
}

test "integration: route middleware isolation" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

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

    var alpha_log = MiddlewareLog.empty;
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

    var beta_log = MiddlewareLog.empty;
    defer beta_log.deinit(allocator);
    MiddlewareTest.attachLog(&beta_request, &beta_log);

    try server.router.handleRequest(&beta_request, &beta_response);
    try std.testing.expectEqualStrings("GBH", beta_log.items);
    try std.testing.expect(std.mem.eql(u8, beta_response.getBody(), "beta"));
}

test "integration: router error handler captures failures" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

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
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

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

    // Set middleware config from server (normally done by processRequest)
    request.middleware_config = @ptrCast(&server.middleware_config);

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

test "integration: router returns 405 with allow header" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server = try Http3.Http3Server.init(allocator, .{});
    defer server.deinit();

    const handler = struct {
        fn handle(_: *Http3.Request, res: *Http3.Response) Error.ZquicError!void {
            try res.text("ok");
        }
    }.handle;

    try server.get("/items", handler);
    try server.post("/items", handler);

    var request = Http3.Request.init(allocator, 40, "conn-405");
    defer request.deinit();
    const headers = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "DELETE" },
        .{ .name = ":path", .value = "/items" },
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
    try std.testing.expectEqual(Http3.StatusCode.method_not_allowed, response.status);
    try std.testing.expectEqualStrings("GET, POST", response.headers.get("allow").?);
}

test "integration: POST request body is visible to handler" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server = try Http3.Http3Server.init(allocator, .{});
    defer server.deinit();

    const handler = struct {
        fn echo(req: *Http3.Request, res: *Http3.Response) Error.ZquicError!void {
            try res.text(req.getBody());
        }
    }.echo;

    try server.post("/echo", handler);

    var request = Http3.Request.init(allocator, 41, "conn-post");
    defer request.deinit();
    const headers = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "11" },
    });
    defer {
        for (headers) |*field| field.deinit();
        allocator.free(headers);
    }
    try request.parseFromHeaders(headers);
    try request.appendBody("hello ");
    try request.appendBody("zquic");

    var response = Http3.Response.init(allocator, request.context.stream_id);
    defer response.deinit();

    try server.router.handleRequest(&request, &response);
    try std.testing.expectEqualStrings("hello zquic", response.getBody());
}

test "integration: concurrent request streams stay isolated" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server = try Http3.Http3Server.init(allocator, .{});
    defer server.deinit();

    const handler = struct {
        fn streamId(req: *Http3.Request, res: *Http3.Response) Error.ZquicError!void {
            try res.writeFormat("stream={d}", .{req.context.stream_id});
        }
    }.streamId;

    try server.get("/stream", handler);

    var req_a = Http3.Request.init(allocator, 44, "conn-concurrent");
    defer req_a.deinit();
    var req_b = Http3.Request.init(allocator, 48, "conn-concurrent");
    defer req_b.deinit();

    const headers_a = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/stream" },
        .{ .name = ":authority", .value = "localhost" },
    });
    defer {
        for (headers_a) |*field| field.deinit();
        allocator.free(headers_a);
    }
    const headers_b = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/stream" },
        .{ .name = ":authority", .value = "localhost" },
    });
    defer {
        for (headers_b) |*field| field.deinit();
        allocator.free(headers_b);
    }
    try req_a.parseFromHeaders(headers_a);
    try req_b.parseFromHeaders(headers_b);

    var res_a = Http3.Response.init(allocator, req_a.context.stream_id);
    defer res_a.deinit();
    var res_b = Http3.Response.init(allocator, req_b.context.stream_id);
    defer res_b.deinit();

    try server.router.handleRequest(&req_a, &res_a);
    try server.router.handleRequest(&req_b, &res_b);

    try std.testing.expectEqualStrings("stream=44", res_a.getBody());
    try std.testing.expectEqualStrings("stream=48", res_b.getBody());
}

test "interop: http3 settings fixture parses exact values" {
    var settings = Http3.SettingsFrame.init(std.testing.allocator);
    defer settings.deinit(std.testing.allocator);

    try settings.addSetting(std.testing.allocator, 0x01, 0);
    try settings.addSetting(std.testing.allocator, 0x06, 4096);

    var buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try settings.serialize(&writer, std.testing.allocator);

    const written = std.Io.Writer.buffered(&writer);
    const header = try Http3.FrameHeader.parse(written);
    try std.testing.expectEqual(Http3.FrameType.settings, header.header.frame_type);

    const payload_start = header.consumed;
    const payload_end = payload_start + @as(usize, @intCast(header.header.length));
    var parsed = try Http3.SettingsFrame.parse(written[payload_start..payload_end], std.testing.allocator);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.settings.items.len);
    try std.testing.expectEqual(@as(u64, 0x01), parsed.settings.items[0].id);
    try std.testing.expectEqual(@as(u64, 0), parsed.settings.items[0].value);
    try std.testing.expectEqual(@as(u64, 0x06), parsed.settings.items[1].id);
    try std.testing.expectEqual(@as(u64, 4096), parsed.settings.items[1].value);
}

test "interop: http3 goaway and cancellation frames parse" {
    var goaway_buffer: [16]u8 = undefined;
    var goaway_writer = std.Io.Writer.fixed(&goaway_buffer);
    try Http3.GoawayFrame.init(100).serialize(&goaway_writer);

    const goaway_bytes = std.Io.Writer.buffered(&goaway_writer);
    const goaway_header = try Http3.FrameHeader.parse(goaway_bytes);
    try std.testing.expectEqual(Http3.FrameType.goaway, goaway_header.header.frame_type);
    const goaway_payload_start = goaway_header.consumed;
    const goaway_payload_end = goaway_payload_start + @as(usize, @intCast(goaway_header.header.length));
    const goaway = try Http3.GoawayFrame.parse(goaway_bytes[goaway_payload_start..goaway_payload_end]);
    try std.testing.expectEqual(@as(u64, 100), goaway.stream_or_push_id);

    var cancel_buffer: [16]u8 = undefined;
    var cancel_writer = std.Io.Writer.fixed(&cancel_buffer);
    try Http3.CancelPushFrame.init(3).serialize(&cancel_writer);

    const cancel_bytes = std.Io.Writer.buffered(&cancel_writer);
    const cancel_header = try Http3.FrameHeader.parse(cancel_bytes);
    try std.testing.expectEqual(Http3.FrameType.cancel_push, cancel_header.header.frame_type);
    const cancel_payload_start = cancel_header.consumed;
    const cancel_payload_end = cancel_payload_start + @as(usize, @intCast(cancel_header.header.length));
    const cancel = try Http3.CancelPushFrame.parse(cancel_bytes[cancel_payload_start..cancel_payload_end]);
    try std.testing.expectEqual(@as(u64, 3), cancel.push_id);
}

test "interop: http3 malformed frame rejection" {
    try std.testing.expectError(error.Http3Error, Http3.FrameHeader.parse(&[_]u8{0x40}));
    try std.testing.expectError(error.Http3Error, Http3.FrameHeader.parse(&[_]u8{ 0x21, 0x00 }));
    try std.testing.expectError(error.Http3Error, Http3.SettingsFrame.parse(&[_]u8{ 0x01, 0x40 }, std.testing.allocator));
    try std.testing.expectError(error.Http3Error, Http3.GoawayFrame.parse(&[_]u8{}));
    try std.testing.expectError(error.Http3Error, Http3.CancelPushFrame.parse(&[_]u8{ 0x03, 0x00 }));
}

test "interop: http3 request response lifecycle and error mapping" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server = try Http3.Http3Server.init(allocator, .{});
    defer server.deinit();

    const handlers = struct {
        fn ok(_: *Http3.Request, res: *Http3.Response) Error.ZquicError!void {
            try res.text("interop-ok");
        }

        fn fail(_: *Http3.Request, _: *Http3.Response) Error.ZquicError!void {
            return Error.ZquicError.ProtocolViolation;
        }
    };

    try server.get("/interop", handlers.ok);
    try server.get("/fail", handlers.fail);

    var ok_request = Http3.Request.init(allocator, 64, "conn-h3-interop");
    defer ok_request.deinit();
    const ok_headers = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/interop" },
        .{ .name = ":authority", .value = "localhost" },
    });
    defer {
        for (ok_headers) |*field| field.deinit();
        allocator.free(ok_headers);
    }
    try ok_request.parseFromHeaders(ok_headers);

    var ok_response = Http3.Response.init(allocator, ok_request.context.stream_id);
    defer ok_response.deinit();
    try server.router.handleRequest(&ok_request, &ok_response);
    try std.testing.expectEqual(Http3.StatusCode.ok, ok_response.status);
    try std.testing.expectEqualStrings("interop-ok", ok_response.getBody());

    var fail_request = Http3.Request.init(allocator, 68, "conn-h3-interop");
    defer fail_request.deinit();
    const fail_headers = try buildHeaderFields(allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/fail" },
        .{ .name = ":authority", .value = "localhost" },
    });
    defer {
        for (fail_headers) |*field| field.deinit();
        allocator.free(fail_headers);
    }
    try fail_request.parseFromHeaders(fail_headers);

    var fail_response = Http3.Response.init(allocator, fail_request.context.stream_id);
    defer fail_response.deinit();
    try server.router.handleRequest(&fail_request, &fail_response);
    try std.testing.expectEqual(Http3.StatusCode.internal_server_error, fail_response.status);
}

test "interop: qpack fixtures replay" {
    try replayQpackFixture(@embedFile("fixtures/qpack/static-table-literals.json"));
    try replayQpackFixture(@embedFile("fixtures/qpack/duplicate-pseudo-header.json"));
    try replayQpackFixture(@embedFile("fixtures/qpack/malformed-block.json"));
    try replayQpackFixture(@embedFile("fixtures/qpack/header-list-size-limit.json"));
    try replayQpackFixture(@embedFile("fixtures/qpack/dynamic-table-disabled.json"));
}
