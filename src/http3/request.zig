//! HTTP/3 request handling
//!
//! HTTP request structures and parsing for HTTP/3

const std = @import("std");
const Error = @import("../utils/error.zig");
const QpackDecoder = @import("qpack.zig").QpackDecoder;
const HeaderField = @import("qpack.zig").HeaderField;

/// HTTP methods
pub const Method = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
    CONNECT,

    pub fn fromString(method_str: []const u8) ?Method {
        if (std.mem.eql(u8, method_str, "GET")) return .GET;
        if (std.mem.eql(u8, method_str, "POST")) return .POST;
        if (std.mem.eql(u8, method_str, "PUT")) return .PUT;
        if (std.mem.eql(u8, method_str, "DELETE")) return .DELETE;
        if (std.mem.eql(u8, method_str, "HEAD")) return .HEAD;
        if (std.mem.eql(u8, method_str, "OPTIONS")) return .OPTIONS;
        if (std.mem.eql(u8, method_str, "PATCH")) return .PATCH;
        if (std.mem.eql(u8, method_str, "CONNECT")) return .CONNECT;
        return null;
    }

    pub fn toString(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
            .PATCH => "PATCH",
            .CONNECT => "CONNECT",
        };
    }
};

/// HTTP version
pub const Version = enum {
    HTTP3,

    pub fn toString(self: Version) []const u8 {
        return switch (self) {
            .HTTP3 => "HTTP/3",
        };
    }
};

/// HTTP request headers
pub const Headers = struct {
    fields: std.ArrayList(HeaderField),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .fields = std.ArrayList(HeaderField).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.fields.items) |*field| {
            field.deinit();
        }
        self.fields.deinit();
    }

    pub fn add(self: *Self, name: []const u8, value: []const u8) !void {
        const field = try HeaderField.init(self.allocator, name, value);
        try self.fields.append(field);
    }

    pub fn get(self: *const Self, name: []const u8) ?[]const u8 {
        for (self.fields.items) |field| {
            if (std.ascii.eqlIgnoreCase(field.name, name)) {
                return field.value;
            }
        }
        return null;
    }

    pub fn contains(self: *const Self, name: []const u8) bool {
        return self.get(name) != null;
    }

    pub fn remove(self: *Self, name: []const u8) void {
        var i: usize = 0;
        while (i < self.fields.items.len) {
            if (std.ascii.eqlIgnoreCase(self.fields.items[i].name, name)) {
                var field = self.fields.swapRemove(i);
                field.deinit();
                continue;
            }
            i += 1;
        }
    }
};

/// Query parameters
pub const QueryParams = struct {
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

/// HTTP request context
pub const RequestContext = struct {
    stream_id: u64,
    connection_id: []const u8,
    user_data: ?*anyopaque = null,
    start_time: i64,

    const Self = @This();

    pub fn init(stream_id: u64, connection_id: []const u8) Self {
        return Self{
            .stream_id = stream_id,
            .connection_id = connection_id,
            .start_time = std.time.microTimestamp(),
        };
    }

    pub fn elapsedMicros(self: *const Self) i64 {
        return std.time.microTimestamp() - self.start_time;
    }
};

/// HTTP request
pub const Request = struct {
    method: Method,
    uri: []const u8,
    path: []const u8,
    query_string: ?[]const u8,
    version: Version,
    headers: Headers,
    query_params: QueryParams,
    body: std.ArrayList(u8),
    context: RequestContext,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, stream_id: u64, connection_id: []const u8) Self {
        return Self{
            .method = .GET,
            .uri = "",
            .path = "",
            .query_string = null,
            .version = .HTTP3,
            .headers = Headers.init(allocator),
            .query_params = QueryParams.init(allocator),
            .body = std.ArrayList(u8).init(allocator),
            .context = RequestContext.init(stream_id, connection_id),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        self.query_params.deinit();
        self.body.deinit();
        if (self.uri.len > 0) self.allocator.free(self.uri);
        if (self.path.len > 0) self.allocator.free(self.path);
        if (self.query_string) |qs| self.allocator.free(qs);
    }

    /// Parse request from QPACK-decoded headers
    pub fn parseFromHeaders(self: *Self, header_fields: []const HeaderField) !void {
        for (header_fields) |field| {
            if (std.mem.eql(u8, field.name, ":method")) {
                self.method = Method.fromString(field.value) orelse return Error.ZquicError.Http3Error;
            } else if (std.mem.eql(u8, field.name, ":path")) {
                try self.setPath(field.value);
            } else if (std.mem.eql(u8, field.name, ":scheme")) {
                // Store scheme if needed
            } else if (std.mem.eql(u8, field.name, ":authority")) {
                try self.headers.add("host", field.value);
            } else {
                try self.headers.add(field.name, field.value);
            }
        }
    }

    fn setPath(self: *Self, uri: []const u8) !void {
        self.uri = try self.allocator.dupe(u8, uri);

        // Parse path and query string
        if (std.mem.indexOf(u8, uri, "?")) |query_start| {
            self.path = try self.allocator.dupe(u8, uri[0..query_start]);
            self.query_string = try self.allocator.dupe(u8, uri[query_start + 1 ..]);
            try self.parseQueryString();
        } else {
            self.path = try self.allocator.dupe(u8, uri);
        }
    }

    fn parseQueryString(self: *Self) !void {
        if (self.query_string) |qs| {
            var params_iter = std.mem.splitScalar(u8, qs, '&');
            while (params_iter.next()) |param| {
                if (std.mem.indexOf(u8, param, "=")) |eq_pos| {
                    const key = param[0..eq_pos];
                    const value = param[eq_pos + 1 ..];
                    try self.query_params.put(key, value);
                } else {
                    try self.query_params.put(param, "");
                }
            }
        }
    }

    pub fn getHeader(self: *const Self, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }

    pub fn getQueryParam(self: *const Self, name: []const u8) ?[]const u8 {
        return self.query_params.get(name);
    }

    pub fn appendBody(self: *Self, data: []const u8) !void {
        try self.body.appendSlice(data);
    }

    pub fn getBody(self: *const Self) []const u8 {
        return self.body.items;
    }

    pub fn getContentType(self: *const Self) ?[]const u8 {
        return self.getHeader("content-type");
    }

    pub fn getUserAgent(self: *const Self) ?[]const u8 {
        return self.getHeader("user-agent");
    }

    pub fn getContentLength(self: *const Self) ?usize {
        if (self.getHeader("content-length")) |length_str| {
            return std.fmt.parseInt(usize, length_str, 10) catch null;
        }
        return null;
    }
};

test "request method parsing" {
    try std.testing.expect(Method.fromString("GET") == .GET);
    try std.testing.expect(Method.fromString("POST") == .POST);
    try std.testing.expect(Method.fromString("INVALID") == null);
}

test "request headers management" {
    var headers = Headers.init(std.testing.allocator);
    defer headers.deinit();

    try headers.add("content-type", "application/json");
    try headers.add("authorization", "Bearer token123");

    try std.testing.expect(std.mem.eql(u8, headers.get("content-type").?, "application/json"));
    try std.testing.expect(headers.contains("authorization"));
    try std.testing.expect(!headers.contains("nonexistent"));
}

test "query params parsing" {
    var request = Request.init(std.testing.allocator, 1, "test-conn");
    defer request.deinit();

    try request.setPath("/api/users?id=123&name=test&active");

    try std.testing.expect(std.mem.eql(u8, request.path, "/api/users"));
    try std.testing.expect(std.mem.eql(u8, request.getQueryParam("id").?, "123"));
    try std.testing.expect(std.mem.eql(u8, request.getQueryParam("name").?, "test"));
    try std.testing.expect(std.mem.eql(u8, request.getQueryParam("active").?, ""));
}
