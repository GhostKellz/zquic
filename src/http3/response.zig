//! HTTP/3 response handling
//!
//! HTTP response structures and generation for HTTP/3

const std = @import("std");
const Error = @import("../utils/error.zig");
const HeaderField = @import("qpack.zig").HeaderField;
const Frame = @import("frame.zig");

/// HTTP status codes
pub const StatusCode = enum(u16) {
    // 2xx Success
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    partial_content = 206,

    // 3xx Redirection
    moved_permanently = 301,
    found = 302,
    not_modified = 304,
    temporary_redirect = 307,
    permanent_redirect = 308,

    // 4xx Client Error
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    conflict = 409,
    gone = 410,
    length_required = 411,
    payload_too_large = 413,
    uri_too_long = 414,
    unsupported_media_type = 415,
    range_not_satisfiable = 416,
    expectation_failed = 417,
    unprocessable_entity = 422,
    too_many_requests = 429,

    // 5xx Server Error
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,

    pub fn toString(self: StatusCode) []const u8 {
        return switch (self) {
            .ok => "200 OK",
            .created => "201 Created",
            .accepted => "202 Accepted",
            .no_content => "204 No Content",
            .partial_content => "206 Partial Content",
            .moved_permanently => "301 Moved Permanently",
            .found => "302 Found",
            .not_modified => "304 Not Modified",
            .temporary_redirect => "307 Temporary Redirect",
            .permanent_redirect => "308 Permanent Redirect",
            .bad_request => "400 Bad Request",
            .unauthorized => "401 Unauthorized",
            .forbidden => "403 Forbidden",
            .not_found => "404 Not Found",
            .method_not_allowed => "405 Method Not Allowed",
            .not_acceptable => "406 Not Acceptable",
            .conflict => "409 Conflict",
            .gone => "410 Gone",
            .length_required => "411 Length Required",
            .payload_too_large => "413 Payload Too Large",
            .uri_too_long => "414 URI Too Long",
            .unsupported_media_type => "415 Unsupported Media Type",
            .range_not_satisfiable => "416 Range Not Satisfiable",
            .expectation_failed => "417 Expectation Failed",
            .unprocessable_entity => "422 Unprocessable Entity",
            .too_many_requests => "429 Too Many Requests",
            .internal_server_error => "500 Internal Server Error",
            .not_implemented => "501 Not Implemented",
            .bad_gateway => "502 Bad Gateway",
            .service_unavailable => "503 Service Unavailable",
            .gateway_timeout => "504 Gateway Timeout",
            .http_version_not_supported => "505 HTTP Version Not Supported",
        };
    }

    pub fn getCode(self: StatusCode) u16 {
        return @intFromEnum(self);
    }

    pub fn getReasonPhrase(self: StatusCode) []const u8 {
        const full_str = self.toString();
        if (std.mem.indexOf(u8, full_str, " ")) |space_pos| {
            return full_str[space_pos + 1 ..];
        }
        return "Unknown";
    }
};

/// Response headers management
pub const ResponseHeaders = struct {
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

    pub fn set(self: *Self, name: []const u8, value: []const u8) !void {
        // Remove existing headers with the same name
        var i: usize = 0;
        while (i < self.fields.items.len) {
            if (std.ascii.eqlIgnoreCase(self.fields.items[i].name, name)) {
                var field = self.fields.swapRemove(i);
                field.deinit();
                continue;
            }
            i += 1;
        }
        // Add new header
        try self.add(name, value);
    }

    pub fn get(self: *const Self, name: []const u8) ?[]const u8 {
        for (self.fields.items) |field| {
            if (std.ascii.eqlIgnoreCase(field.name, name)) {
                return field.value;
            }
        }
        return null;
    }

    pub fn setContentType(self: *Self, content_type: []const u8) !void {
        try self.set("content-type", content_type);
    }

    pub fn setContentLength(self: *Self, length: usize) !void {
        var buffer: [32]u8 = undefined;
        const length_str = try std.fmt.bufPrint(&buffer, "{d}", .{length});
        try self.set("content-length", length_str);
    }

    pub fn setCacheControl(self: *Self, cache_control: []const u8) !void {
        try self.set("cache-control", cache_control);
    }

    pub fn setLocation(self: *Self, location: []const u8) !void {
        try self.set("location", location);
    }

    pub fn setCookie(self: *Self, name: []const u8, value: []const u8, options: CookieOptions) !void {
        var cookie_buffer: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&cookie_buffer);
        const writer = fbs.writer();

        try writer.print("{s}={s}", .{ name, value });

        if (options.max_age) |max_age| {
            try writer.print("; Max-Age={d}", .{max_age});
        }

        if (options.domain) |domain| {
            try writer.print("; Domain={s}", .{domain});
        }

        if (options.path) |path| {
            try writer.print("; Path={s}", .{path});
        }

        if (options.secure) {
            try writer.writeAll("; Secure");
        }

        if (options.http_only) {
            try writer.writeAll("; HttpOnly");
        }

        if (options.same_site) |same_site| {
            try writer.print("; SameSite={s}", .{same_site});
        }

        const cookie_str = fbs.getWritten();
        try self.add("set-cookie", cookie_str);
    }

    pub fn addCORS(self: *Self, origin: ?[]const u8) !void {
        try self.set("access-control-allow-origin", origin orelse "*");
        try self.set("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS");
        try self.set("access-control-allow-headers", "Content-Type, Authorization");
    }
};

/// Cookie options for Set-Cookie header
pub const CookieOptions = struct {
    max_age: ?u32 = null,
    domain: ?[]const u8 = null,
    path: ?[]const u8 = null,
    secure: bool = false,
    http_only: bool = false,
    same_site: ?[]const u8 = null, // "Strict", "Lax", or "None"
};

/// HTTP response
pub const Response = struct {
    status: StatusCode,
    headers: ResponseHeaders,
    body: std.ArrayList(u8),
    allocator: std.mem.Allocator,
    stream_id: u64,
    is_sent: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, stream_id: u64) Self {
        return Self{
            .status = .ok,
            .headers = ResponseHeaders.init(allocator),
            .body = std.ArrayList(u8).init(allocator),
            .allocator = allocator,
            .stream_id = stream_id,
        };
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        self.body.deinit();
    }

    /// Set response status
    pub fn setStatus(self: *Self, status: StatusCode) void {
        self.status = status;
    }

    /// Set response header
    pub fn setHeader(self: *Self, name: []const u8, value: []const u8) !void {
        try self.headers.set(name, value);
    }

    /// Add response header (allows multiple headers with same name)
    pub fn addHeader(self: *Self, name: []const u8, value: []const u8) !void {
        try self.headers.add(name, value);
    }

    /// Write data to response body
    pub fn write(self: *Self, data: []const u8) !void {
        try self.body.appendSlice(data);
    }

    /// Write formatted data to response body
    pub fn writeFormat(self: *Self, comptime fmt: []const u8, args: anytype) !void {
        try self.body.writer().print(fmt, args);
    }

    /// Set JSON content type and write JSON data
    pub fn json(self: *Self, data: anytype) !void {
        try self.headers.setContentType("application/json");
        try std.json.stringify(data, .{}, self.body.writer());
    }

    /// Set HTML content type and write HTML
    pub fn html(self: *Self, html_content: []const u8) !void {
        try self.headers.setContentType("text/html; charset=utf-8");
        try self.write(html_content);
    }

    /// Set plain text content type and write text
    pub fn text(self: *Self, text_content: []const u8) !void {
        try self.headers.setContentType("text/plain; charset=utf-8");
        try self.write(text_content);
    }

    /// Redirect to another URL
    pub fn redirect(self: *Self, status: StatusCode, location: []const u8) !void {
        self.setStatus(status);
        try self.headers.setLocation(location);
    }

    /// Send file content (basic implementation)
    pub fn sendFile(self: *Self, file_path: []const u8) !void {
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                self.setStatus(.not_found);
                try self.text("File not found");
                return;
            },
            else => return err,
        };
        defer file.close();

        // Determine content type from extension
        const content_type = getContentTypeFromPath(file_path);
        try self.headers.setContentType(content_type);

        // Read and write file content
        const file_size = try file.getEndPos();
        try self.body.ensureTotalCapacity(file_size);
        _ = try file.readAll(self.body.items[0..file_size]);
        self.body.items.len = file_size;
    }

    /// Get response body
    pub fn getBody(self: *const Self) []const u8 {
        return self.body.items;
    }

    /// Get response body size
    pub fn getBodySize(self: *const Self) usize {
        return self.body.items.len;
    }

    /// Generate HTTP/3 frames for this response
    pub fn generateFrames(self: *Self, allocator: std.mem.Allocator) ![]Frame.Frame {
        var frames = std.ArrayList(Frame.Frame).init(allocator);

        // Set content-length if not already set
        if (self.headers.get("content-length") == null) {
            try self.headers.setContentLength(self.body.items.len);
        }

        // Add pseudo-headers for HTTP/3
        var all_headers = std.ArrayList(HeaderField).init(allocator);
        defer {
            for (all_headers.items) |*field| {
                field.deinit();
            }
            all_headers.deinit();
        }

        // Add :status pseudo-header
        var status_buffer: [8]u8 = undefined;
        const status_str = try std.fmt.bufPrint(&status_buffer, "{d}", .{self.status.getCode()});
        try all_headers.append(try HeaderField.init(allocator, ":status", status_str));

        // Add regular headers
        for (self.headers.fields.items) |field| {
            try all_headers.append(try HeaderField.init(allocator, field.name, field.value));
        }

        // Create HEADERS frame (simplified - would need QPACK encoding)
        const headers_payload = try allocator.alloc(u8, all_headers.items.len * 32); // Simplified
        defer allocator.free(headers_payload);

        // TODO: Properly encode headers with QPACK
        const headers_frame = Frame.Frame{
            .frame_type = .headers,
            .payload = try allocator.dupe(u8, headers_payload[0..0]), // Empty for now
        };
        try frames.append(headers_frame);

        // Create DATA frame if body exists
        if (self.body.items.len > 0) {
            const data_frame = Frame.Frame{
                .frame_type = .data,
                .payload = try allocator.dupe(u8, self.body.items),
            };
            try frames.append(data_frame);
        }

        return frames.toOwnedSlice();
    }

    /// Mark response as sent
    pub fn markSent(self: *Self) void {
        self.is_sent = true;
    }

    /// Check if response has been sent
    pub fn isSent(self: *const Self) bool {
        return self.is_sent;
    }
};

/// Get content type from file extension
fn getContentTypeFromPath(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '.')) |dot_index| {
        const ext = path[dot_index + 1 ..];

        if (std.mem.eql(u8, ext, "html") or std.mem.eql(u8, ext, "htm")) {
            return "text/html";
        } else if (std.mem.eql(u8, ext, "css")) {
            return "text/css";
        } else if (std.mem.eql(u8, ext, "js")) {
            return "application/javascript";
        } else if (std.mem.eql(u8, ext, "json")) {
            return "application/json";
        } else if (std.mem.eql(u8, ext, "png")) {
            return "image/png";
        } else if (std.mem.eql(u8, ext, "jpg") or std.mem.eql(u8, ext, "jpeg")) {
            return "image/jpeg";
        } else if (std.mem.eql(u8, ext, "gif")) {
            return "image/gif";
        } else if (std.mem.eql(u8, ext, "svg")) {
            return "image/svg+xml";
        } else if (std.mem.eql(u8, ext, "pdf")) {
            return "application/pdf";
        }
    }

    return "application/octet-stream";
}

test "status code functionality" {
    try std.testing.expect(StatusCode.ok.getCode() == 200);
    try std.testing.expect(std.mem.eql(u8, StatusCode.not_found.toString(), "404 Not Found"));
    try std.testing.expect(std.mem.eql(u8, StatusCode.ok.getReasonPhrase(), "OK"));
}

test "response headers" {
    var headers = ResponseHeaders.init(std.testing.allocator);
    defer headers.deinit();

    try headers.setContentType("application/json");
    try headers.setContentLength(100);

    try std.testing.expect(std.mem.eql(u8, headers.get("content-type").?, "application/json"));
    try std.testing.expect(std.mem.eql(u8, headers.get("content-length").?, "100"));
}

test "response creation and modification" {
    var response = Response.init(std.testing.allocator, 1);
    defer response.deinit();

    response.setStatus(.created);
    try response.setHeader("x-custom", "test-value");
    try response.write("Hello, World!");

    try std.testing.expect(response.status == .created);
    try std.testing.expect(std.mem.eql(u8, response.getBody(), "Hello, World!"));
    try std.testing.expect(response.getBodySize() == 13);
}

test "content type detection" {
    try std.testing.expect(std.mem.eql(u8, getContentTypeFromPath("index.html"), "text/html"));
    try std.testing.expect(std.mem.eql(u8, getContentTypeFromPath("style.css"), "text/css"));
    try std.testing.expect(std.mem.eql(u8, getContentTypeFromPath("app.js"), "application/javascript"));
    try std.testing.expect(std.mem.eql(u8, getContentTypeFromPath("unknown.xyz"), "application/octet-stream"));
}
