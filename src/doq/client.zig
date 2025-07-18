//! DNS-over-QUIC Client Implementation (RFC 9250)
//!
//! Post-quantum secure DoQ client for async DNS queries

const std = @import("std");
const zquic = @import("../root.zig");
const message = @import("message.zig");
const Error = @import("../utils/error.zig");

const Connection = zquic.Connection.Connection;
const Stream = zquic.Stream.Stream;
const DnsMessage = message.DnsMessage;
const DnsRecordType = message.DnsRecordType;

/// DoQ client configuration
pub const DoQClientConfig = struct {
    /// Server address
    server_address: []const u8 = "1.1.1.1",
    /// Server port (standard DoQ port)
    server_port: u16 = 853,
    /// Query timeout in milliseconds
    timeout_ms: u32 = 5000,
    /// Enable post-quantum crypto
    enable_post_quantum: bool = true,
    /// Max retry attempts
    max_retries: u32 = 3,
    /// Connection keep-alive duration in seconds
    keep_alive_seconds: u32 = 300,
    /// Enable connection reuse
    enable_connection_reuse: bool = true,
    /// Client certificate path (optional)
    client_cert_path: ?[]const u8 = null,
    /// Client private key path (optional)
    client_key_path: ?[]const u8 = null,
};

/// DoQ query options
pub const DoQQueryOptions = struct {
    /// Query ID (auto-generated if 0)
    id: u16 = 0,
    /// Recursion desired
    recursion_desired: bool = true,
    /// Query timeout override
    timeout_ms: ?u32 = null,
    /// Retry count override
    max_retries: ?u32 = null,
};

/// DoQ query result
pub const DoQQueryResult = struct {
    /// DNS response message
    response: DnsMessage,
    /// Query duration in milliseconds
    duration_ms: u64,
    /// Number of retry attempts made
    retry_count: u32,
    /// Server address that responded
    server_address: []const u8,
    /// Response size in bytes
    response_size: usize,

    pub fn deinit(self: *DoQQueryResult) void {
        self.response.deinit();
    }
};

/// DoQ client statistics
pub const DoQClientStats = struct {
    queries_sent: u64 = 0,
    queries_successful: u64 = 0,
    queries_failed: u64 = 0,
    queries_retried: u64 = 0,
    connections_created: u64 = 0,
    connections_reused: u64 = 0,
    total_query_time_ms: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,

    pub fn averageQueryTime(self: *const DoQClientStats) f64 {
        if (self.queries_successful == 0) return 0.0;
        return @as(f64, @floatFromInt(self.total_query_time_ms)) / @as(f64, @floatFromInt(self.queries_successful));
    }

    pub fn successRate(self: *const DoQClientStats) f64 {
        const total = self.queries_successful + self.queries_failed;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.queries_successful)) / @as(f64, @floatFromInt(total));
    }

    pub fn toJson(self: *const DoQClientStats, allocator: std.mem.Allocator) ![]u8 {
        return std.json.stringifyAlloc(allocator, self, .{});
    }
};

/// DNS-over-QUIC Client
pub const DoQClient = struct {
    config: DoQClientConfig,
    stats: DoQClientStats,
    allocator: std.mem.Allocator,
    connection: ?*Connection = null,
    connection_created_at: i64 = 0,
    next_query_id: u16 = 1,

    pub fn init(allocator: std.mem.Allocator, config: DoQClientConfig) DoQClient {
        return DoQClient{
            .config = config,
            .stats = DoQClientStats{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DoQClient) void {
        self.disconnect();
    }

    /// Connect to DoQ server
    pub fn connect(self: *DoQClient) !void {
        if (self.connection != null and self.isConnectionValid()) {
            self.stats.connections_reused += 1;
            return;
        }

        self.disconnect();

        std.log.info("🔗 DoQ: Connecting to {}:{} with post-quantum crypto", .{ self.config.server_address, self.config.server_port });

        // Create QUIC connection with post-quantum crypto
        const conn_config = zquic.Connection.ConnectionConfig{
            .max_streams = 1, // DoQ typically uses stream 0
            .max_packet_size = 1200,
            .idle_timeout_ms = self.config.keep_alive_seconds * 1000,
            .enable_post_quantum = self.config.enable_post_quantum,
        };

        self.connection = try Connection.connect(
            self.allocator,
            self.config.server_address,
            self.config.server_port,
            conn_config,
        );

        self.connection_created_at = std.time.timestamp();
        self.stats.connections_created += 1;

        std.log.info("✅ DoQ: Connected successfully with quantum-safe encryption");
    }

    /// Disconnect from DoQ server
    pub fn disconnect(self: *DoQClient) void {
        if (self.connection) |conn| {
            conn.close();
            self.connection = null;
            self.connection_created_at = 0;
        }
    }

    /// Query DNS record
    pub fn query(self: *DoQClient, domain: []const u8, record_type: DnsRecordType, options: DoQQueryOptions) !DoQQueryResult {
        const start_time = std.time.milliTimestamp();
        
        try self.connect();

        const query_id = if (options.id != 0) options.id else blk: {
            const id = self.next_query_id;
            self.next_query_id +%= 1;
            if (self.next_query_id == 0) self.next_query_id = 1;
            break :blk id;
        };

        // Create DNS query message
        var query_msg = try self.createQuery(domain, record_type, query_id, options);
        defer query_msg.deinit();

        const max_retries = options.max_retries orelse self.config.max_retries;
        const timeout_ms = options.timeout_ms orelse self.config.timeout_ms;

        var retry_count: u32 = 0;
        while (retry_count <= max_retries) {
            const result = self.executeQuery(&query_msg, timeout_ms) catch |err| {
                retry_count += 1;
                if (retry_count > max_retries) {
                    self.stats.queries_failed += 1;
                    std.log.err("DoQ: Query failed after {} retries: {}", .{ max_retries, err });
                    return err;
                }
                
                self.stats.queries_retried += 1;
                std.log.warn("DoQ: Query failed, retrying ({}/{}): {}", .{ retry_count, max_retries, err });
                
                // Reconnect on failure
                self.disconnect();
                try self.connect();
                continue;
            };

            const end_time = std.time.milliTimestamp();
            const duration = @as(u64, @intCast(end_time - start_time));

            self.stats.queries_successful += 1;
            self.stats.total_query_time_ms += duration;

            return DoQQueryResult{
                .response = result.response,
                .duration_ms = duration,
                .retry_count = retry_count,
                .server_address = self.config.server_address,
                .response_size = result.response_size,
            };
        }

        unreachable;
    }

    /// Query A record (IPv4 address)
    pub fn queryA(self: *DoQClient, domain: []const u8, options: DoQQueryOptions) !DoQQueryResult {
        return self.query(domain, DnsRecordType.A, options);
    }

    /// Query AAAA record (IPv6 address)
    pub fn queryAAAA(self: *DoQClient, domain: []const u8, options: DoQQueryOptions) !DoQQueryResult {
        return self.query(domain, DnsRecordType.AAAA, options);
    }

    /// Query TXT record
    pub fn queryTXT(self: *DoQClient, domain: []const u8, options: DoQQueryOptions) !DoQQueryResult {
        return self.query(domain, DnsRecordType.TXT, options);
    }

    /// Query MX record
    pub fn queryMX(self: *DoQClient, domain: []const u8, options: DoQQueryOptions) !DoQQueryResult {
        return self.query(domain, DnsRecordType.MX, options);
    }

    /// Get client statistics
    pub fn getStats(self: *const DoQClient) DoQClientStats {
        return self.stats;
    }

    /// Reset client statistics
    pub fn resetStats(self: *DoQClient) void {
        self.stats = DoQClientStats{};
    }

    fn isConnectionValid(self: *const DoQClient) bool {
        if (self.connection == null) return false;
        
        const age = std.time.timestamp() - self.connection_created_at;
        return age < self.config.keep_alive_seconds and self.connection.?.isActive();
    }

    fn createQuery(self: *DoQClient, domain: []const u8, record_type: DnsRecordType, query_id: u16, options: DoQQueryOptions) !DnsMessage {
        var query_msg = DnsMessage.init(self.allocator);
        
        query_msg.header = message.DnsHeader{
            .id = query_id,
            .flags = if (options.recursion_desired) 0x0100 else 0x0000, // RD bit
            .qdcount = 1,
            .ancount = 0,
            .nscount = 0,
            .arcount = 0,
        };

        // Add question
        query_msg.questions = try self.allocator.alloc(message.DnsQuestion, 1);
        query_msg.questions[0] = message.DnsQuestion{
            .name = try self.allocator.dupe(u8, domain),
            .qtype = @intFromEnum(record_type),
            .qclass = 1, // IN
        };

        return query_msg;
    }

    fn executeQuery(self: *DoQClient, query_msg: *const DnsMessage, timeout_ms: u32) !struct { response: DnsMessage, response_size: usize } {
        if (self.connection == null) return Error.ZquicError.ConnectionClosed;

        // Serialize query
        const query_data = try query_msg.serializeToStream(self.allocator);
        defer self.allocator.free(query_data);

        self.stats.queries_sent += 1;
        self.stats.bytes_sent += query_data.len;

        // Get stream 0 for DoQ (RFC 9250)
        const stream = try self.connection.?.openStream(0);
        defer stream.close();

        // Send query
        try stream.write(query_data);

        std.log.debug("DoQ: Sent {} byte query for '{s}'", .{ query_data.len, query_msg.questions[0].name });

        // Read response with timeout
        var response_buffer: [4096]u8 = undefined;
        const bytes_read = try stream.readWithTimeout(response_buffer[0..], timeout_ms);
        
        if (bytes_read == 0) {
            return Error.ZquicError.EmptyResponse;
        }

        self.stats.bytes_received += bytes_read;

        // Parse response
        const response = try DnsMessage.parseFromStream(self.allocator, response_buffer[0..bytes_read]);

        std.log.debug("DoQ: Received {} byte response", .{bytes_read});

        return .{ .response = response, .response_size = bytes_read };
    }
};

/// Create DoQ client with Cloudflare DoQ server
pub fn createCloudflareClient(allocator: std.mem.Allocator) DoQClient {
    const config = DoQClientConfig{
        .server_address = "cloudflare-dns.com",
        .server_port = 853,
        .timeout_ms = 5000,
        .enable_post_quantum = true,
        .max_retries = 2,
        .enable_connection_reuse = true,
    };
    
    return DoQClient.init(allocator, config);
}

/// Create DoQ client with Quad9 DoQ server
pub fn createQuad9Client(allocator: std.mem.Allocator) DoQClient {
    const config = DoQClientConfig{
        .server_address = "dns.quad9.net",
        .server_port = 853,
        .timeout_ms = 5000,
        .enable_post_quantum = true,
        .max_retries = 2,
        .enable_connection_reuse = true,
    };
    
    return DoQClient.init(allocator, config);
}

/// Create DoQ client with Google DoQ server
pub fn createGoogleClient(allocator: std.mem.Allocator) DoQClient {
    const config = DoQClientConfig{
        .server_address = "dns.google",
        .server_port = 853,
        .timeout_ms = 5000,
        .enable_post_quantum = true,
        .max_retries = 2,
        .enable_connection_reuse = true,
    };
    
    return DoQClient.init(allocator, config);
}

/// Example: Resolve multiple domains concurrently
pub fn resolveMultiple(allocator: std.mem.Allocator, domains: []const []const u8, record_type: DnsRecordType) ![]DoQQueryResult {
    var client = createCloudflareClient(allocator);
    defer client.deinit();

    var results = try allocator.alloc(DoQQueryResult, domains.len);
    
    const options = DoQQueryOptions{
        .recursion_desired = true,
        .timeout_ms = 3000,
    };

    for (domains, 0..) |domain, i| {
        results[i] = client.query(domain, record_type, options) catch |err| {
            std.log.err("DoQ: Failed to resolve {s}: {}", .{ domain, err });
            
            // Create empty result for failed queries
            const empty_response = DnsMessage.init(allocator);
            results[i] = DoQQueryResult{
                .response = empty_response,
                .duration_ms = 0,
                .retry_count = 0,
                .server_address = client.config.server_address,
                .response_size = 0,
            };
        };
    }

    return results;
}

test "DoQ client initialization" {
    const allocator = std.testing.allocator;
    
    const config = DoQClientConfig{
        .server_address = "1.1.1.1",
        .server_port = 853,
    };
    
    var client = DoQClient.init(allocator, config);
    defer client.deinit();
    
    try std.testing.expect(client.config.server_port == 853);
    try std.testing.expect(client.stats.queries_sent == 0);
}

test "DoQ query creation" {
    const allocator = std.testing.allocator;
    
    var client = DoQClient.init(allocator, DoQClientConfig{});
    defer client.deinit();
    
    const options = DoQQueryOptions{
        .id = 0x1234,
        .recursion_desired = true,
    };
    
    var query = try client.createQuery("example.com", DnsRecordType.A, 0x1234, options);
    defer query.deinit();
    
    try std.testing.expect(query.header.id == 0x1234);
    try std.testing.expect(query.questions.len == 1);
    try std.testing.expectEqualStrings("example.com", query.questions[0].name);
}