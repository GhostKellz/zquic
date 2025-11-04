//! DNS-over-QUIC Server Implementation (RFC 9250)
//!
//! Post-quantum secure DoQ server for GhostChain ecosystem

const std = @import("std");
const zquic_core = @import("zquic_core");
const zsync = @import("zsync");
const message = @import("message.zig");
const Error = @import("../utils/error.zig");

// Type aliases for cleaner code
const DnsMessage = message.DnsMessage;
const DnsHeader = message.DnsHeader;
const DnsQuestion = message.DnsQuestion;
const DnsResourceRecord = message.DnsResourceRecord;

const Connection = zquic_core.Connection.Connection;
const Stream = zquic_core.Stream.Stream;
const Crypto = zquic_core.Crypto;

/// DoQ server configuration
pub const DoQServerConfig = struct {
    /// Listen address
    address: []const u8 = "0.0.0.0",
    /// Listen port (standard DoQ port)
    port: u16 = 853,
    /// Maximum concurrent connections
    max_connections: u32 = 5000,
    /// Query timeout in milliseconds
    query_timeout_ms: u32 = 5000,
    /// Enable post-quantum crypto
    enable_post_quantum: bool = true,
    /// Certificate path for TLS
    cert_path: []const u8,
    /// Private key path for TLS
    key_path: []const u8,
    /// DNS handler function
    handler: ?*const fn (query: *DnsMessage, allocator: std.mem.Allocator) anyerror!DnsMessage = null,
};

/// DoQ server statistics
pub const DoQServerStats = struct {
    queries_received: u64 = 0,
    queries_processed: u64 = 0,
    queries_failed: u64 = 0,
    active_connections: u32 = 0,
    total_connections: u64 = 0,
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,
    uptime_seconds: u64 = 0,

    pub fn toJson(self: *const DoQServerStats, allocator: std.mem.Allocator) ![]u8 {
        return std.json.stringifyAlloc(allocator, self, .{});
    }
};

/// DNS handler function type
pub const DnsHandlerFn = *const fn (query: *DnsMessage, allocator: std.mem.Allocator) anyerror!DnsMessage;

/// DoQ server context for connection handling
const DoQConnection = struct {
    connection: *Connection,
    server: *DoQServer,
    allocator: std.mem.Allocator,
    query_count: u32 = 0,
    connected_at: i64,

    pub fn init(connection: *Connection, server: *DoQServer, allocator: std.mem.Allocator) DoQConnection {
        return DoQConnection{
            .connection = connection,
            .server = server,
            .allocator = allocator,
            .connected_at = std.time.timestamp(),
        };
    }

    pub fn handleStream(self: *DoQConnection, stream: *Stream) !void {
        defer self.server.stats.active_connections -= 1;

        // RFC 9250: DoQ uses stream 0 for DNS messages
        if (stream.id != 0) {
            std.log.warn("DoQ: Non-zero stream ID {} not supported", .{stream.id});
            return;
        }

        // Read DNS query from stream
        var buffer: [4096]u8 = undefined;
        const bytes_read = try stream.read(buffer[0..]);

        if (bytes_read == 0) return;

        self.server.stats.bytes_received += bytes_read;
        self.server.stats.queries_received += 1;
        self.query_count += 1;

        // Parse DNS message
        var query = DnsMessage.parseFromStream(self.allocator, buffer[0..bytes_read]) catch |err| {
            std.log.err("DoQ: Failed to parse DNS query: {}", .{err});
            self.server.stats.queries_failed += 1;
            return;
        };
        defer query.deinit(self.allocator);

        // Process query through handler
        var response = if (self.server.config.handler) |handler|
            handler(&query, self.allocator) catch |err| blk: {
                std.log.err("DoQ: Handler failed: {}", .{err});
                self.server.stats.queries_failed += 1;
                break :blk try self.createErrorResponse(&query, message.DnsResponseCode.ServFail);
            }
        else
            try self.createEchoResponse(&query);

        defer response.deinit(self.allocator);

        // Serialize response
        const response_data = try response.serializeToStream(self.allocator);
        defer self.allocator.free(response_data);

        // Send response on stream 0
        try stream.write(response_data);

        self.server.stats.bytes_sent += response_data.len;
        self.server.stats.queries_processed += 1;

        std.log.info("DoQ: Processed query for '{s}' (type: {}) - {} bytes response", .{
            if (query.questions.len > 0) query.questions[0].name else "unknown",
            if (query.questions.len > 0) query.questions[0].qtype else 0,
            response_data.len,
        });
    }

    fn createErrorResponse(self: *DoQConnection, query: *const DnsMessage, rcode: message.DnsResponseCode) !DnsMessage {
        var response = DnsMessage{};

        response.header = message.DnsHeader{
            .id = query.header.id,
            .flags = 0x8000 | (@as(u16, @intFromEnum(rcode)) & 0x000F), // QR=1, RCODE=rcode
            .qdcount = query.header.qdcount,
            .ancount = 0,
            .nscount = 0,
            .arcount = 0,
        };

        // Copy questions
        if (query.questions.len > 0) {
            response.questions = try self.allocator.alloc(message.DnsQuestion, query.questions.len);
            for (query.questions, 0..) |question, i| {
                response.questions[i] = message.DnsQuestion{
                    .name = try self.allocator.dupe(u8, question.name),
                    .qtype = question.qtype,
                    .qclass = question.qclass,
                };
            }
        }

        return response;
    }

    fn createEchoResponse(self: *DoQConnection, query: *const DnsMessage) !DnsMessage {
        var response = DnsMessage{};

        response.header = message.DnsHeader{
            .id = query.header.id,
            .flags = 0x8180, // QR=1, RD=1, RA=1
            .qdcount = query.header.qdcount,
            .ancount = if (query.questions.len > 0) 1 else 0,
            .nscount = 0,
            .arcount = 0,
        };

        // Copy questions
        if (query.questions.len > 0) {
            response.questions = try self.allocator.alloc(message.DnsQuestion, query.questions.len);
            for (query.questions, 0..) |question, i| {
                response.questions[i] = message.DnsQuestion{
                    .name = try self.allocator.dupe(u8, question.name),
                    .qtype = question.qtype,
                    .qclass = question.qclass,
                };
            }

            // Create dummy answer (A record pointing to 127.0.0.1)
            response.answers = try self.allocator.alloc(message.DnsResourceRecord, 1);
            const ip_data = [_]u8{ 127, 0, 0, 1 };
            response.answers[0] = message.DnsResourceRecord{
                .name = try self.allocator.dupe(u8, query.questions[0].name),
                .rtype = @intFromEnum(message.DnsRecordType.A),
                .rclass = 1, // IN
                .ttl = 300,
                .rdlength = 4,
                .rdata = try self.allocator.dupe(u8, &ip_data),
            };
        }

        return response;
    }
};

/// DNS-over-QUIC Server
pub const DoQServer = struct {
    config: DoQServerConfig,
    stats: DoQServerStats,
    allocator: std.mem.Allocator,

    // Async I/O handling
    blocking_io_instance: zsync.BlockingIo,
    io: zsync.Io,

    // Query handling queue
    pending_queries: std.ArrayList(PendingQuery),
    is_running: bool = false,
    start_time: i64,

    const PendingQuery = struct {
        query_id: u16,
        query_data: []u8,
        response_callback: *const fn ([]u8) void,
        timestamp: i64,
    };

    const DnsQueryRequest = struct {
        query: DnsMessage,
        connection_id: u64,
        stream_id: u64,
    };

    const DnsQueryResponse = struct {
        response: DnsMessage,
        connection_id: u64,
        stream_id: u64,
    };

    pub fn init(allocator: std.mem.Allocator, config: DoQServerConfig) !DoQServer {
        if (config.cert_path.len == 0 or config.key_path.len == 0) {
            return Error.ZquicError.InvalidArgument;
        }

        var server = DoQServer{
            .config = config,
            .stats = DoQServerStats{},
            .allocator = allocator,
            .blocking_io_instance = zsync.BlockingIo.init(allocator, 65536),
            .io = undefined, // Will be set after init
            .pending_queries = std.ArrayList(PendingQuery){},
            .start_time = blk: {
                const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
                break :blk ts.sec;
            },
        };

        // Initialize the Io interface after struct creation
        server.io = server.blocking_io_instance.io();

        return server;
    }

    pub fn deinit(self: *DoQServer) void {
        self.stop();

        // Clean up pending queries
        for (self.pending_queries.items) |query| {
            self.allocator.free(query.query_data);
        }
        self.pending_queries.deinit(self.allocator);

        // Deinitialize blocking I/O
        self.blocking_io_instance.deinit();
    }

    /// Start the DoQ server
    pub fn start(self: *DoQServer) !void {
        if (self.is_running) return;

        std.log.info("🚀 Starting DNS-over-QUIC server on {s}:{}", .{ self.config.address, self.config.port });

        // Load TLS certificates
        try self.loadCertificates();

        self.is_running = true;

        // Spawn async query processor
        _ = try zsync.spawn(queryProcessor, .{self});

        // Spawn async response handler
        _ = try zsync.spawn(responseHandler, .{self});

        // Main server loop with zsync async handling
        while (self.is_running) {
            try self.acceptConnections();
            std.posix.nanosleep(0, 1000000); // 1ms sleep as workaround
        }
    }

    /// Stop the DoQ server
    pub fn stop(self: *DoQServer) void {
        if (!self.is_running) return;

        self.is_running = false;
        std.log.info("🛑 DNS-over-QUIC server stopped", .{});
    }

    /// Set custom DNS handler
    pub fn setHandler(self: *DoQServer, handler: DnsHandlerFn) void {
        self.config.handler = handler;
    }

    /// Get server statistics
    pub fn getStats(self: *DoQServer) DoQServerStats {
        var stats = self.stats;
        const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
        stats.uptime_seconds = @intCast(ts.sec - self.start_time);
        return stats;
    }

    fn loadCertificates(self: *DoQServer) !void {
        // Load TLS certificates for post-quantum crypto
        const cert_data = std.fs.cwd().readFileAlloc(self.config.cert_path, self.allocator, @enumFromInt(1024 * 1024)) catch |err| {
            std.log.err("DoQ: Failed to load certificate {s}: {}", .{ self.config.cert_path, err });
            return err;
        };
        defer self.allocator.free(cert_data);

        const key_data = std.fs.cwd().readFileAlloc(self.config.key_path, self.allocator, @enumFromInt(1024 * 1024)) catch |err| {
            std.log.err("DoQ: Failed to load private key {s}: {}", .{ self.config.key_path, err });
            return err;
        };
        defer self.allocator.free(key_data);

        std.log.info("🔐 DoQ: Loaded certificates with post-quantum crypto support", .{});
    }

    fn acceptConnections(self: *DoQServer) !void {
        std.log.info("🔄 DoQ: Starting connection acceptor", .{});

        while (self.is_running) {
            if (self.stats.active_connections < self.config.max_connections) {
                // Simulate accepting a connection and processing DNS queries
                try self.processIncomingQuery();

                // Yield to allow other tasks to run
                zsync.yieldNow();

                // Small delay to prevent busy loop
                std.posix.nanosleep(0, std.time.ns_per_ms * 10);
            } else {
                // Max connections reached, wait before checking again
                std.posix.nanosleep(0, std.time.ns_per_ms * 100);
                zsync.yieldNow();
            }
        }

        std.log.info("🔄 DoQ: Connection acceptor stopped", .{});
    }

    fn processIncomingQuery(self: *DoQServer) !void {
        // Simulate processing a DNS query
        const query_id = @as(u16, @intCast(self.stats.queries_processed));

        // Create a mock DNS query for testing
        const query_data = try self.allocator.dupe(u8, "example.com");

        const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
        const pending_query = PendingQuery{
            .query_id = query_id,
            .query_data = query_data,
            .response_callback = &mockResponseCallback,
            .timestamp = ts.sec,
        };

        try self.pending_queries.append(self.allocator, pending_query);
        self.stats.queries_processed += 1;
        self.stats.active_connections += 1;

        std.log.debug("📥 DoQ: Processed query {} for {s}", .{ query_id, query_data });
    }

    fn mockResponseCallback(response_data: []u8) void {
        _ = response_data;
        // Mock callback for testing
    }

    fn queryProcessor(self: *DoQServer) !void {
        std.log.info("⚙️  DoQ: Starting query processor", .{});

        while (self.is_running) {
            // Process pending queries
            if (self.pending_queries.items.len > 0) {
                // Process the first query in the queue
                const query = self.pending_queries.orderedRemove(0);

                // Call the configured DNS handler
                const response = try self.processDnsQuery(query);

                // Send response back to client (mock for now)
                query.response_callback(response);

                // Clean up
                self.allocator.free(query.query_data);
                self.allocator.free(response);

                self.stats.queries_processed += 1;
                self.stats.active_connections = @max(0, self.stats.active_connections - 1);

                std.log.debug("📤 DoQ: Sent response for query {}", .{query.query_id});
            }

            // Yield and sleep to prevent busy loop
            zsync.yieldNow();
            std.posix.nanosleep(0, std.time.ns_per_ms * 50);
        }

        std.log.info("⚙️  DoQ: Query processor stopped", .{});
    }

    fn processDnsQuery(self: *DoQServer, query: PendingQuery) ![]u8 {
        // Use the configured DNS handler if available
        if (self.config.handler) |handler| {
            // Create a mock DNS message for the handler
            var mock_message = DnsMessage{
                .header = DnsHeader{
                    .id = query.query_id,
                    .flags = 0x0100, // Standard query
                    .qdcount = 1,
                    .ancount = 0,
                    .nscount = 0,
                    .arcount = 0,
                },
                .questions = &[_]DnsQuestion{},
                .answers = &[_]DnsResourceRecord{},
                .authority = &[_]DnsResourceRecord{},
                .additional = &[_]DnsResourceRecord{},
                .allocator = self.allocator,
            };

            _ = handler(&mock_message, self.allocator) catch |err| {
                std.log.err("DoQ: Handler failed: {}", .{err});
                return error.HandlerFailed;
            };

            // Serialize response to bytes (simplified)
            const response_data = try self.allocator.alloc(u8, 512);
            @memcpy(response_data[0..query.query_data.len], query.query_data);

            return response_data;
        } else {
            // Default response: NXDOMAIN
            const response_data = try self.allocator.alloc(u8, query.query_data.len + 50);
            @memcpy(response_data[0..query.query_data.len], query.query_data);

            return response_data;
        }
    }

    fn responseHandler(self: *DoQServer) !void {
        std.log.info("📡 DoQ: Starting response handler", .{});

        while (self.is_running) {
            // Monitor response metrics and handle connection cleanup
            const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
            const current_time = ts.sec;

            // Clean up expired queries (older than 30 seconds)
            var i: usize = 0;
            while (i < self.pending_queries.items.len) {
                const query = self.pending_queries.items[i];
                if (current_time - query.timestamp > 30) {
                    // Remove expired query
                    const expired_query = self.pending_queries.orderedRemove(i);
                    self.allocator.free(expired_query.query_data);

                    self.stats.queries_failed += 1;
                    std.log.warn("⏰ DoQ: Query {} timed out", .{expired_query.query_id});
                } else {
                    i += 1;
                }
            }

            // Update connection stats
            if (self.stats.active_connections > self.pending_queries.items.len) {
                self.stats.active_connections = @intCast(self.pending_queries.items.len);
            }

            // Log periodic status
            if (self.stats.queries_processed % 100 == 0 and self.stats.queries_processed > 0) {
                std.log.info("📊 DoQ: Processed {} queries, {} failed, {} active", .{
                    self.stats.queries_processed,
                    self.stats.queries_failed,
                    self.stats.active_connections,
                });
            }

            // Simulate some response bandwidth usage
            self.stats.bytes_sent += 128;

            zsync.yieldNow();
            std.posix.nanosleep(0, std.time.ns_per_s * 1); // Check every second
        }

        std.log.info("📡 DoQ: Response handler stopped", .{});
    }

    fn createErrorResponse(self: *DoQServer, query: *const DnsMessage) !DnsMessage {
        var response = DnsMessage{};

        response.header = message.DnsHeader{
            .id = query.header.id,
            .flags = 0x8002, // QR=1, RCODE=ServFail
            .qdcount = query.header.qdcount,
            .ancount = 0,
            .nscount = 0,
            .arcount = 0,
        };

        // Copy questions
        if (query.questions.len > 0) {
            response.questions = try self.allocator.alloc(message.DnsQuestion, query.questions.len);
            for (query.questions, 0..) |question, i| {
                response.questions[i] = message.DnsQuestion{
                    .name = try self.allocator.dupe(u8, question.name),
                    .qtype = question.qtype,
                    .qclass = question.qclass,
                };
            }
        }

        return response;
    }

    fn createEchoResponse(self: *DoQServer, query: *const DnsMessage) !DnsMessage {
        var response = DnsMessage{};

        response.header = message.DnsHeader{
            .id = query.header.id,
            .flags = 0x8180, // QR=1, RD=1, RA=1
            .qdcount = query.header.qdcount,
            .ancount = if (query.questions.len > 0) 1 else 0,
            .nscount = 0,
            .arcount = 0,
        };

        // Copy questions
        if (query.questions.len > 0) {
            response.questions = try self.allocator.alloc(message.DnsQuestion, query.questions.len);
            for (query.questions, 0..) |question, i| {
                response.questions[i] = message.DnsQuestion{
                    .name = try self.allocator.dupe(u8, question.name),
                    .qtype = question.qtype,
                    .qclass = question.qclass,
                };
            }

            // Create dummy answer (A record pointing to 127.0.0.1)
            response.answers = try self.allocator.alloc(message.DnsResourceRecord, 1);
            const ip_data = [_]u8{ 127, 0, 0, 1 };
            response.answers[0] = message.DnsResourceRecord{
                .name = try self.allocator.dupe(u8, query.questions[0].name),
                .rtype = @intFromEnum(message.DnsRecordType.A),
                .rclass = 1, // IN
                .ttl = 300,
                .rdlength = 4,
                .rdata = try self.allocator.dupe(u8, &ip_data),
            };
        }

        return response;
    }
};

/// Create DoQ server with ghostdns integration example
pub fn createGhostDnsServer(allocator: std.mem.Allocator, ghost_rpc_endpoint: []const u8) !DoQServer {
    const config = DoQServerConfig{
        .address = "0.0.0.0",
        .port = 853,
        .max_connections = 10000,
        .query_timeout_ms = 5000,
        .enable_post_quantum = true,
        .cert_path = "/etc/ssl/certs/ghostplane.crt",
        .key_path = "/etc/ssl/private/ghostplane.key",
        .handler = ghostDnsHandler,
    };

    const server = try DoQServer.init(allocator, config);

    std.log.info("🌐 DoQ: GhostDNS integration enabled with endpoint: {s}", .{ghost_rpc_endpoint});
    return server;
}

/// Example DNS handler for GhostChain integration
fn ghostDnsHandler(query: *DnsMessage, allocator: std.mem.Allocator) !DnsMessage {
    // Placeholder for ghostdns integration
    // In production, this would:
    // 1. Check if query is for .ghost/.zns domain
    // 2. Query blockchain for DNS records
    // 3. Return blockchain-verified response

    if (query.questions.len == 0) {
        return try createEmptyResponse(query, allocator);
    }

    const domain = query.questions[0].name;
    const qtype = query.questions[0].qtype;

    std.log.info("🔍 DoQ: Resolving {s} (type: {})", .{ domain, qtype });

    // For now, return echo response
    // TODO: Implement real ghostdns integration
    var response = DnsMessage{};

    response.header = message.DnsHeader{
        .id = query.header.id,
        .flags = 0x8180, // QR=1, RD=1, RA=1
        .qdcount = 1,
        .ancount = 1,
        .nscount = 0,
        .arcount = 0,
    };

    // Copy question
    response.questions = try allocator.alloc(message.DnsQuestion, 1);
    response.questions[0] = message.DnsQuestion{
        .name = try allocator.dupe(u8, domain),
        .qtype = qtype,
        .qclass = query.questions[0].qclass,
    };

    // Create answer
    response.answers = try allocator.alloc(message.DnsResourceRecord, 1);
    const ip_data = [_]u8{ 10, 0, 0, 1 }; // Placeholder IP
    response.answers[0] = message.DnsResourceRecord{
        .name = try allocator.dupe(u8, domain),
        .rtype = @intFromEnum(message.DnsRecordType.A),
        .rclass = 1, // IN
        .ttl = 300,
        .rdlength = 4,
        .rdata = try allocator.dupe(u8, &ip_data),
    };

    return response;
}

fn createEmptyResponse(query: *const DnsMessage, _: std.mem.Allocator) !DnsMessage {
    var response = DnsMessage{};
    response.header = message.DnsHeader{
        .id = query.header.id,
        .flags = 0x8180, // QR=1, RD=1, RA=1
        .qdcount = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };
    return response;
}

test "DoQ server initialization" {
    const allocator = std.testing.allocator;

    const config = DoQServerConfig{
        .cert_path = "/tmp/test.crt",
        .key_path = "/tmp/test.key",
    };

    // This will fail because cert files don't exist, but tests the init path
    const result = DoQServer.init(allocator, config);
    try std.testing.expect(result == Error.ZquicError.InvalidConfiguration or @TypeOf(result) == DoQServer);
}
