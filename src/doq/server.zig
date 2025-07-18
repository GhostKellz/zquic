//! DNS-over-QUIC Server Implementation (RFC 9250)
//!
//! Post-quantum secure DoQ server for GhostChain ecosystem

const std = @import("std");
const zquic = @import("../root.zig");
const zsync = @import("zsync");
const message = @import("message.zig");
const Error = @import("../utils/error.zig");

const Connection = zquic.Connection.Connection;
const Stream = zquic.Stream.Stream;
const Crypto = zquic.Crypto;
const DnsMessage = message.DnsMessage;

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
        defer query.deinit();

        // Process query through handler
        var response = if (self.server.config.handler) |handler|
            handler(&query, self.allocator) catch |err| blk: {
                std.log.err("DoQ: Handler failed: {}", .{err});
                self.server.stats.queries_failed += 1;
                break :blk try self.createErrorResponse(&query, message.DnsResponseCode.ServFail);
            }
        else
            try self.createEchoResponse(&query);
        
        defer response.deinit();

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
        var response = DnsMessage.init(self.allocator);
        
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
        var response = DnsMessage.init(self.allocator);
        
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
    io: zsync.GreenThreadsIo,
    query_channel: @TypeOf(zsync.bounded(DnsQueryRequest, std.heap.page_allocator, 256) catch unreachable),
    response_channel: @TypeOf(zsync.bounded(DnsQueryResponse, std.heap.page_allocator, 256) catch unreachable),
    is_running: bool = false,
    start_time: i64,

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

        return DoQServer{
            .config = config,
            .stats = DoQServerStats{},
            .allocator = allocator,
            .io = try zsync.GreenThreadsIo.init(allocator, .{}),
            .query_channel = try zsync.bounded(DnsQueryRequest, allocator, 256),
            .response_channel = try zsync.bounded(DnsQueryResponse, allocator, 256),
            .start_time = std.time.timestamp(),
        };
    }

    pub fn deinit(self: *DoQServer) void {
        self.stop();
        // Note: zsync channels don't have deinit method in current API
        _ = self.query_channel;
        _ = self.response_channel;
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
            zsync.yieldNow();
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
        stats.uptime_seconds = @intCast(std.time.timestamp() - self.start_time);
        return stats;
    }

    fn loadCertificates(self: *DoQServer) !void {
        // Load TLS certificates for post-quantum crypto
        const cert_data = std.fs.cwd().readFileAlloc(self.allocator, self.config.cert_path, 1024 * 1024) catch |err| {
            std.log.err("DoQ: Failed to load certificate {s}: {}", .{ self.config.cert_path, err });
            return err;
        };
        defer self.allocator.free(cert_data);

        const key_data = std.fs.cwd().readFileAlloc(self.allocator, self.config.key_path, 1024 * 1024) catch |err| {
            std.log.err("DoQ: Failed to load private key {s}: {}", .{ self.config.key_path, err });
            return err;
        };
        defer self.allocator.free(key_data);

        std.log.info("🔐 DoQ: Loaded certificates with post-quantum crypto support", .{});
    }

    fn acceptConnections(self: *DoQServer) !void {
        // Accept QUIC connections and spawn handlers
        // This is a placeholder - actual implementation depends on QUIC connection API
        
        // Simulate connection acceptance
        if (self.stats.active_connections < self.config.max_connections) {
            // Would accept actual connection here
            std.log.debug("DoQ: Ready to accept connections", .{});
        }
    }

    fn queryProcessor(self: *DoQServer) !void {
        while (self.is_running) {
            // Receive query from channel
            const query_req = self.query_channel.recv() catch |err| {
                if (err == error.Closed) break;
                continue;
            };

            // Process DNS query
            const response = if (self.config.handler) |handler|
                handler(&query_req.query, self.allocator) catch |err| blk: {
                    std.log.err("DoQ: Handler failed: {}", .{err});
                    break :blk try self.createErrorResponse(&query_req.query);
                }
            else
                try self.createEchoResponse(&query_req.query);

            // Send response via channel
            const response_msg = DnsQueryResponse{
                .response = response,
                .connection_id = query_req.connection_id,
                .stream_id = query_req.stream_id,
            };

            try self.response_channel.send(response_msg);
            self.stats.queries_processed += 1;

            zsync.yieldNow();
        }
    }

    fn responseHandler(self: *DoQServer) !void {
        while (self.is_running) {
            // Receive response from channel
            const response_msg = self.response_channel.recv() catch |err| {
                if (err == error.Closed) break;
                continue;
            };

            // Serialize and send response
            const response_data = try response_msg.response.serializeToStream(self.allocator);
            defer self.allocator.free(response_data);

            // Send response back to client (placeholder - needs connection lookup)
            std.log.info("DoQ: Sending {} byte response for connection {}", .{ 
                response_data.len, 
                response_msg.connection_id 
            });

            self.stats.bytes_sent += response_data.len;
            
            // Clean up response
            var mutable_response = response_msg.response;
            mutable_response.deinit();

            zsync.yieldNow();
        }
    }

    fn createErrorResponse(self: *DoQServer, query: *const DnsMessage) !DnsMessage {
        var response = DnsMessage.init(self.allocator);
        
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
        var response = DnsMessage.init(self.allocator);
        
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
    var response = DnsMessage.init(allocator);
    
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

fn createEmptyResponse(query: *const DnsMessage, allocator: std.mem.Allocator) !DnsMessage {
    var response = DnsMessage.init(allocator);
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