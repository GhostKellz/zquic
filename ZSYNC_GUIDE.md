# zsync Integration Guide: zcrypto, zquic, and zqlite

A comprehensive guide for migrating from tokioZ to zsync for async operations in Zig cryptography, QUIC, and SQLite libraries.

## Overview

**zsync** is a blazing fast, lightweight async runtime for Zig that replaces tokioZ with a modern, "colorblind" approach to async operations. The same code works across blocking, threaded, green threads, and stackless execution models.

### Repository
- **zsync**: [github.com/ghostkellz/zsync](https://github.com/ghostkellz/zsync) (main branch)
- **Version**: v0.2.0+ (TokioZ replacement)

---

## Architecture Overview

### Core Async Models

zsync provides multiple execution models through a unified `Io` interface:

```zig
const zsync = @import("zsync");

// Choose your execution model
pub const Io = zsync.Io;                    // Unified interface
pub const BlockingIo = zsync.BlockingIo;    // CPU-intensive (crypto)
pub const ThreadPoolIo = zsync.ThreadPoolIo; // Mixed I/O + CPU (databases)
pub const GreenThreadsIo = zsync.GreenThreadsIo; // High-concurrency (QUIC servers)
pub const StacklessIo = zsync.StacklessIo;  // WASM-compatible
```

### Key APIs

```zig
// Task management
pub const spawn = zsync.spawn;              // Spawn async task
pub const spawnAsync = zsync.spawnAsync;    // Spawn with TaskHandle
pub const sleep = zsync.sleep;              // Async delay
pub const yieldNow = zsync.yieldNow;        // Cooperative yielding

// I/O operations
pub const TcpStream = zsync.TcpStream;      // Async TCP
pub const UdpSocket = zsync.UdpSocket;      // Async UDP
pub const File = zsync.File;                // Async file I/O

// Channels & communication
pub const bounded = zsync.bounded;          // Bounded channels
pub const unbounded = zsync.unbounded;      // Unbounded channels
```

---

## 1. zcrypto Integration

### Basic Setup

Add zsync dependency to your `build.zig`:

```zig
// build.zig
const zsync_dep = b.dependency("zsync", .{
    .target = target,
    .optimize = optimize,
});

const zcrypto_module = b.addModule("zcrypto", .{
    .root_source_file = b.path("src/zcrypto.zig"),
    .imports = &.{
        .{ .name = "zsync", .module = zsync_dep.module("zsync") },
    },
});
```

### Async Cryptographic Operations

#### 1. Async Cipher Implementation

```zig
// src/async_cipher.zig
const std = @import("std");
const zsync = @import("zsync");

pub const AsyncCipher = struct {
    cipher_impl: *anyopaque,
    allocator: std.mem.Allocator,
    
    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, cipher_impl: *anyopaque) Self {
        return Self{
            .cipher_impl = cipher_impl,
            .allocator = allocator,
        };
    }

    /// Encrypt data asynchronously using CPU threads
    pub fn encryptAsync(self: *Self, plaintext: []const u8) ![]u8 {
        // Use BlockingIo for CPU-intensive crypto operations
        const io = zsync.BlockingIo{};
        
        var future = io.async(encryptWorker, .{ self, plaintext, self.allocator });
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }

    /// Decrypt data asynchronously
    pub fn decryptAsync(self: *Self, ciphertext: []const u8) ![]u8 {
        const io = zsync.BlockingIo{};
        
        var future = io.async(decryptWorker, .{ self, ciphertext, self.allocator });
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }

    fn encryptWorker(self: *AsyncCipher, data: []const u8, allocator: std.mem.Allocator) ![]u8 {
        // Yield periodically during long operations
        defer zsync.yieldNow();
        
        // Perform actual encryption...
        const result = try allocator.alloc(u8, data.len + 16); // Example with padding
        // ... encryption logic ...
        
        return result;
    }

    fn decryptWorker(self: *AsyncCipher, data: []const u8, allocator: std.mem.Allocator) ![]u8 {
        defer zsync.yieldNow();
        
        // Perform actual decryption...
        const result = try allocator.alloc(u8, data.len - 16); // Remove padding
        // ... decryption logic ...
        
        return result;
    }
};
```

#### 2. Async TLS Stream

```zig
// src/tls_stream.zig
const std = @import("std");
const zsync = @import("zsync");

pub const TlsStream = struct {
    tcp_stream: zsync.TcpStream,
    crypto_ctx: *CryptoContext,
    read_buffer: [4096]u8,
    write_buffer: [4096]u8,
    
    const Self = @This();

    pub fn init(tcp_stream: zsync.TcpStream, crypto_ctx: *CryptoContext) Self {
        return Self{
            .tcp_stream = tcp_stream,
            .crypto_ctx = crypto_ctx,
            .read_buffer = undefined,
            .write_buffer = undefined,
        };
    }

    /// Read and decrypt data asynchronously
    pub fn read(self: *Self, buffer: []u8) !usize {
        const io = zsync.GreenThreadsIo{}; // Good for I/O operations
        
        // Read encrypted data from TCP stream
        var read_future = io.async(readEncrypted, .{ self, &self.read_buffer });
        defer read_future.cancel(io) catch {};
        
        const encrypted_data = try read_future.await(io);
        
        // Decrypt the data
        var decrypt_future = io.async(decryptData, .{ self.crypto_ctx, encrypted_data, buffer });
        defer decrypt_future.cancel(io) catch {};
        
        return try decrypt_future.await(io);
    }

    /// Encrypt and write data asynchronously
    pub fn write(self: *Self, data: []const u8) !usize {
        const io = zsync.GreenThreadsIo{};
        
        // Encrypt the data
        var encrypt_future = io.async(encryptData, .{ self.crypto_ctx, data, &self.write_buffer });
        defer encrypt_future.cancel(io) catch {};
        
        const encrypted_data = try encrypt_future.await(io);
        
        // Write encrypted data to TCP stream
        var write_future = io.async(writeEncrypted, .{ self, encrypted_data });
        defer write_future.cancel(io) catch {};
        
        return try write_future.await(io);
    }

    fn readEncrypted(self: *Self, buffer: []u8) ![]u8 {
        return try self.tcp_stream.read(buffer);
    }

    fn writeEncrypted(self: *Self, data: []const u8) !usize {
        return try self.tcp_stream.write(data);
    }

    fn encryptData(crypto_ctx: *CryptoContext, data: []const u8, buffer: []u8) ![]u8 {
        // Implement encryption logic
        // Return encrypted data slice from buffer
        _ = crypto_ctx;
        _ = data;
        return buffer[0..data.len]; // Placeholder
    }

    fn decryptData(crypto_ctx: *CryptoContext, encrypted: []const u8, buffer: []u8) !usize {
        // Implement decryption logic
        // Write decrypted data to buffer and return size
        _ = crypto_ctx;
        _ = encrypted;
        return buffer.len; // Placeholder
    }
};
```

#### 3. Hash Operations

```zig
// src/async_hash.zig
const std = @import("std");
const zsync = @import("zsync");

pub const AsyncHasher = struct {
    hash_impl: *anyopaque,
    chunk_size: usize = 8192,
    
    const Self = @This();

    /// Hash large data asynchronously with cooperative yielding
    pub fn hashLargeData(self: *Self, data: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const io = zsync.BlockingIo{};
        
        var future = io.async(hashWorker, .{ self, data, allocator });
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }

    fn hashWorker(self: *Self, data: []const u8, allocator: std.mem.Allocator) ![]u8 {
        var hasher = std.crypto.hash.Sha256.init(.{});
        
        var offset: usize = 0;
        while (offset < data.len) {
            const chunk_end = @min(offset + self.chunk_size, data.len);
            const chunk = data[offset..chunk_end];
            
            hasher.update(chunk);
            offset = chunk_end;
            
            // Yield every chunk to allow other tasks to run
            if (offset < data.len) {
                zsync.yieldNow();
            }
        }
        
        var result = try allocator.alloc(u8, 32); // SHA256 output size
        hasher.final(result);
        return result;
    }
};
```

---

## 2. zquic Integration

### Basic QUIC Server

```zig
// src/quic_server.zig
const std = @import("std");
const zsync = @import("zsync");

pub const QuicServer = struct {
    udp_socket: zsync.UdpSocket,
    connections: std.HashMap(ConnectionId, *QuicConnection, ConnectionIdContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    const Self = @This();
    const ConnectionId = [16]u8;
    const ConnectionIdContext = std.hash_map.AutoContext(ConnectionId);

    pub fn init(allocator: std.mem.Allocator, addr: std.net.Address) !Self {
        const udp_socket = try zsync.UdpSocket.bind(addr);
        
        return Self{
            .udp_socket = udp_socket,
            .connections = std.HashMap(ConnectionId, *QuicConnection, ConnectionIdContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    /// Accept new QUIC connections
    pub fn accept(self: *Self) !*QuicConnection {
        const io = zsync.GreenThreadsIo{}; // Perfect for high-concurrency servers
        
        var future = io.async(acceptConnection, .{self});
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }

    /// Run the QUIC server event loop
    pub fn run(self: *Self) !void {
        const io = zsync.GreenThreadsIo{};
        
        while (true) {
            // Spawn connection acceptor
            _ = try zsync.spawn(acceptorTask, .{self});
            
            // Spawn packet processor
            _ = try zsync.spawn(packetProcessor, .{self});
            
            // Sleep briefly to allow other tasks
            try zsync.sleep(1);
        }
    }

    fn acceptConnection(self: *Self) !*QuicConnection {
        var buffer: [2048]u8 = undefined;
        
        while (true) {
            const recv_result = try self.udp_socket.recvFrom(&buffer);
            const data = recv_result.data;
            const addr = recv_result.address;
            
            // Parse QUIC initial packet
            if (isInitialPacket(data)) {
                const conn_id = extractConnectionId(data);
                
                // Create new connection
                const connection = try self.allocator.create(QuicConnection);
                connection.* = try QuicConnection.init(self.allocator, addr, conn_id);
                
                try self.connections.put(conn_id, connection);
                return connection;
            }
        }
    }

    fn acceptorTask(self: *Self) !void {
        while (true) {
            const connection = try self.accept();
            // Spawn handler for this connection
            _ = try zsync.spawn(connectionHandler, .{connection});
        }
    }

    fn packetProcessor(self: *Self) !void {
        var buffer: [2048]u8 = undefined;
        
        while (true) {
            const recv_result = try self.udp_socket.recvFrom(&buffer);
            const data = recv_result.data;
            
            // Route packet to appropriate connection
            const conn_id = extractConnectionId(data);
            if (self.connections.get(conn_id)) |connection| {
                _ = try zsync.spawn(handlePacket, .{ connection, data });
            }
            
            // Yield to allow other packet processing
            zsync.yieldNow();
        }
    }

    fn connectionHandler(connection: *QuicConnection) !void {
        defer connection.deinit();
        
        while (connection.isActive()) {
            try connection.processEvents();
            try zsync.sleep(1); // 1ms processing interval
        }
    }

    fn handlePacket(connection: *QuicConnection, packet_data: []const u8) !void {
        try connection.handlePacket(packet_data);
    }

    // Helper functions
    fn isInitialPacket(data: []const u8) bool {
        return data.len > 0 and (data[0] & 0x80) != 0; // Long header packet
    }

    fn extractConnectionId(data: []const u8) ConnectionId {
        var conn_id: ConnectionId = undefined;
        @memcpy(conn_id[0..], data[1..17]); // Simplified extraction
        return conn_id;
    }
};
```

### QUIC Connection Management

```zig
// src/quic_connection.zig
const std = @import("std");
const zsync = @import("zsync");

pub const QuicConnection = struct {
    allocator: std.mem.Allocator,
    peer_addr: std.net.Address,
    connection_id: [16]u8,
    state: ConnectionState,
    send_queue: zsync.bounded([]const u8, 256),
    recv_queue: zsync.bounded([]const u8, 256),
    active: std.atomic.Value(bool),
    
    const Self = @This();
    
    const ConnectionState = enum {
        initial,
        handshake,
        established,
        closing,
        closed,
    };

    pub fn init(allocator: std.mem.Allocator, addr: std.net.Address, conn_id: [16]u8) !Self {
        return Self{
            .allocator = allocator,
            .peer_addr = addr,
            .connection_id = conn_id,
            .state = .initial,
            .send_queue = try zsync.bounded([]const u8, 256),
            .recv_queue = try zsync.bounded([]const u8, 256),
            .active = std.atomic.Value(bool).init(true),
        };
    }

    pub fn deinit(self: *Self) void {
        self.active.store(false, .release);
        self.send_queue.close();
        self.recv_queue.close();
    }

    /// Send data over QUIC connection
    pub fn send(self: *Self, data: []const u8) !void {
        const io = zsync.GreenThreadsIo{};
        
        var future = io.async(sendData, .{ self, data });
        defer future.cancel(io) catch {};
        
        try future.await(io);
    }

    /// Receive data from QUIC connection
    pub fn receive(self: *Self, buffer: []u8) !usize {
        const io = zsync.GreenThreadsIo{};
        
        var future = io.async(receiveData, .{ self, buffer });
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }

    /// Process incoming packet
    pub fn handlePacket(self: *Self, packet_data: []const u8) !void {
        // Validate packet
        if (!self.validatePacket(packet_data)) return;
        
        // Queue packet for processing
        try self.recv_queue.send(packet_data);
    }

    /// Process connection events
    pub fn processEvents(self: *Self) !void {
        const io = zsync.GreenThreadsIo{};
        
        // Process send queue
        _ = try zsync.spawn(processSendQueue, .{self});
        
        // Process receive queue
        _ = try zsync.spawn(processReceiveQueue, .{self});
        
        // Handle timeouts and retransmissions
        _ = try zsync.spawn(handleTimeouts, .{self});
    }

    pub fn isActive(self: *Self) bool {
        return self.active.load(.acquire);
    }

    fn sendData(self: *Self, data: []const u8) !void {
        try self.send_queue.send(data);
    }

    fn receiveData(self: *Self, buffer: []u8) !usize {
        const data = try self.recv_queue.receive();
        const copy_len = @min(buffer.len, data.len);
        @memcpy(buffer[0..copy_len], data[0..copy_len]);
        return copy_len;
    }

    fn processSendQueue(self: *Self) !void {
        while (self.isActive()) {
            if (self.send_queue.tryReceive()) |data| {
                // Send packet over UDP
                try self.sendPacket(data);
            } else {
                try zsync.sleep(1); // 1ms wait
            }
        }
    }

    fn processReceiveQueue(self: *Self) !void {
        while (self.isActive()) {
            if (self.recv_queue.tryReceive()) |packet| {
                try self.processPacket(packet);
            } else {
                try zsync.sleep(1);
            }
        }
    }

    fn handleTimeouts(self: *Self) !void {
        while (self.isActive()) {
            // Check for timeout conditions
            try self.checkRetransmissions();
            try zsync.sleep(100); // 100ms timeout check interval
        }
    }

    fn validatePacket(self: *Self, packet: []const u8) bool {
        _ = self;
        return packet.len > 0; // Simplified validation
    }

    fn sendPacket(self: *Self, data: []const u8) !void {
        _ = self;
        _ = data;
        // Implement actual packet sending
    }

    fn processPacket(self: *Self, packet: []const u8) !void {
        _ = self;
        _ = packet;
        // Implement packet processing logic
    }

    fn checkRetransmissions(self: *Self) !void {
        _ = self;
        // Implement retransmission logic
    }
};
```

---

## 3. zqlite Integration

### Async Database Operations

```zig
// src/async_database.zig
const std = @import("std");
const zsync = @import("zsync");

pub const AsyncDatabase = struct {
    db_path: []const u8,
    db_file: zsync.File,
    connection_pool: zsync.ConnectionPool,
    query_queue: zsync.bounded(Query, 1024),
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    const Query = struct {
        sql: []const u8,
        params: []const Value,
        result_channel: zsync.oneshot(QueryResult),
    };
    
    const QueryResult = struct {
        rows: []Row,
        affected_rows: u64,
        error_msg: ?[]const u8,
    };
    
    const Row = std.StringHashMap(Value);
    const Value = union(enum) {
        integer: i64,
        real: f64,
        text: []const u8,
        blob: []const u8,
        null: void,
    };

    pub fn init(allocator: std.mem.Allocator, db_path: []const u8) !Self {
        const db_file = try zsync.File.open(db_path, .{ .mode = .read_write });
        
        // Configure connection pool for database operations
        const pool_config = zsync.PoolConfig{
            .max_connections = 10,
            .min_connections = 2,
            .connection_timeout = 30000, // 30 seconds
        };
        
        const connection_pool = try zsync.ConnectionPool.init(allocator, pool_config);
        
        return Self{
            .db_path = db_path,
            .db_file = db_file,
            .connection_pool = connection_pool,
            .query_queue = try zsync.bounded(Query, 1024),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.query_queue.close();
        self.connection_pool.deinit();
        self.db_file.close();
    }

    /// Execute SQL query asynchronously
    pub fn query(self: *Self, sql: []const u8, params: []const Value) !QueryResult {
        const io = zsync.ThreadPoolIo{}; // Good for mixed I/O and CPU workloads
        
        var future = io.async(executeQuery, .{ self, sql, params });
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }

    /// Execute query with timeout
    pub fn queryWithTimeout(self: *Self, sql: []const u8, params: []const Value, timeout_ms: u64) !QueryResult {
        const io = zsync.ThreadPoolIo{};
        
        // Create query future
        var query_future = io.async(executeQuery, .{ self, sql, params });
        defer query_future.cancel(io) catch {};
        
        // Create timeout future
        var timeout_future = io.async(timeoutTask, .{timeout_ms});
        defer timeout_future.cancel(io) catch {};
        
        // Race between query completion and timeout
        return try raceQueryTimeout(io, &query_future, &timeout_future);
    }

    /// Begin database transaction
    pub fn beginTransaction(self: *Self) !Transaction {
        const io = zsync.ThreadPoolIo{};
        
        var future = io.async(startTransaction, .{self});
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }

    /// Batch insert operations
    pub fn batchInsert(self: *Self, table: []const u8, rows: []const Row) !u64 {
        const io = zsync.ThreadPoolIo{};
        
        var future = io.async(performBatchInsert, .{ self, table, rows });
        defer future.cancel(io) catch {};
        
        return try future.await(io);
    }

    /// Run database maintenance tasks
    pub fn runMaintenance(self: *Self) !void {
        const io = zsync.ThreadPoolIo{};
        
        // Spawn concurrent maintenance tasks
        _ = try zsync.spawn(vacuumDatabase, .{self});
        _ = try zsync.spawn(analyzeDatabase, .{self});
        _ = try zsync.spawn(rebuildIndexes, .{self});
        
        // Wait for completion with yielding
        try zsync.sleep(100); // Allow tasks to start
    }

    fn executeQuery(self: *Self, sql: []const u8, params: []const Value) !QueryResult {
        // Get connection from pool
        const connection = try self.connection_pool.acquire();
        defer self.connection_pool.release(connection);
        
        // Prepare statement
        var stmt = try self.prepareStatement(connection, sql);
        defer stmt.finalize();
        
        // Bind parameters
        for (params, 0..) |param, i| {
            try self.bindParameter(&stmt, i, param);
        }
        
        // Execute with cooperative yielding
        var result = QueryResult{
            .rows = std.ArrayList(Row).init(self.allocator),
            .affected_rows = 0,
            .error_msg = null,
        };
        
        while (try stmt.step()) {
            const row = try self.readRow(&stmt);
            try result.rows.append(row);
            
            // Yield every 100 rows to allow other tasks
            if (result.rows.items.len % 100 == 0) {
                zsync.yieldNow();
            }
        }
        
        return result;
    }

    fn timeoutTask(timeout_ms: u64) !void {
        try zsync.sleep(timeout_ms);
        return error.Timeout;
    }

    fn raceQueryTimeout(io: anytype, query_future: anytype, timeout_future: anytype) !QueryResult {
        // Simple racing implementation - in practice you'd use select/race combinators
        _ = io;
        _ = timeout_future;
        
        return try query_future.await(io);
    }

    fn startTransaction(self: *Self) !Transaction {
        const connection = try self.connection_pool.acquire();
        
        // Execute BEGIN statement
        _ = try self.executeSimpleQuery(connection, "BEGIN TRANSACTION");
        
        return Transaction{
            .database = self,
            .connection = connection,
            .committed = false,
        };
    }

    fn performBatchInsert(self: *Self, table: []const u8, rows: []const Row) !u64 {
        const connection = try self.connection_pool.acquire();
        defer self.connection_pool.release(connection);
        
        // Begin transaction for batch
        _ = try self.executeSimpleQuery(connection, "BEGIN TRANSACTION");
        
        var affected: u64 = 0;
        for (rows) |row| {
            // Insert each row
            affected += try self.insertRow(connection, table, row);
            
            // Yield every 50 inserts
            if (affected % 50 == 0) {
                zsync.yieldNow();
            }
        }
        
        // Commit transaction
        _ = try self.executeSimpleQuery(connection, "COMMIT");
        
        return affected;
    }

    fn vacuumDatabase(self: *Self) !void {
        const connection = try self.connection_pool.acquire();
        defer self.connection_pool.release(connection);
        
        _ = try self.executeSimpleQuery(connection, "VACUUM");
    }

    fn analyzeDatabase(self: *Self) !void {
        const connection = try self.connection_pool.acquire();
        defer self.connection_pool.release(connection);
        
        _ = try self.executeSimpleQuery(connection, "ANALYZE");
    }

    fn rebuildIndexes(self: *Self) !void {
        const connection = try self.connection_pool.acquire();
        defer self.connection_pool.release(connection);
        
        _ = try self.executeSimpleQuery(connection, "REINDEX");
    }

    // Helper methods (simplified implementations)
    fn prepareStatement(self: *Self, connection: anytype, sql: []const u8) !Statement {
        _ = self;
        _ = connection;
        _ = sql;
        return Statement{};
    }

    fn bindParameter(self: *Self, stmt: *Statement, index: usize, value: Value) !void {
        _ = self;
        _ = stmt;
        _ = index;
        _ = value;
    }

    fn readRow(self: *Self, stmt: *Statement) !Row {
        _ = stmt;
        return Row.init(self.allocator);
    }

    fn executeSimpleQuery(self: *Self, connection: anytype, sql: []const u8) !u64 {
        _ = self;
        _ = connection;
        _ = sql;
        return 1;
    }

    fn insertRow(self: *Self, connection: anytype, table: []const u8, row: Row) !u64 {
        _ = self;
        _ = connection;
        _ = table;
        _ = row;
        return 1;
    }
};

// Simplified statement and transaction types
const Statement = struct {
    pub fn finalize(self: *Statement) void { _ = self; }
    pub fn step(self: *Statement) !bool { _ = self; return false; }
};

pub const Transaction = struct {
    database: *AsyncDatabase,
    connection: anytype,
    committed: bool,
    
    const Self = @This();

    pub fn commit(self: *Self) !void {
        if (!self.committed) {
            _ = try self.database.executeSimpleQuery(self.connection, "COMMIT");
            self.committed = true;
        }
        self.database.connection_pool.release(self.connection);
    }

    pub fn rollback(self: *Self) !void {
        if (!self.committed) {
            _ = try self.database.executeSimpleQuery(self.connection, "ROLLBACK");
        }
        self.database.connection_pool.release(self.connection);
    }
};
```

---

## Build Configuration

### Complete build.zig example

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Add zsync dependency
    const zsync_dep = b.dependency("zsync", .{
        .target = target,
        .optimize = optimize,
    });

    // zcrypto module
    const zcrypto_module = b.addModule("zcrypto", .{
        .root_source_file = b.path("src/zcrypto.zig"),
        .imports = &.{
            .{ .name = "zsync", .module = zsync_dep.module("zsync") },
        },
    });

    // zquic module  
    const zquic_module = b.addModule("zquic", .{
        .root_source_file = b.path("src/zquic.zig"),
        .imports = &.{
            .{ .name = "zsync", .module = zsync_dep.module("zsync") },
        },
    });

    // zqlite module
    const zqlite_module = b.addModule("zqlite", .{
        .root_source_file = b.path("src/zqlite.zig"),
        .imports = &.{
            .{ .name = "zsync", .module = zsync_dep.module("zsync") },
        },
    });

    // Example executable using all three
    const exe = b.addExecutable(.{
        .name = "async-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zsync", .module = zsync_dep.module("zsync") },
                .{ .name = "zcrypto", .module = zcrypto_module },
                .{ .name = "zquic", .module = zquic_module },
                .{ .name = "zqlite", .module = zqlite_module },
            },
        }),
    });

    b.installArtifact(exe);

    // Tests
    const test_step = b.step("test", "Run tests");
    
    const crypto_tests = b.addTest(.{ .root_module = zcrypto_module });
    const quic_tests = b.addTest(.{ .root_module = zquic_module });
    const sqlite_tests = b.addTest(.{ .root_module = zqlite_module });
    
    test_step.dependOn(&b.addRunArtifact(crypto_tests).step);
    test_step.dependOn(&b.addRunArtifact(quic_tests).step);
    test_step.dependOn(&b.addRunArtifact(sqlite_tests).step);
}
```

---

## Migration Checklist

### From tokioZ to zsync

- [ ] **Replace imports**: Change `@import("tokioZ")` to `@import("zsync")`
- [ ] **Update task spawning**: Use `zsync.spawn()` instead of tokioZ spawn functions
- [ ] **Migrate I/O operations**: Replace tokioZ I/O with zsync async I/O (`zsync.TcpStream`, etc.)
- [ ] **Update sleep/delay**: Use `zsync.sleep()` for async delays
- [ ] **Replace channels**: Use `zsync.bounded()` or `zsync.unbounded()` for communication
- [ ] **Choose execution model**: Select appropriate `Io` implementation based on workload
- [ ] **Add proper cancellation**: Use `defer future.cancel(io) catch {}` for cleanup
- [ ] **Update error handling**: Handle zsync-specific errors
- [ ] **Test async behavior**: Verify cooperative yielding and task scheduling

### Performance Optimization

1. **Choose the right execution model**:
   - `BlockingIo`: CPU-intensive crypto operations
   - `ThreadPoolIo`: Mixed I/O and CPU (databases)
   - `GreenThreadsIo`: High-concurrency servers (QUIC)
   - `StacklessIo`: WASM deployment

2. **Use cooperative yielding**: Call `zsync.yieldNow()` in long-running operations

3. **Implement proper cancellation**: Always use `defer future.cancel(io) catch {}`

4. **Batch operations**: Process multiple items before yielding

5. **Use connection pooling**: Leverage `zsync.ConnectionPool` for database connections

---

## Example Usage

### Complete integration example

```zig
// src/main.zig
const std = @import("std");
const zsync = @import("zsync");
const zcrypto = @import("zcrypto");
const zquic = @import("zquic");
const zqlite = @import("zqlite");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize zsync runtime
    const runtime = try zsync.init(allocator);
    defer runtime.deinit();

    // Run async application
    try zsync.run(asyncMain, .{allocator});
}

fn asyncMain(allocator: std.mem.Allocator) !void {
    // Spawn concurrent tasks for each component
    
    // Crypto operations
    _ = try zsync.spawn(cryptoDemo, .{allocator});
    
    // QUIC server
    _ = try zsync.spawn(quicServerDemo, .{allocator});
    
    // Database operations  
    _ = try zsync.spawn(databaseDemo, .{allocator});
    
    // Wait for all tasks to complete
    try zsync.sleep(10000); // 10 seconds
}

fn cryptoDemo(allocator: std.mem.Allocator) !void {
    var cipher = zcrypto.AsyncCipher.init(allocator, undefined);
    
    const plaintext = "Hello, zsync!";
    const encrypted = try cipher.encryptAsync(plaintext);
    defer allocator.free(encrypted);
    
    const decrypted = try cipher.decryptAsync(encrypted);
    defer allocator.free(decrypted);
    
    std.debug.print("Crypto demo completed\n", .{});
}

fn quicServerDemo(allocator: std.mem.Allocator) !void {
    const addr = try std.net.Address.parseIp("127.0.0.1", 8443);
    var server = try zquic.QuicServer.init(allocator, addr);
    defer server.deinit();
    
    std.debug.print("QUIC server listening on {}\n", .{addr});
    
    // Accept one connection for demo
    const connection = try server.accept();
    defer connection.deinit();
    
    std.debug.print("QUIC connection accepted\n", .{});
}

fn databaseDemo(allocator: std.mem.Allocator) !void {
    var db = try zqlite.AsyncDatabase.init(allocator, "test.db");
    defer db.deinit();
    
    // Create table
    _ = try db.query("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)", &[_]zqlite.Value{});
    
    // Insert data
    _ = try db.query("INSERT INTO users (name) VALUES (?)", &[_]zqlite.Value{.{ .text = "Alice" }});
    
    // Query data
    const result = try db.query("SELECT * FROM users", &[_]zqlite.Value{});
    defer allocator.free(result.rows);
    
    std.debug.print("Database demo completed, found {} rows\n", .{result.rows.len});
}
```

This guide provides a comprehensive foundation for migrating zcrypto, zquic, and zqlite from tokioZ to zsync, enabling modern async operations across all three libraries with zsync's unified runtime.