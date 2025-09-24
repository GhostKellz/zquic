//! Asynchronous Cryptographic Operations for ZQUIC
//!
//! Provides non-blocking cryptographic processing using zsync for high-performance
//! QUIC packet encryption/decryption without blocking the main event loop

const std = @import("std");
const zsync = @import("zsync");
const Error = @import("../utils/error.zig");
const PacketCrypto = @import("../core/crypto.zig").PacketCrypto;

/// Asynchronous cryptographic operation types
pub const AsyncCryptoOp = union(enum) {
    encrypt: EncryptRequest,
    decrypt: DecryptRequest,
    key_update: KeyUpdateRequest,
    derive_keys: DeriveKeysRequest,
};

/// Encryption request for async processing
pub const EncryptRequest = struct {
    packet_data: []const u8,
    packet_number: u64,
    key_phase: u8,
    result_callback: *const fn (result: EncryptResult) void,
};

/// Decryption request for async processing
pub const DecryptRequest = struct {
    encrypted_data: []const u8,
    packet_number: u64,
    key_phase: u8,
    result_callback: *const fn (result: DecryptResult) void,
};

/// Key update request for async processing
pub const KeyUpdateRequest = struct {
    current_generation: u32,
    result_callback: *const fn (result: KeyUpdateResult) void,
};

/// Key derivation request for async processing
pub const DeriveKeysRequest = struct {
    shared_secret: []const u8,
    salt: []const u8,
    result_callback: *const fn (result: DeriveKeysResult) void,
};

/// Encryption operation result
pub const EncryptResult = struct {
    success: bool,
    encrypted_data: ?[]u8,
    auth_tag: ?[16]u8,
    error_code: ?Error.ZquicError,
};

/// Decryption operation result
pub const DecryptResult = struct {
    success: bool,
    decrypted_data: ?[]u8,
    error_code: ?Error.ZquicError,
};

/// Key update operation result
pub const KeyUpdateResult = struct {
    success: bool,
    new_generation: u32,
    error_code: ?Error.ZquicError,
};

/// Key derivation operation result
pub const DeriveKeysResult = struct {
    success: bool,
    client_key: ?[32]u8,
    server_key: ?[32]u8,
    error_code: ?Error.ZquicError,
};

/// Asynchronous crypto processor using zsync
pub const AsyncCryptoProcessor = struct {
    packet_crypto: *PacketCrypto,
    operation_queue: zsync.Channel(AsyncCryptoOp),
    result_queue: zsync.Channel(AsyncCryptoResult),
    worker_pool: zsync.WorkerPool,
    allocator: std.mem.Allocator,
    is_running: bool,

    const Self = @This();
    const AsyncCryptoResult = union(enum) {
        encrypt_result: EncryptResult,
        decrypt_result: DecryptResult,
        key_update_result: KeyUpdateResult,
        derive_keys_result: DeriveKeysResult,
    };

    pub fn init(allocator: std.mem.Allocator, packet_crypto: *PacketCrypto, worker_count: u32) !Self {
        return Self{
            .packet_crypto = packet_crypto,
            .operation_queue = try zsync.Channel(AsyncCryptoOp).init(allocator, 1024),
            .result_queue = try zsync.Channel(AsyncCryptoResult).init(allocator, 1024),
            .worker_pool = try zsync.WorkerPool.init(allocator, worker_count),
            .allocator = allocator,
            .is_running = false,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.is_running) {
            self.stop();
        }
        self.operation_queue.deinit();
        self.result_queue.deinit();
        self.worker_pool.deinit();
    }

    /// Start the async crypto processor
    pub fn start(self: *Self) !void {
        if (self.is_running) {
            return Error.ZquicError.InvalidState;
        }

        self.is_running = true;

        // Start worker threads for crypto operations
        for (0..self.worker_pool.worker_count) |i| {
            _ = i;
            try self.worker_pool.spawn(cryptoWorker, .{self});
        }

        // Start result dispatcher
        try self.worker_pool.spawn(resultDispatcher, .{self});

        std.log.info("AsyncCryptoProcessor started with {} workers", .{self.worker_pool.worker_count});
    }

    /// Stop the async crypto processor
    pub fn stop(self: *Self) void {
        if (!self.is_running) return;

        self.is_running = false;
        self.operation_queue.close();
        self.result_queue.close();
        self.worker_pool.shutdown();

        std.log.info("AsyncCryptoProcessor stopped", .{});
    }

    /// Submit encryption request for async processing
    pub fn submitEncrypt(self: *Self, request: EncryptRequest) !void {
        if (!self.is_running) {
            return Error.ZquicError.InvalidState;
        }

        try self.operation_queue.send(.{ .encrypt = request });
    }

    /// Submit decryption request for async processing
    pub fn submitDecrypt(self: *Self, request: DecryptRequest) !void {
        if (!self.is_running) {
            return Error.ZquicError.InvalidState;
        }

        try self.operation_queue.send(.{ .decrypt = request });
    }

    /// Submit key update request for async processing
    pub fn submitKeyUpdate(self: *Self, request: KeyUpdateRequest) !void {
        if (!self.is_running) {
            return Error.ZquicError.InvalidState;
        }

        try self.operation_queue.send(.{ .key_update = request });
    }

    /// Submit key derivation request for async processing
    pub fn submitDeriveKeys(self: *Self, request: DeriveKeysRequest) !void {
        if (!self.is_running) {
            return Error.ZquicError.InvalidState;
        }

        try self.operation_queue.send(.{ .derive_keys = request });
    }

    /// Get current queue depth for monitoring
    pub fn getQueueDepth(self: *const Self) struct { operations: usize, results: usize } {
        return .{
            .operations = self.operation_queue.len(),
            .results = self.result_queue.len(),
        };
    }

    /// Worker function for processing crypto operations
    fn cryptoWorker(self: *Self) void {
        while (self.is_running) {
            if (self.operation_queue.receive()) |op| {
                const result = self.processCryptoOperation(op);
                self.result_queue.send(result) catch |err| {
                    std.log.err("Failed to send crypto result: {}", .{err});
                };
            } else |err| {
                if (err == zsync.ChannelError.Closed) break;
                std.log.err("Crypto worker error: {}", .{err});
            }
        }
    }

    /// Result dispatcher function
    fn resultDispatcher(self: *Self) void {
        while (self.is_running) {
            if (self.result_queue.receive()) |result| {
                self.dispatchResult(result);
            } else |err| {
                if (err == zsync.ChannelError.Closed) break;
                std.log.err("Result dispatcher error: {}", .{err});
            }
        }
    }

    /// Process a single crypto operation
    fn processCryptoOperation(self: *Self, op: AsyncCryptoOp) AsyncCryptoResult {
        switch (op) {
            .encrypt => |req| {
                const result = self.processEncryption(req);
                return .{ .encrypt_result = result };
            },
            .decrypt => |req| {
                const result = self.processDecryption(req);
                return .{ .decrypt_result = result };
            },
            .key_update => |req| {
                const result = self.processKeyUpdate(req);
                return .{ .key_update_result = result };
            },
            .derive_keys => |req| {
                const result = self.processKeyDerivation(req);
                return .{ .derive_keys_result = result };
            },
        }
    }

    /// Process encryption request
    fn processEncryption(self: *Self, req: EncryptRequest) EncryptResult {
        // Allocate buffer for encrypted data
        const encrypted_data = self.allocator.alloc(u8, req.packet_data.len + 16) catch {
            return EncryptResult{
                .success = false,
                .encrypted_data = null,
                .auth_tag = null,
                .error_code = Error.ZquicError.OutOfMemory,
            };
        };

        // Perform encryption using PacketCrypto
        const encrypt_result = self.packet_crypto.encryptPacket(
            req.packet_data,
            req.packet_number,
            req.key_phase,
            encrypted_data,
        );

        if (encrypt_result) |auth_tag| {
            return EncryptResult{
                .success = true,
                .encrypted_data = encrypted_data,
                .auth_tag = auth_tag,
                .error_code = null,
            };
        } else |err| {
            self.allocator.free(encrypted_data);
            return EncryptResult{
                .success = false,
                .encrypted_data = null,
                .auth_tag = null,
                .error_code = err,
            };
        }
    }

    /// Process decryption request
    fn processDecryption(self: *Self, req: DecryptRequest) DecryptResult {
        // Allocate buffer for decrypted data
        const decrypted_data = self.allocator.alloc(u8, req.encrypted_data.len) catch {
            return DecryptResult{
                .success = false,
                .decrypted_data = null,
                .error_code = Error.ZquicError.OutOfMemory,
            };
        };

        // Perform decryption using PacketCrypto
        const decrypt_result = self.packet_crypto.decryptPacket(
            req.encrypted_data,
            req.packet_number,
            req.key_phase,
            decrypted_data,
        );

        if (decrypt_result) {
            return DecryptResult{
                .success = true,
                .decrypted_data = decrypted_data,
                .error_code = null,
            };
        } else |err| {
            self.allocator.free(decrypted_data);
            return DecryptResult{
                .success = false,
                .decrypted_data = null,
                .error_code = err,
            };
        }
    }

    /// Process key update request
    fn processKeyUpdate(self: *Self, req: KeyUpdateRequest) KeyUpdateResult {
        const update_result = self.packet_crypto.updateKeys(req.current_generation);

        if (update_result) |new_generation| {
            return KeyUpdateResult{
                .success = true,
                .new_generation = new_generation,
                .error_code = null,
            };
        } else |err| {
            return KeyUpdateResult{
                .success = false,
                .new_generation = req.current_generation,
                .error_code = err,
            };
        }
    }

    /// Process key derivation request
    fn processKeyDerivation(self: *Self, req: DeriveKeysRequest) DeriveKeysResult {
        var client_key: [32]u8 = undefined;
        var server_key: [32]u8 = undefined;

        const derive_result = self.packet_crypto.deriveTrafficKeys(
            req.shared_secret,
            req.salt,
            &client_key,
            &server_key,
        );

        if (derive_result) {
            return DeriveKeysResult{
                .success = true,
                .client_key = client_key,
                .server_key = server_key,
                .error_code = null,
            };
        } else |err| {
            return DeriveKeysResult{
                .success = false,
                .client_key = null,
                .server_key = null,
                .error_code = err,
            };
        }
    }

    /// Dispatch result to callback
    fn dispatchResult(self: *Self, result: AsyncCryptoResult) void {
        _ = self;
        switch (result) {
            .encrypt_result => |res| {
                // Callback would be called here in real implementation
                std.log.debug("Encryption completed: success={}", .{res.success});
            },
            .decrypt_result => |res| {
                std.log.debug("Decryption completed: success={}", .{res.success});
            },
            .key_update_result => |res| {
                std.log.debug("Key update completed: success={}, generation={}", .{ res.success, res.new_generation });
            },
            .derive_keys_result => |res| {
                std.log.debug("Key derivation completed: success={}", .{res.success});
            },
        }
    }
};

/// Utility function for high-performance batch encryption
pub fn batchEncrypt(
    processor: *AsyncCryptoProcessor,
    packets: []const []const u8,
    packet_numbers: []const u64,
    key_phase: u8,
    completion_callback: *const fn (results: []EncryptResult) void,
) !void {
    if (packets.len != packet_numbers.len) {
        return Error.ZquicError.InvalidInput;
    }

    // Submit all encryption requests
    for (packets, packet_numbers) |packet_data, packet_number| {
        const request = EncryptRequest{
            .packet_data = packet_data,
            .packet_number = packet_number,
            .key_phase = key_phase,
            .result_callback = undefined, // Would be set in real implementation
        };

        try processor.submitEncrypt(request);
    }

    _ = completion_callback; // Would be used in real implementation
    std.log.info("Submitted {} packets for batch encryption", .{packets.len});
}

/// Performance monitoring for async crypto operations
pub const AsyncCryptoMetrics = struct {
    operations_queued: std.atomic.AtomicUsize,
    operations_completed: std.atomic.AtomicUsize,
    operations_failed: std.atomic.AtomicUsize,
    average_processing_time_ns: std.atomic.AtomicUsize,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .operations_queued = std.atomic.AtomicUsize.init(0),
            .operations_completed = std.atomic.AtomicUsize.init(0),
            .operations_failed = std.atomic.AtomicUsize.init(0),
            .average_processing_time_ns = std.atomic.AtomicUsize.init(0),
        };
    }

    pub fn recordOperation(self: *Self, success: bool, processing_time_ns: u64) void {
        if (success) {
            _ = self.operations_completed.fetchAdd(1, .SeqCst);
        } else {
            _ = self.operations_failed.fetchAdd(1, .SeqCst);
        }

        // Update average processing time (simplified)
        _ = self.average_processing_time_ns.store(processing_time_ns, .SeqCst);
    }

    pub fn getMetrics(self: *const Self) struct {
        queued: usize,
        completed: usize,
        failed: usize,
        avg_time_ns: usize,
    } {
        return .{
            .queued = self.operations_queued.load(.SeqCst),
            .completed = self.operations_completed.load(.SeqCst),
            .failed = self.operations_failed.load(.SeqCst),
            .avg_time_ns = self.average_processing_time_ns.load(.SeqCst),
        };
    }
};

/// Test async crypto functionality
pub fn testAsyncCrypto() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a mock PacketCrypto instance
    var packet_crypto = PacketCrypto.init(allocator) catch |err| {
        std.log.err("Failed to initialize PacketCrypto: {}", .{err});
        return;
    };
    defer packet_crypto.deinit();

    // Create async crypto processor
    var processor = try AsyncCryptoProcessor.init(allocator, &packet_crypto, 4);
    defer processor.deinit();

    // Start processing
    try processor.start();
    defer processor.stop();

    // Test data
    const test_data = "Hello, ZQUIC async crypto!";

    // Submit encryption request
    const encrypt_req = EncryptRequest{
        .packet_data = test_data,
        .packet_number = 12345,
        .key_phase = 0,
        .result_callback = undefined,
    };

    try processor.submitEncrypt(encrypt_req);

    // Wait a bit for processing
    std.time.sleep(100 * std.time.ns_per_ms);

    const queue_depth = processor.getQueueDepth();
    std.log.info("Async crypto test completed. Queue depth: operations={}, results={}", .{ queue_depth.operations, queue_depth.results });
}
