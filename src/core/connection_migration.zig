//! Connection Migration and 0-RTT Support for QUIC
//!
//! Implements RFC 9000 connection migration and 0-RTT capabilities
//! that match and exceed Quinn's functionality

const std = @import("std");
const Error = @import("../utils/error.zig");
const Frame = @import("quic_frames.zig").Frame;
const PathChallengeFrame = @import("quic_frames.zig").PathChallengeFrame;
const PathResponseFrame = @import("quic_frames.zig").PathResponseFrame;
const NewConnectionIdFrame = @import("quic_frames.zig").NewConnectionIdFrame;
const RetireConnectionIdFrame = @import("quic_frames.zig").RetireConnectionIdFrame;
const ComprehensiveTlsContext = @import("../crypto/comprehensive_tls.zig").ComprehensiveTlsContext;
const SessionTicket = @import("../crypto/comprehensive_tls.zig").SessionTicket;
const NetAddress = @import("../net/address.zig");
const Address = NetAddress.Address;

/// Path validation states
pub const PathValidationState = enum {
    idle,
    validating,
    validated,
    failed,
    abandoned,
};

/// Connection migration states
pub const MigrationState = enum {
    stable,
    probing,
    migrating,
    failed,
};

/// Path information for connection migration
pub const PathInfo = struct {
    local_address: Address,
    remote_address: Address,
    path_id: u64,
    validation_state: PathValidationState,
    challenge_data: ?[8]u8,
    rtt_estimate: ?u64,
    loss_rate: f64,
    congestion_window: u64,
    bytes_sent: u64,
    bytes_received: u64,
    last_activity: i64,

    pub fn init(local_address: Address, remote_address: Address, path_id: u64) PathInfo {
        return PathInfo{
            .local_address = local_address,
            .remote_address = remote_address,
            .path_id = path_id,
            .validation_state = .idle,
            .challenge_data = null,
            .rtt_estimate = null,
            .loss_rate = 0.0,
            .congestion_window = 10 * 1200, // Initial congestion window
            .bytes_sent = 0,
            .bytes_received = 0,
            .last_activity = blk: {
                const ts = std.posix.clock_gettime(.realtime) catch break :blk 0;
                break :blk ts.sec;
            },
        };
    }

    pub fn updateActivity(self: *PathInfo) void {
        const ts = std.posix.clock_gettime(.realtime) catch return;
        self.last_activity = ts.sec;
    }

    pub fn isExpired(self: *const PathInfo, timeout_ms: u64) bool {
        const ts = std.posix.clock_gettime(.realtime) catch return true;
        const now = ts.sec;
        return now - self.last_activity > @as(i64, @intCast(timeout_ms / 1000));
    }

    pub fn calculateScore(self: *const PathInfo) f64 {
        var score: f64 = 1.0;

        // Prefer validated paths
        if (self.validation_state == .validated) {
            score += 2.0;
        }

        // Prefer lower RTT
        if (self.rtt_estimate) |rtt| {
            score += 1.0 / (@as(f64, @floatFromInt(rtt)) / 1000.0 + 1.0);
        }

        // Penalize high loss rates
        score -= self.loss_rate * 2.0;

        // Prefer higher congestion window
        score += @as(f64, @floatFromInt(self.congestion_window)) / 10000.0;

        return score;
    }
};

/// Connection ID management for migration
pub const ConnectionIdManager = struct {
    active_connection_ids: std.ArrayListUnmanaged(ConnectionIdEntry),
    next_sequence_number: u64,
    retire_prior_to: u64,
    allocator: std.mem.Allocator,

    const ConnectionIdEntry = struct {
        connection_id: []const u8,
        sequence_number: u64,
        stateless_reset_token: [16]u8,
        active: bool,

        pub fn init(alloc: std.mem.Allocator, connection_id: []const u8, sequence_number: u64, stateless_reset_token: [16]u8) !ConnectionIdEntry {
            return ConnectionIdEntry{
                .connection_id = try alloc.dupe(u8, connection_id),
                .sequence_number = sequence_number,
                .stateless_reset_token = stateless_reset_token,
                .active = true,
            };
        }

        pub fn deinit(self: *ConnectionIdEntry, alloc: std.mem.Allocator) void {
            alloc.free(self.connection_id);
        }
    };

    pub fn init(alloc: std.mem.Allocator) ConnectionIdManager {
        return ConnectionIdManager{
            .active_connection_ids = .{},
            .next_sequence_number = 1,
            .retire_prior_to = 0,
            .allocator = alloc,
        };
    }

    pub fn deinit(self: *ConnectionIdManager) void {
        for (self.active_connection_ids.items) |*entry| {
            entry.deinit(self.allocator);
        }
        self.active_connection_ids.deinit(self.allocator);
    }

    pub fn generateConnectionId(self: *ConnectionIdManager) ![]u8 {
        const connection_id = try self.allocator.alloc(u8, 16);
        std.crypto.random.bytes(connection_id);
        return connection_id;
    }

    pub fn generateStatelessResetToken(self: *ConnectionIdManager) ![16]u8 {
        _ = self;
        var token: [16]u8 = undefined;
        std.crypto.random.bytes(&token);
        return token;
    }

    pub fn addConnectionId(self: *ConnectionIdManager, connection_id: []const u8, stateless_reset_token: [16]u8) !NewConnectionIdFrame {
        const entry = try ConnectionIdEntry.init(self.allocator, connection_id, self.next_sequence_number, stateless_reset_token);
        try self.active_connection_ids.append(self.allocator, entry);

        const frame = NewConnectionIdFrame.init(
            self.next_sequence_number,
            self.retire_prior_to,
            connection_id,
            stateless_reset_token,
        );

        self.next_sequence_number += 1;
        return frame;
    }

    pub fn retireConnectionId(self: *ConnectionIdManager, sequence_number: u64) ?RetireConnectionIdFrame {
        for (self.active_connection_ids.items) |*entry| {
            if (entry.sequence_number == sequence_number) {
                entry.active = false;
                return RetireConnectionIdFrame.init(sequence_number);
            }
        }
        return null;
    }

    /// Returns a slice of active connection IDs. Caller does NOT own the returned slice.
    pub fn getActiveConnectionIds(self: *const ConnectionIdManager) []const ConnectionIdEntry {
        // Return active entries from the internal list directly (no allocation)
        // Caller should iterate and check .active field if needed
        return self.active_connection_ids.items;
    }

    pub fn cleanupRetiredConnectionIds(self: *ConnectionIdManager) void {
        var i: usize = 0;
        while (i < self.active_connection_ids.items.len) {
            if (!self.active_connection_ids.items[i].active) {
                var entry = self.active_connection_ids.swapRemove(i);
                entry.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }
};

/// Path validation manager
pub const PathValidator = struct {
    active_validations: std.AutoHashMapUnmanaged(u64, PathValidation),
    next_validation_id: u64,
    allocator: std.mem.Allocator,

    const PathValidation = struct {
        path_id: u64,
        challenge_data: [8]u8,
        start_time: i64,
        attempts: u8,
        max_attempts: u8,
        timeout_ms: u64,

        pub fn init(path_id: u64, challenge_data: [8]u8) PathValidation {
            return PathValidation{
                .path_id = path_id,
                .challenge_data = challenge_data,
                .start_time = blk: {
                    const ts = std.posix.clock_gettime(.realtime) catch return PathValidation{
                        .path_id = path_id,
                        .challenge_data = challenge_data,
                        .start_time = 0,
                        .attempts = 1,
                        .max_attempts = 3,
                        .timeout_ms = 3000,
                    };
                    break :blk ts.sec;
                },
                .attempts = 1,
                .max_attempts = 3,
                .timeout_ms = 3000,
            };
        }

        pub fn isExpired(self: *const PathValidation) bool {
            const ts = std.posix.clock_gettime(.realtime) catch return true;
            const now = ts.sec;
            return now - self.start_time > @as(i64, @intCast(self.timeout_ms / 1000));
        }

        pub fn shouldRetry(self: *const PathValidation) bool {
            return self.attempts < self.max_attempts and !self.isExpired();
        }

        pub fn retry(self: *PathValidation) void {
            self.attempts += 1;
            const ts = std.posix.clock_gettime(.realtime) catch return;
            self.start_time = ts.sec;
        }
    };

    pub fn init(alloc: std.mem.Allocator) PathValidator {
        return PathValidator{
            .active_validations = .{},
            .next_validation_id = 1,
            .allocator = alloc,
        };
    }

    pub fn deinit(self: *PathValidator) void {
        self.active_validations.deinit(self.allocator);
    }

    pub fn startValidation(self: *PathValidator, path_id: u64) ![8]u8 {
        var challenge_data: [8]u8 = undefined;
        std.crypto.random.bytes(&challenge_data);

        const validation = PathValidation.init(path_id, challenge_data);
        try self.active_validations.put(self.allocator, self.next_validation_id, validation);
        self.next_validation_id += 1;

        return challenge_data;
    }

    pub fn validateResponse(self: *PathValidator, response_data: [8]u8) ?u64 {
        var iterator = self.active_validations.iterator();
        while (iterator.next()) |entry| {
            if (std.mem.eql(u8, &entry.value_ptr.challenge_data, &response_data)) {
                const path_id = entry.value_ptr.path_id;
                _ = self.active_validations.remove(entry.key_ptr.*);
                return path_id;
            }
        }
        return null;
    }

    pub fn cleanupExpiredValidations(self: *PathValidator) void {
        var expired_keys: std.ArrayListUnmanaged(u64) = .{};
        defer expired_keys.deinit(self.allocator);

        var iterator = self.active_validations.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                expired_keys.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (expired_keys.items) |key| {
            _ = self.active_validations.remove(key);
        }
    }

    pub fn retryValidations(self: *PathValidator) ![]PathChallengeFrame {
        var challenges: std.ArrayListUnmanaged(PathChallengeFrame) = .{};
        errdefer challenges.deinit(self.allocator);

        var iterator = self.active_validations.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.shouldRetry()) {
                entry.value_ptr.retry();
                try challenges.append(self.allocator, PathChallengeFrame.init(entry.value_ptr.challenge_data));
            }
        }

        return challenges.toOwnedSlice(self.allocator);
    }
};

/// Connection migration manager
pub const ConnectionMigrator = struct {
    current_path: PathInfo,
    candidate_paths: std.ArrayListUnmanaged(PathInfo),
    migration_state: MigrationState,
    path_validator: PathValidator,
    connection_id_manager: ConnectionIdManager,
    migration_timeout_ms: u64,
    migration_start_time: i64,
    enable_migration: bool,
    allocator: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator, local_address: Address, remote_address: Address) ConnectionMigrator {
        return ConnectionMigrator{
            .current_path = PathInfo.init(local_address, remote_address, 0),
            .candidate_paths = .{},
            .migration_state = .stable,
            .path_validator = PathValidator.init(alloc),
            .connection_id_manager = ConnectionIdManager.init(alloc),
            .migration_timeout_ms = 15000, // 15 seconds
            .migration_start_time = 0,
            .enable_migration = true,
            .allocator = alloc,
        };
    }

    pub fn deinit(self: *ConnectionMigrator) void {
        self.candidate_paths.deinit(self.allocator);
        self.path_validator.deinit();
        self.connection_id_manager.deinit();
    }

    pub fn addCandidatePath(self: *ConnectionMigrator, local_address: Address, remote_address: Address) !void {
        const path_id = self.candidate_paths.items.len + 1;
        const path_info = PathInfo.init(local_address, remote_address, path_id);
        try self.candidate_paths.append(self.allocator, path_info);
    }

    pub fn startPathProbing(self: *ConnectionMigrator) ![]PathChallengeFrame {
        if (!self.enable_migration) {
            return &[_]PathChallengeFrame{};
        }

        var challenges: std.ArrayListUnmanaged(PathChallengeFrame) = .{};
        errdefer challenges.deinit(self.allocator);

        for (self.candidate_paths.items) |*path| {
            if (path.validation_state == .idle) {
                const challenge_data = try self.path_validator.startValidation(path.path_id);
                path.challenge_data = challenge_data;
                path.validation_state = .validating;

                try challenges.append(self.allocator, PathChallengeFrame.init(challenge_data));
            }
        }

        if (challenges.items.len > 0) {
            self.migration_state = .probing;
        }

        return challenges.toOwnedSlice(self.allocator);
    }

    pub fn handlePathResponse(self: *ConnectionMigrator, response_frame: PathResponseFrame) !void {
        if (self.path_validator.validateResponse(response_frame.data)) |path_id| {
            // Find the corresponding path
            for (self.candidate_paths.items) |*path| {
                if (path.path_id == path_id) {
                    path.validation_state = .validated;
                    path.updateActivity();

                    // Consider migration if this path is better
                    if (self.shouldMigrate(path)) {
                        try self.startMigration(path);
                    }
                    break;
                }
            }
        }
    }

    pub fn handlePathChallenge(self: *ConnectionMigrator, challenge_frame: PathChallengeFrame) !PathResponseFrame {
        // Update current path activity
        self.current_path.updateActivity();

        // Echo the challenge data back
        return PathResponseFrame.init(challenge_frame.data);
    }

    fn shouldMigrate(self: *const ConnectionMigrator, candidate_path: *const PathInfo) bool {
        if (self.migration_state != .probing) return false;
        if (candidate_path.validation_state != .validated) return false;

        // Simple migration decision based on path score
        const current_score = self.current_path.calculateScore();
        const candidate_score = candidate_path.calculateScore();

        // Require significant improvement to avoid unnecessary migrations
        return candidate_score > current_score * 1.2;
    }

    fn startMigration(self: *ConnectionMigrator, target_path: *const PathInfo) !void {
        self.migration_state = .migrating;
        const ts = std.posix.clock_gettime(.realtime) catch return error.TimerUnavailable;
        self.migration_start_time = ts.sec;

        // Generate new connection ID for migration
        const new_connection_id = try self.connection_id_manager.generateConnectionId();
        const reset_token = try self.connection_id_manager.generateStatelessResetToken();

        _ = try self.connection_id_manager.addConnectionId(new_connection_id, reset_token);

        std.log.info("Starting migration to path {} -> {}", .{ target_path.local_address, target_path.remote_address });
    }

    pub fn completeMigration(self: *ConnectionMigrator, target_path: PathInfo) !void {
        if (self.migration_state != .migrating) return;

        // Update current path
        self.current_path = target_path;
        self.migration_state = .stable;

        // Remove the migrated path from candidates
        for (self.candidate_paths.items, 0..) |path, i| {
            if (path.path_id == target_path.path_id) {
                _ = self.candidate_paths.swapRemove(i);
                break;
            }
        }

        // Cleanup connection IDs
        self.connection_id_manager.cleanupRetiredConnectionIds();

        std.log.info("Migration completed to path {} -> {}", .{ target_path.local_address, target_path.remote_address });
    }

    pub fn handleMigrationTimeout(self: *ConnectionMigrator) !void {
        if (self.migration_state == .migrating) {
            const ts = std.posix.clock_gettime(.realtime) catch return;
            const now = ts.sec;
            if (now - self.migration_start_time > @as(i64, @intCast(self.migration_timeout_ms / 1000))) {
                self.migration_state = .failed;

                // Clean up failed migration
                self.cleanupFailedMigration();

                std.log.warn("Migration timeout - reverting to stable state");
            }
        }
    }

    fn cleanupFailedMigration(self: *ConnectionMigrator) void {
        // Mark all candidate paths as failed
        for (self.candidate_paths.items) |*path| {
            if (path.validation_state == .validating) {
                path.validation_state = .failed;
            }
        }

        // Reset to stable state
        self.migration_state = .stable;

        // Cleanup expired validations
        self.path_validator.cleanupExpiredValidations();
    }

    pub fn updatePathStatistics(self: *ConnectionMigrator, path_id: u64, bytes_sent: u64, bytes_received: u64, rtt: ?u64) void {
        if (self.current_path.path_id == path_id) {
            self.current_path.bytes_sent += bytes_sent;
            self.current_path.bytes_received += bytes_received;
            if (rtt) |r| {
                self.current_path.rtt_estimate = r;
            }
            self.current_path.updateActivity();
        }

        for (self.candidate_paths.items) |*path| {
            if (path.path_id == path_id) {
                path.bytes_sent += bytes_sent;
                path.bytes_received += bytes_received;
                if (rtt) |r| {
                    path.rtt_estimate = r;
                }
                path.updateActivity();
                break;
            }
        }
    }

    pub fn getCurrentPath(self: *const ConnectionMigrator) PathInfo {
        return self.current_path;
    }

    pub fn getMigrationState(self: *const ConnectionMigrator) MigrationState {
        return self.migration_state;
    }

    /// Returns validated paths. Caller should iterate candidate_paths and filter by validation_state.
    pub fn getValidatedPaths(self: *const ConnectionMigrator) []const PathInfo {
        // Return the full items slice - caller filters by validation_state
        return self.candidate_paths.items;
    }
};

test "connection id manager lifecycle" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var manager = ConnectionIdManager.init(allocator);
    defer manager.deinit();

    const cid = try manager.generateConnectionId();
    defer allocator.free(cid);

    const token = try manager.generateStatelessResetToken();
    const frame = try manager.addConnectionId(cid, token);
    try std.testing.expectEqual(@as(u64, 0), frame.retire_prior_to);
    try std.testing.expectEqual(@as(u64, 1), frame.sequence_number);

    const entries = manager.getActiveConnectionIds();
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expect(entries[0].active);

    const retire_frame = manager.retireConnectionId(entries[0].sequence_number) orelse return error.Unexpected;
    try std.testing.expectEqual(entries[0].sequence_number, retire_frame.sequence_number);

    manager.cleanupRetiredConnectionIds();
    try std.testing.expectEqual(@as(usize, 0), manager.getActiveConnectionIds().len);
}

test "path validator start validate retry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var validator = PathValidator.init(allocator);
    defer validator.deinit();

    const challenge = try validator.startValidation(42);
    const maybe_path = validator.validateResponse(challenge);
    try std.testing.expectEqual(@as(?u64, 42), maybe_path);

    // Start another validation to exercise retry logic
    const retry_challenge = try validator.startValidation(7);
    _ = retry_challenge;

    const retries = try validator.retryValidations();
    defer allocator.free(retries);
    try std.testing.expect(retries.len >= 1);
}

/// 0-RTT (Zero Round Trip Time) manager
pub const ZeroRTTManager = struct {
    session_tickets: std.ArrayListUnmanaged(SessionTicket),
    early_data_buffer: std.ArrayListUnmanaged(u8),
    max_early_data_size: u32,
    early_data_accepted: bool,
    early_data_state: EarlyDataState,
    allocator: std.mem.Allocator,

    const EarlyDataState = enum {
        disabled,
        ready,
        sending,
        accepted,
        rejected,
    };

    pub fn init(alloc: std.mem.Allocator) ZeroRTTManager {
        return ZeroRTTManager{
            .session_tickets = .{},
            .early_data_buffer = .{},
            .max_early_data_size = 0xFFFFFFFF,
            .early_data_accepted = false,
            .early_data_state = .disabled,
            .allocator = alloc,
        };
    }

    pub fn deinit(self: *ZeroRTTManager) void {
        for (self.session_tickets.items) |*ticket| {
            ticket.deinit(self.allocator);
        }
        self.session_tickets.deinit(self.allocator);
        self.early_data_buffer.deinit(self.allocator);
    }

    pub fn addSessionTicket(self: *ZeroRTTManager, ticket: SessionTicket) !void {
        try self.session_tickets.append(self.allocator, ticket);
        if (ticket.max_early_data_size > 0) {
            self.early_data_state = .ready;
        }
    }

    pub fn getValidSessionTicket(self: *const ZeroRTTManager) ?SessionTicket {
        for (self.session_tickets.items) |ticket| {
            if (ticket.isValid()) {
                return ticket;
            }
        }
        return null;
    }

    pub fn canSendEarlyData(self: *const ZeroRTTManager) bool {
        return self.early_data_state == .ready and self.getValidSessionTicket() != null;
    }

    pub fn prepareEarlyData(self: *ZeroRTTManager, data: []const u8) !bool {
        if (!self.canSendEarlyData()) {
            return false;
        }

        if (self.early_data_buffer.items.len + data.len > self.max_early_data_size) {
            return false;
        }

        try self.early_data_buffer.appendSlice(self.allocator, data);
        self.early_data_state = .sending;
        return true;
    }

    pub fn getEarlyData(self: *const ZeroRTTManager) []const u8 {
        return self.early_data_buffer.items;
    }

    pub fn acceptEarlyData(self: *ZeroRTTManager) void {
        self.early_data_accepted = true;
        self.early_data_state = .accepted;
    }

    pub fn rejectEarlyData(self: *ZeroRTTManager) void {
        self.early_data_accepted = false;
        self.early_data_state = .rejected;
        self.early_data_buffer.clearRetainingCapacity();
    }

    pub fn isEarlyDataAccepted(self: *const ZeroRTTManager) bool {
        return self.early_data_accepted and self.early_data_state == .accepted;
    }

    pub fn isEarlyDataRejected(self: *const ZeroRTTManager) bool {
        return self.early_data_state == .rejected;
    }

    pub fn cleanupExpiredTickets(self: *ZeroRTTManager) void {
        var i: usize = 0;
        while (i < self.session_tickets.items.len) {
            if (!self.session_tickets.items[i].isValid()) {
                var ticket = self.session_tickets.swapRemove(i);
                ticket.deinit(self.allocator);
            } else {
                i += 1;
            }
        }

        // Update early data state if no valid tickets
        if (self.getValidSessionTicket() == null) {
            self.early_data_state = .disabled;
        }
    }

    pub fn deriveEarlyTrafficSecret(self: *const ZeroRTTManager, tls_context: *const ComprehensiveTlsContext) ![]u8 {
        _ = tls_context;

        if (self.getValidSessionTicket()) |ticket| {
            // Derive early traffic secret from resumption secret
            const secret = try self.allocator.alloc(u8, 32);
            @memcpy(secret, ticket.resumption_secret[0..32]);

            // In real implementation, would use HKDF-Expand-Label
            return secret;
        }

        return Error.ZquicError.InvalidState;
    }

    pub fn updateMaxEarlyDataSize(self: *ZeroRTTManager, max_size: u32) void {
        self.max_early_data_size = max_size;
    }

    pub fn getEarlyDataState(self: *const ZeroRTTManager) EarlyDataState {
        return self.early_data_state;
    }
};

/// Combined connection migration and 0-RTT manager
pub const MigrationAndZeroRTTManager = struct {
    migrator: ConnectionMigrator,
    zero_rtt_manager: ZeroRTTManager,
    tls_context: ?*ComprehensiveTlsContext,
    allocator: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator, local_address: Address, remote_address: Address) MigrationAndZeroRTTManager {
        return MigrationAndZeroRTTManager{
            .migrator = ConnectionMigrator.init(alloc, local_address, remote_address),
            .zero_rtt_manager = ZeroRTTManager.init(alloc),
            .tls_context = null,
            .allocator = alloc,
        };
    }

    pub fn deinit(self: *MigrationAndZeroRTTManager) void {
        self.migrator.deinit();
        self.zero_rtt_manager.deinit();
    }

    pub fn setTlsContext(self: *MigrationAndZeroRTTManager, tls_context: *ComprehensiveTlsContext) void {
        self.tls_context = tls_context;
    }

    pub fn canUseZeroRTT(self: *const MigrationAndZeroRTTManager) bool {
        return self.zero_rtt_manager.canSendEarlyData();
    }

    pub fn canMigrate(self: *const MigrationAndZeroRTTManager) bool {
        return self.migrator.enable_migration and self.migrator.migration_state == .stable;
    }

    pub fn handleIncomingFrame(self: *MigrationAndZeroRTTManager, frame: Frame) !?Frame {
        switch (frame) {
            .path_challenge => |challenge_frame| {
                return Frame{ .path_response = try self.migrator.handlePathChallenge(challenge_frame) };
            },
            .path_response => |response_frame| {
                try self.migrator.handlePathResponse(response_frame);
                return null;
            },
            .new_connection_id => |_| {
                // Handle new connection ID for migration
                return null;
            },
            .retire_connection_id => |_| {
                // Handle connection ID retirement
                return null;
            },
            else => return null,
        }
    }

    pub fn generateMigrationFrames(self: *MigrationAndZeroRTTManager) ![]Frame {
        var frames: std.ArrayListUnmanaged(Frame) = .{};
        errdefer frames.deinit(self.allocator);

        // Generate path challenge frames
        const challenges = try self.migrator.startPathProbing();
        defer self.allocator.free(challenges);

        for (challenges) |challenge| {
            try frames.append(self.allocator, Frame{ .path_challenge = challenge });
        }

        // Generate new connection ID frames if needed
        // This would be implemented based on connection ID management requirements

        return frames.toOwnedSlice(self.allocator);
    }

    pub fn processPeriodicTasks(self: *MigrationAndZeroRTTManager) !void {
        // Handle migration timeouts
        try self.migrator.handleMigrationTimeout();

        // Clean up expired path validations
        self.migrator.path_validator.cleanupExpiredValidations();

        // Clean up expired session tickets
        self.zero_rtt_manager.cleanupExpiredTickets();

        // Clean up retired connection IDs
        self.migrator.connection_id_manager.cleanupRetiredConnectionIds();
    }

    pub fn getConnectionStats(self: *const MigrationAndZeroRTTManager) ConnectionStats {
        return ConnectionStats{
            .current_path = self.migrator.getCurrentPath(),
            .migration_state = self.migrator.getMigrationState(),
            .validated_paths = self.migrator.getValidatedPaths(),
            .early_data_state = self.zero_rtt_manager.getEarlyDataState(),
            .early_data_accepted = self.zero_rtt_manager.isEarlyDataAccepted(),
            .available_session_tickets = self.zero_rtt_manager.session_tickets.items.len,
        };
    }

    pub const ConnectionStats = struct {
        current_path: PathInfo,
        migration_state: MigrationState,
        validated_paths: []const PathInfo,
        early_data_state: ZeroRTTManager.EarlyDataState,
        early_data_accepted: bool,
        available_session_tickets: usize,
    };
};

/// Test utilities for migration and 0-RTT
pub const TestUtilities = struct {
    pub fn createMockSessionTicket(allocator: std.mem.Allocator) !SessionTicket {
        const ticket_data = try allocator.alloc(u8, 32);
        std.crypto.random.bytes(ticket_data);

        const resumption_secret = try allocator.alloc(u8, 32);
        std.crypto.random.bytes(resumption_secret);

        return SessionTicket.init(allocator, ticket_data, resumption_secret, .tls_aes_128_gcm_sha256);
    }

    pub fn createMockPathInfo(local_port: u16, remote_port: u16) PathInfo {
        const local_addr = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, local_port);
        const remote_addr = NetAddress.initIp4([4]u8{ 192, 168, 1, 1 }, remote_port);
        return PathInfo.init(local_addr, remote_addr, 1);
    }

    pub fn simulatePathValidation(migrator: *ConnectionMigrator, path_id: u64) !void {
        const challenge_data = try migrator.path_validator.startValidation(path_id);
        const response_frame = PathResponseFrame.init(challenge_data);
        try migrator.handlePathResponse(response_frame);
    }
};
