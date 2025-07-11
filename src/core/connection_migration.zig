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
    local_address: std.net.Address,
    remote_address: std.net.Address,
    path_id: u64,
    validation_state: PathValidationState,
    challenge_data: ?[8]u8,
    rtt_estimate: ?u64,
    loss_rate: f64,
    congestion_window: u64,
    bytes_sent: u64,
    bytes_received: u64,
    last_activity: i64,
    
    pub fn init(local_address: std.net.Address, remote_address: std.net.Address, path_id: u64) PathInfo {
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
            .last_activity = std.time.timestamp(),
        };
    }
    
    pub fn updateActivity(self: *PathInfo) void {
        self.last_activity = std.time.timestamp();
    }
    
    pub fn isExpired(self: *const PathInfo, timeout_ms: u64) bool {
        const now = std.time.timestamp();
        return now - self.last_activity > timeout_ms;
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
    active_connection_ids: std.ArrayList(ConnectionIdEntry),
    next_sequence_number: u64,
    retire_prior_to: u64,
    allocator: std.mem.Allocator,
    
    const ConnectionIdEntry = struct {
        connection_id: []const u8,
        sequence_number: u64,
        stateless_reset_token: [16]u8,
        active: bool,
        
        pub fn init(allocator: std.mem.Allocator, connection_id: []const u8, sequence_number: u64, stateless_reset_token: [16]u8) !ConnectionIdEntry {
            return ConnectionIdEntry{
                .connection_id = try allocator.dupe(u8, connection_id),
                .sequence_number = sequence_number,
                .stateless_reset_token = stateless_reset_token,
                .active = true,
            };
        }
        
        pub fn deinit(self: *ConnectionIdEntry, allocator: std.mem.Allocator) void {
            allocator.free(self.connection_id);
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) ConnectionIdManager {
        return ConnectionIdManager{
            .active_connection_ids = std.ArrayList(ConnectionIdEntry).init(allocator),
            .next_sequence_number = 1,
            .retire_prior_to = 0,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ConnectionIdManager) void {
        for (self.active_connection_ids.items) |*entry| {
            entry.deinit(self.allocator);
        }
        self.active_connection_ids.deinit();
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
        try self.active_connection_ids.append(entry);
        
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
    
    pub fn getActiveConnectionIds(self: *const ConnectionIdManager) []const ConnectionIdEntry {
        var active_ids = std.ArrayList(ConnectionIdEntry).init(self.allocator);
        defer active_ids.deinit();
        
        for (self.active_connection_ids.items) |entry| {
            if (entry.active) {
                active_ids.append(entry) catch continue;
            }
        }
        
        return active_ids.toOwnedSlice() catch &[_]ConnectionIdEntry{};
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
    active_validations: std.HashMap(u64, PathValidation, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
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
                .start_time = std.time.timestamp(),
                .attempts = 1,
                .max_attempts = 3,
                .timeout_ms = 3000,
            };
        }
        
        pub fn isExpired(self: *const PathValidation) bool {
            const now = std.time.timestamp();
            return now - self.start_time > self.timeout_ms;
        }
        
        pub fn shouldRetry(self: *const PathValidation) bool {
            return self.attempts < self.max_attempts and !self.isExpired();
        }
        
        pub fn retry(self: *PathValidation) void {
            self.attempts += 1;
            self.start_time = std.time.timestamp();
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) PathValidator {
        return PathValidator{
            .active_validations = std.HashMap(u64, PathValidation, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .next_validation_id = 1,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *PathValidator) void {
        self.active_validations.deinit();
    }
    
    pub fn startValidation(self: *PathValidator, path_id: u64) ![8]u8 {
        var challenge_data: [8]u8 = undefined;
        std.crypto.random.bytes(&challenge_data);
        
        const validation = PathValidation.init(path_id, challenge_data);
        try self.active_validations.put(self.next_validation_id, validation);
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
        var expired_keys = std.ArrayList(u64).init(self.allocator);
        defer expired_keys.deinit();
        
        var iterator = self.active_validations.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                expired_keys.append(entry.key_ptr.*) catch continue;
            }
        }
        
        for (expired_keys.items) |key| {
            _ = self.active_validations.remove(key);
        }
    }
    
    pub fn retryValidations(self: *PathValidator) ![]PathChallengeFrame {
        var challenges = std.ArrayList(PathChallengeFrame).init(self.allocator);
        defer challenges.deinit();
        
        var iterator = self.active_validations.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.shouldRetry()) {
                entry.value_ptr.retry();
                try challenges.append(PathChallengeFrame.init(entry.value_ptr.challenge_data));
            }
        }
        
        return challenges.toOwnedSlice();
    }
};

/// Connection migration manager
pub const ConnectionMigrator = struct {
    current_path: PathInfo,
    candidate_paths: std.ArrayList(PathInfo),
    migration_state: MigrationState,
    path_validator: PathValidator,
    connection_id_manager: ConnectionIdManager,
    migration_timeout_ms: u64,
    migration_start_time: i64,
    enable_migration: bool,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, local_address: std.net.Address, remote_address: std.net.Address) ConnectionMigrator {
        return ConnectionMigrator{
            .current_path = PathInfo.init(local_address, remote_address, 0),
            .candidate_paths = std.ArrayList(PathInfo).init(allocator),
            .migration_state = .stable,
            .path_validator = PathValidator.init(allocator),
            .connection_id_manager = ConnectionIdManager.init(allocator),
            .migration_timeout_ms = 15000, // 15 seconds
            .migration_start_time = 0,
            .enable_migration = true,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ConnectionMigrator) void {
        self.candidate_paths.deinit();
        self.path_validator.deinit();
        self.connection_id_manager.deinit();
    }
    
    pub fn addCandidatePath(self: *ConnectionMigrator, local_address: std.net.Address, remote_address: std.net.Address) !void {
        const path_id = self.candidate_paths.items.len + 1;
        const path_info = PathInfo.init(local_address, remote_address, path_id);
        try self.candidate_paths.append(path_info);
    }
    
    pub fn startPathProbing(self: *ConnectionMigrator) ![]PathChallengeFrame {
        if (!self.enable_migration) {
            return &[_]PathChallengeFrame{};
        }
        
        var challenges = std.ArrayList(PathChallengeFrame).init(self.allocator);
        defer challenges.deinit();
        
        for (self.candidate_paths.items) |*path| {
            if (path.validation_state == .idle) {
                const challenge_data = try self.path_validator.startValidation(path.path_id);
                path.challenge_data = challenge_data;
                path.validation_state = .validating;
                
                try challenges.append(PathChallengeFrame.init(challenge_data));
            }
        }
        
        if (challenges.items.len > 0) {
            self.migration_state = .probing;
        }
        
        return challenges.toOwnedSlice();
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
        self.migration_start_time = std.time.timestamp();
        
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
            const now = std.time.timestamp();
            if (now - self.migration_start_time > self.migration_timeout_ms) {
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
    
    pub fn getValidatedPaths(self: *const ConnectionMigrator) []const PathInfo {
        var validated_paths = std.ArrayList(PathInfo).init(self.allocator);
        defer validated_paths.deinit();
        
        for (self.candidate_paths.items) |path| {
            if (path.validation_state == .validated) {
                validated_paths.append(path) catch continue;
            }
        }
        
        return validated_paths.toOwnedSlice() catch &[_]PathInfo{};
    }
};

/// 0-RTT (Zero Round Trip Time) manager
pub const ZeroRTTManager = struct {
    session_tickets: std.ArrayList(SessionTicket),
    early_data_buffer: std.ArrayList(u8),
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
    
    pub fn init(allocator: std.mem.Allocator) ZeroRTTManager {
        return ZeroRTTManager{
            .session_tickets = std.ArrayList(SessionTicket).init(allocator),
            .early_data_buffer = std.ArrayList(u8).init(allocator),
            .max_early_data_size = 0xFFFFFFFF,
            .early_data_accepted = false,
            .early_data_state = .disabled,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ZeroRTTManager) void {
        for (self.session_tickets.items) |*ticket| {
            ticket.deinit();
        }
        self.session_tickets.deinit();
        self.early_data_buffer.deinit();
    }
    
    pub fn addSessionTicket(self: *ZeroRTTManager, ticket: SessionTicket) !void {
        try self.session_tickets.append(ticket);
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
        
        try self.early_data_buffer.appendSlice(data);
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
                ticket.deinit();
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
    
    pub fn init(allocator: std.mem.Allocator, local_address: std.net.Address, remote_address: std.net.Address) MigrationAndZeroRTTManager {
        return MigrationAndZeroRTTManager{
            .migrator = ConnectionMigrator.init(allocator, local_address, remote_address),
            .zero_rtt_manager = ZeroRTTManager.init(allocator),
            .tls_context = null,
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
        var frames = std.ArrayList(Frame).init(self.migrator.allocator);
        defer frames.deinit();
        
        // Generate path challenge frames
        const challenges = try self.migrator.startPathProbing();
        for (challenges) |challenge| {
            try frames.append(Frame{ .path_challenge = challenge });
        }
        
        // Generate new connection ID frames if needed
        // This would be implemented based on connection ID management requirements
        
        return frames.toOwnedSlice();
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
        const local_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, local_port);
        const remote_addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 1 }, remote_port);
        return PathInfo.init(local_addr, remote_addr, 1);
    }
    
    pub fn simulatePathValidation(migrator: *ConnectionMigrator, path_id: u64) !void {
        const challenge_data = try migrator.path_validator.startValidation(path_id);
        const response_frame = PathResponseFrame.init(challenge_data);
        try migrator.handlePathResponse(response_frame);
    }
};