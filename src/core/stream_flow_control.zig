//! Advanced Stream Flow Control and Prioritization for QUIC
//!
//! Implements RFC 9000 flow control mechanisms with advanced prioritization
//! that exceeds Quinn's capabilities:
//! - Per-stream and connection-level flow control
//! - HTTP/3 priority trees and scheduling
//! - Dynamic priority adjustment
//! - Fairness algorithms
//! - Backpressure management
//! - Stream dependency graphs

const std = @import("std");
const Error = @import("../utils/error.zig");
const Frame = @import("quic_frames.zig").Frame;
const MaxDataFrame = @import("quic_frames.zig").MaxDataFrame;
const MaxStreamDataFrame = @import("quic_frames.zig").MaxStreamDataFrame;
const DataBlockedFrame = @import("quic_frames.zig").DataBlockedFrame;
const StreamDataBlockedFrame = @import("quic_frames.zig").StreamDataBlockedFrame;

/// Stream priority levels
pub const StreamPriority = enum(u8) {
    critical = 0,
    high = 1,
    normal = 2,
    low = 3,
    background = 4,
    
    pub fn getWeight(self: StreamPriority) u32 {
        return switch (self) {
            .critical => 1000,
            .high => 256,
            .normal => 64,
            .low => 16,
            .background => 1,
        };
    }
    
    pub fn toString(self: StreamPriority) []const u8 {
        return switch (self) {
            .critical => "Critical",
            .high => "High",
            .normal => "Normal",
            .low => "Low",
            .background => "Background",
        };
    }
};

/// HTTP/3 priority urgency levels (RFC 9218)
pub const PriorityUrgency = enum(u8) {
    urgency_0 = 0, // Highest priority
    urgency_1 = 1,
    urgency_2 = 2,
    urgency_3 = 3, // Default
    urgency_4 = 4,
    urgency_5 = 5,
    urgency_6 = 6,
    urgency_7 = 7, // Lowest priority
    
    pub fn getWeight(self: PriorityUrgency) u32 {
        return switch (self) {
            .urgency_0 => 256,
            .urgency_1 => 128,
            .urgency_2 => 64,
            .urgency_3 => 32,
            .urgency_4 => 16,
            .urgency_5 => 8,
            .urgency_6 => 4,
            .urgency_7 => 1,
        };
    }
};

/// Stream flow control state
pub const StreamFlowControl = struct {
    stream_id: u64,
    send_window: u64,
    receive_window: u64,
    max_stream_data_local: u64,
    max_stream_data_remote: u64,
    bytes_sent: u64,
    bytes_received: u64,
    bytes_acknowledged: u64,
    
    // Flow control limits
    initial_max_stream_data: u64,
    max_window_size: u64,
    window_update_threshold: f64,
    
    // Backpressure management
    is_blocked: bool,
    blocked_since: ?i64,
    
    pub fn init(stream_id: u64, initial_max_stream_data: u64) StreamFlowControl {
        return StreamFlowControl{
            .stream_id = stream_id,
            .send_window = initial_max_stream_data,
            .receive_window = initial_max_stream_data,
            .max_stream_data_local = initial_max_stream_data,
            .max_stream_data_remote = initial_max_stream_data,
            .bytes_sent = 0,
            .bytes_received = 0,
            .bytes_acknowledged = 0,
            .initial_max_stream_data = initial_max_stream_data,
            .max_window_size = initial_max_stream_data * 16, // Allow window to grow 16x
            .window_update_threshold = 0.5, // Update when 50% consumed
            .is_blocked = false,
            .blocked_since = null,
        };
    }
    
    pub fn canSend(self: *const StreamFlowControl, bytes: u64) bool {
        return self.bytes_sent + bytes <= self.send_window and !self.is_blocked;
    }
    
    pub fn consumeSendWindow(self: *StreamFlowControl, bytes: u64) !void {
        if (!self.canSend(bytes)) {
            self.is_blocked = true;
            self.blocked_since = std.time.timestamp();
            return Error.ZquicError.FlowControlBlocked;
        }
        
        self.bytes_sent += bytes;
    }
    
    pub fn updateSendWindow(self: *StreamFlowControl, new_max_data: u64) void {
        if (new_max_data > self.send_window) {
            self.send_window = new_max_data;
            if (self.is_blocked and self.bytes_sent < self.send_window) {
                self.is_blocked = false;
                self.blocked_since = null;
            }
        }
    }
    
    pub fn consumeReceiveWindow(self: *StreamFlowControl, bytes: u64) !void {
        if (self.bytes_received + bytes > self.receive_window) {
            return Error.ZquicError.FlowControlViolation;
        }
        
        self.bytes_received += bytes;
    }
    
    pub fn shouldUpdateReceiveWindow(self: *const StreamFlowControl) bool {
        const consumed = self.bytes_received;
        const threshold = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.receive_window)) * self.window_update_threshold));
        return consumed >= threshold;
    }
    
    pub fn generateWindowUpdate(self: *StreamFlowControl) MaxStreamDataFrame {
        // Increase receive window based on consumption rate
        const consumption_rate = if (self.bytes_received > 0) self.bytes_received else self.initial_max_stream_data;
        const new_window = @min(self.receive_window + consumption_rate, self.max_window_size);
        
        self.max_stream_data_local = new_window;
        self.receive_window = new_window;
        
        return MaxStreamDataFrame.init(self.stream_id, new_window);
    }
    
    pub fn getAvailableSendData(self: *const StreamFlowControl) u64 {
        return if (self.send_window > self.bytes_sent) self.send_window - self.bytes_sent else 0;
    }
    
    pub fn getAvailableReceiveData(self: *const StreamFlowControl) u64 {
        return if (self.receive_window > self.bytes_received) self.receive_window - self.bytes_received else 0;
    }
    
    pub fn getUtilization(self: *const StreamFlowControl) f64 {
        if (self.send_window == 0) return 0.0;
        return @as(f64, @floatFromInt(self.bytes_sent)) / @as(f64, @floatFromInt(self.send_window));
    }
};

/// Connection-level flow control
pub const ConnectionFlowControl = struct {
    max_data_local: u64,
    max_data_remote: u64,
    bytes_sent: u64,
    bytes_received: u64,
    bytes_acknowledged: u64,
    
    // Flow control parameters
    initial_max_data: u64,
    max_window_size: u64,
    window_update_threshold: f64,
    
    // Connection state
    is_blocked: bool,
    blocked_since: ?i64,
    
    pub fn init(initial_max_data: u64) ConnectionFlowControl {
        return ConnectionFlowControl{
            .max_data_local = initial_max_data,
            .max_data_remote = initial_max_data,
            .bytes_sent = 0,
            .bytes_received = 0,
            .bytes_acknowledged = 0,
            .initial_max_data = initial_max_data,
            .max_window_size = initial_max_data * 32, // Allow 32x growth
            .window_update_threshold = 0.5,
            .is_blocked = false,
            .blocked_since = null,
        };
    }
    
    pub fn canSend(self: *const ConnectionFlowControl, bytes: u64) bool {
        return self.bytes_sent + bytes <= self.max_data_remote and !self.is_blocked;
    }
    
    pub fn consumeSendWindow(self: *ConnectionFlowControl, bytes: u64) !void {
        if (!self.canSend(bytes)) {
            self.is_blocked = true;
            self.blocked_since = std.time.timestamp();
            return Error.ZquicError.FlowControlBlocked;
        }
        
        self.bytes_sent += bytes;
    }
    
    pub fn updateSendWindow(self: *ConnectionFlowControl, new_max_data: u64) void {
        if (new_max_data > self.max_data_remote) {
            self.max_data_remote = new_max_data;
            if (self.is_blocked and self.bytes_sent < self.max_data_remote) {
                self.is_blocked = false;
                self.blocked_since = null;
            }
        }
    }
    
    pub fn consumeReceiveWindow(self: *ConnectionFlowControl, bytes: u64) !void {
        if (self.bytes_received + bytes > self.max_data_local) {
            return Error.ZquicError.FlowControlViolation;
        }
        
        self.bytes_received += bytes;
    }
    
    pub fn shouldUpdateReceiveWindow(self: *const ConnectionFlowControl) bool {
        const consumed = self.bytes_received;
        const threshold = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.max_data_local)) * self.window_update_threshold));
        return consumed >= threshold;
    }
    
    pub fn generateWindowUpdate(self: *ConnectionFlowControl) MaxDataFrame {
        // Adaptive window growth based on bandwidth-delay product estimate
        const consumption_rate = if (self.bytes_received > 0) self.bytes_received else self.initial_max_data;
        const growth_factor = @min(consumption_rate / self.initial_max_data, 4); // Max 4x growth
        const new_window = @min(self.max_data_local + consumption_rate * growth_factor, self.max_window_size);
        
        self.max_data_local = new_window;
        
        return MaxDataFrame.init(new_window);
    }
    
    pub fn getAvailableSendData(self: *const ConnectionFlowControl) u64 {
        return if (self.max_data_remote > self.bytes_sent) self.max_data_remote - self.bytes_sent else 0;
    }
};

/// Stream priority information for scheduling
pub const StreamPriorityInfo = struct {
    stream_id: u64,
    priority: StreamPriority,
    urgency: PriorityUrgency,
    incremental: bool, // HTTP/3 incremental flag
    weight: u32,
    parent_stream_id: ?u64, // For dependency trees
    children: std.ArrayList(u64),
    
    // Scheduling state
    bytes_scheduled: u64,
    last_scheduled: i64,
    deficit: f64, // For deficit round-robin scheduling
    
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, stream_id: u64, priority: StreamPriority) StreamPriorityInfo {
        return StreamPriorityInfo{
            .stream_id = stream_id,
            .priority = priority,
            .urgency = .urgency_3, // Default urgency
            .incremental = false,
            .weight = priority.getWeight(),
            .parent_stream_id = null,
            .children = std.ArrayList(u64).init(allocator),
            .bytes_scheduled = 0,
            .last_scheduled = 0,
            .deficit = 0.0,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *StreamPriorityInfo) void {
        self.children.deinit();
    }
    
    pub fn addChild(self: *StreamPriorityInfo, child_stream_id: u64) !void {
        try self.children.append(child_stream_id);
    }
    
    pub fn removeChild(self: *StreamPriorityInfo, child_stream_id: u64) void {
        for (self.children.items, 0..) |child, i| {
            if (child == child_stream_id) {
                _ = self.children.swapRemove(i);
                break;
            }
        }
    }
    
    pub fn getEffectiveWeight(self: *const StreamPriorityInfo) u32 {
        // Combine priority weight with urgency weight
        const priority_weight = self.priority.getWeight();
        const urgency_weight = self.urgency.getWeight();
        return priority_weight + urgency_weight;
    }
    
    pub fn updatePriority(self: *StreamPriorityInfo, new_priority: StreamPriority, new_urgency: PriorityUrgency) void {
        self.priority = new_priority;
        self.urgency = new_urgency;
        self.weight = self.getEffectiveWeight();
    }
};

/// Advanced stream scheduler with multiple algorithms
pub const StreamScheduler = struct {
    algorithm: SchedulingAlgorithm,
    streams: std.HashMap(u64, StreamPriorityInfo, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    ready_streams: std.ArrayList(u64),
    blocked_streams: std.ArrayList(u64),
    
    // Round-robin state
    current_round_robin_index: usize,
    
    // Deficit round-robin state
    quantum: f64,
    
    // Weighted fair queueing state
    virtual_time: f64,
    
    allocator: std.mem.Allocator,
    
    const SchedulingAlgorithm = enum {
        round_robin,
        priority_queue,
        weighted_fair_queueing,
        deficit_round_robin,
        hierarchical_fair_queueing,
        
        pub fn toString(self: SchedulingAlgorithm) []const u8 {
            return switch (self) {
                .round_robin => "Round Robin",
                .priority_queue => "Priority Queue",
                .weighted_fair_queueing => "Weighted Fair Queueing",
                .deficit_round_robin => "Deficit Round Robin",
                .hierarchical_fair_queueing => "Hierarchical Fair Queueing",
            };
        }
    };
    
    pub fn init(allocator: std.mem.Allocator, algorithm: SchedulingAlgorithm) StreamScheduler {
        return StreamScheduler{
            .algorithm = algorithm,
            .streams = std.HashMap(u64, StreamPriorityInfo, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .ready_streams = std.ArrayList(u64).init(allocator),
            .blocked_streams = std.ArrayList(u64).init(allocator),
            .current_round_robin_index = 0,
            .quantum = 1500.0, // Default quantum size
            .virtual_time = 0.0,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *StreamScheduler) void {
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.streams.deinit();
        self.ready_streams.deinit();
        self.blocked_streams.deinit();
    }
    
    pub fn addStream(self: *StreamScheduler, stream_id: u64, priority: StreamPriority) !void {
        const priority_info = StreamPriorityInfo.init(self.allocator, stream_id, priority);
        try self.streams.put(stream_id, priority_info);
        try self.ready_streams.append(stream_id);
    }
    
    pub fn removeStream(self: *StreamScheduler, stream_id: u64) void {
        if (self.streams.getPtr(stream_id)) |stream_info| {
            // Remove from parent's children
            if (stream_info.parent_stream_id) |parent_id| {
                if (self.streams.getPtr(parent_id)) |parent| {
                    parent.removeChild(stream_id);
                }
            }
            
            // Reparent children
            for (stream_info.children.items) |child_id| {
                if (self.streams.getPtr(child_id)) |child| {
                    child.parent_stream_id = stream_info.parent_stream_id;
                    if (stream_info.parent_stream_id) |parent_id| {
                        if (self.streams.getPtr(parent_id)) |parent| {
                            parent.addChild(child_id) catch {};
                        }
                    }
                }
            }
            
            stream_info.deinit();
            _ = self.streams.remove(stream_id);
        }
        
        // Remove from scheduling lists
        for (self.ready_streams.items, 0..) |id, i| {
            if (id == stream_id) {
                _ = self.ready_streams.swapRemove(i);
                break;
            }
        }
        
        for (self.blocked_streams.items, 0..) |id, i| {
            if (id == stream_id) {
                _ = self.blocked_streams.swapRemove(i);
                break;
            }
        }
    }
    
    pub fn updateStreamPriority(self: *StreamScheduler, stream_id: u64, priority: StreamPriority, urgency: PriorityUrgency) void {
        if (self.streams.getPtr(stream_id)) |stream_info| {
            stream_info.updatePriority(priority, urgency);
        }
    }
    
    pub fn setStreamDependency(self: *StreamScheduler, stream_id: u64, parent_stream_id: u64) !void {
        if (self.streams.getPtr(stream_id)) |stream_info| {
            // Remove from old parent
            if (stream_info.parent_stream_id) |old_parent| {
                if (self.streams.getPtr(old_parent)) |old_parent_info| {
                    old_parent_info.removeChild(stream_id);
                }
            }
            
            // Add to new parent
            stream_info.parent_stream_id = parent_stream_id;
            if (self.streams.getPtr(parent_stream_id)) |parent_info| {
                try parent_info.addChild(stream_id);
            }
        }
    }
    
    pub fn markStreamBlocked(self: *StreamScheduler, stream_id: u64) void {
        // Move from ready to blocked
        for (self.ready_streams.items, 0..) |id, i| {
            if (id == stream_id) {
                _ = self.ready_streams.swapRemove(i);
                self.blocked_streams.append(stream_id) catch {};
                break;
            }
        }
    }
    
    pub fn markStreamReady(self: *StreamScheduler, stream_id: u64) void {
        // Move from blocked to ready
        for (self.blocked_streams.items, 0..) |id, i| {
            if (id == stream_id) {
                _ = self.blocked_streams.swapRemove(i);
                self.ready_streams.append(stream_id) catch {};
                break;
            }
        }
    }
    
    pub fn selectNextStream(self: *StreamScheduler) ?u64 {
        return switch (self.algorithm) {
            .round_robin => self.selectRoundRobin(),
            .priority_queue => self.selectPriorityQueue(),
            .weighted_fair_queueing => self.selectWeightedFairQueueing(),
            .deficit_round_robin => self.selectDeficitRoundRobin(),
            .hierarchical_fair_queueing => self.selectHierarchicalFairQueueing(),
        };
    }
    
    fn selectRoundRobin(self: *StreamScheduler) ?u64 {
        if (self.ready_streams.items.len == 0) return null;
        
        const stream_id = self.ready_streams.items[self.current_round_robin_index];
        self.current_round_robin_index = (self.current_round_robin_index + 1) % self.ready_streams.items.len;
        
        return stream_id;
    }
    
    fn selectPriorityQueue(self: *StreamScheduler) ?u64 {
        if (self.ready_streams.items.len == 0) return null;
        
        var highest_priority_stream: ?u64 = null;
        var highest_weight: u32 = 0;
        
        for (self.ready_streams.items) |stream_id| {
            if (self.streams.get(stream_id)) |stream_info| {
                const weight = stream_info.getEffectiveWeight();
                if (weight > highest_weight) {
                    highest_weight = weight;
                    highest_priority_stream = stream_id;
                }
            }
        }
        
        return highest_priority_stream;
    }
    
    fn selectWeightedFairQueueing(self: *StreamScheduler) ?u64 {
        if (self.ready_streams.items.len == 0) return null;
        
        var min_virtual_finish_time: f64 = std.math.inf(f64);
        var selected_stream: ?u64 = null;
        
        for (self.ready_streams.items) |stream_id| {
            if (self.streams.get(stream_id)) |stream_info| {
                const weight = @as(f64, @floatFromInt(stream_info.getEffectiveWeight()));
                const service_time = self.quantum / weight;
                const virtual_finish_time = self.virtual_time + service_time;
                
                if (virtual_finish_time < min_virtual_finish_time) {
                    min_virtual_finish_time = virtual_finish_time;
                    selected_stream = stream_id;
                }
            }
        }
        
        // Update virtual time
        if (selected_stream) |_| {
            self.virtual_time = min_virtual_finish_time;
        }
        
        return selected_stream;
    }
    
    fn selectDeficitRoundRobin(self: *StreamScheduler) ?u64 {
        for (self.ready_streams.items) |stream_id| {
            if (self.streams.getPtr(stream_id)) |stream_info| {
                // Add quantum to deficit
                stream_info.deficit += self.quantum * @as(f64, @floatFromInt(stream_info.getEffectiveWeight())) / 100.0;
                
                // Select if deficit is sufficient for at least one packet
                if (stream_info.deficit >= 1500.0) { // Assume 1500 byte packets
                    return stream_id;
                }
            }
        }
        
        return null;
    }
    
    fn selectHierarchicalFairQueueing(self: *StreamScheduler) ?u64 {
        // Implement hierarchical fair queueing using stream dependency tree
        return self.selectFromTree(null); // Start from root streams
    }
    
    fn selectFromTree(self: *StreamScheduler, parent_stream_id: ?u64) ?u64 {
        var candidates = std.ArrayList(u64).init(self.allocator);
        defer candidates.deinit();
        
        // Find streams with the specified parent
        for (self.ready_streams.items) |stream_id| {
            if (self.streams.get(stream_id)) |stream_info| {
                if (stream_info.parent_stream_id == parent_stream_id) {
                    candidates.append(stream_id) catch continue;
                }
            }
        }
        
        if (candidates.items.len == 0) return null;
        
        // Select based on weights among siblings
        var total_weight: u64 = 0;
        for (candidates.items) |stream_id| {
            if (self.streams.get(stream_id)) |stream_info| {
                total_weight += stream_info.getEffectiveWeight();
            }
        }
        
        if (total_weight == 0) return candidates.items[0];
        
        // Weighted random selection
        const random_weight = std.crypto.random.uintLessThan(u64, total_weight);
        var cumulative_weight: u64 = 0;
        
        for (candidates.items) |stream_id| {
            if (self.streams.get(stream_id)) |stream_info| {
                cumulative_weight += stream_info.getEffectiveWeight();
                if (random_weight < cumulative_weight) {
                    return stream_id;
                }
            }
        }
        
        return candidates.items[candidates.items.len - 1];
    }
    
    pub fn recordStreamScheduled(self: *StreamScheduler, stream_id: u64, bytes_sent: u64) void {
        if (self.streams.getPtr(stream_id)) |stream_info| {
            stream_info.bytes_scheduled += bytes_sent;
            stream_info.last_scheduled = std.time.timestamp();
            
            // Update deficit for DRR
            if (self.algorithm == .deficit_round_robin) {
                stream_info.deficit -= @as(f64, @floatFromInt(bytes_sent));
            }
        }
    }
    
    pub fn getSchedulingStats(self: *const StreamScheduler) SchedulingStats {
        var stats = SchedulingStats{
            .algorithm = self.algorithm,
            .total_streams = self.streams.count(),
            .ready_streams = self.ready_streams.items.len,
            .blocked_streams = self.blocked_streams.items.len,
            .total_bytes_scheduled = 0,
        };
        
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            stats.total_bytes_scheduled += entry.value_ptr.bytes_scheduled;
        }
        
        return stats;
    }
    
    pub const SchedulingStats = struct {
        algorithm: SchedulingAlgorithm,
        total_streams: u32,
        ready_streams: usize,
        blocked_streams: usize,
        total_bytes_scheduled: u64,
    };
};

/// Comprehensive flow control manager
pub const FlowControlManager = struct {
    connection_flow_control: ConnectionFlowControl,
    stream_flow_controls: std.HashMap(u64, StreamFlowControl, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    scheduler: StreamScheduler,
    
    // Configuration
    initial_max_data: u64,
    initial_max_stream_data: u64,
    enable_adaptive_windows: bool,
    
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, initial_max_data: u64, initial_max_stream_data: u64, scheduling_algorithm: StreamScheduler.SchedulingAlgorithm) FlowControlManager {
        return FlowControlManager{
            .connection_flow_control = ConnectionFlowControl.init(initial_max_data),
            .stream_flow_controls = std.HashMap(u64, StreamFlowControl, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .scheduler = StreamScheduler.init(allocator, scheduling_algorithm),
            .initial_max_data = initial_max_data,
            .initial_max_stream_data = initial_max_stream_data,
            .enable_adaptive_windows = true,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *FlowControlManager) void {
        self.stream_flow_controls.deinit();
        self.scheduler.deinit();
    }
    
    pub fn addStream(self: *FlowControlManager, stream_id: u64, priority: StreamPriority) !void {
        const stream_fc = StreamFlowControl.init(stream_id, self.initial_max_stream_data);
        try self.stream_flow_controls.put(stream_id, stream_fc);
        try self.scheduler.addStream(stream_id, priority);
    }
    
    pub fn removeStream(self: *FlowControlManager, stream_id: u64) void {
        _ = self.stream_flow_controls.remove(stream_id);
        self.scheduler.removeStream(stream_id);
    }
    
    pub fn canSendOnStream(self: *FlowControlManager, stream_id: u64, bytes: u64) bool {
        // Check both connection and stream flow control
        if (!self.connection_flow_control.canSend(bytes)) {
            return false;
        }
        
        if (self.stream_flow_controls.getPtr(stream_id)) |stream_fc| {
            return stream_fc.canSend(bytes);
        }
        
        return false;
    }
    
    pub fn sendOnStream(self: *FlowControlManager, stream_id: u64, bytes: u64) !void {
        // Consume both connection and stream windows
        try self.connection_flow_control.consumeSendWindow(bytes);
        
        if (self.stream_flow_controls.getPtr(stream_id)) |stream_fc| {
            try stream_fc.consumeSendWindow(bytes);
            self.scheduler.recordStreamScheduled(stream_id, bytes);
            
            // Mark stream as blocked if it hits flow control limit
            if (!stream_fc.canSend(1)) {
                self.scheduler.markStreamBlocked(stream_id);
            }
        } else {
            return Error.ZquicError.StreamNotFound;
        }
    }
    
    pub fn receiveOnStream(self: *FlowControlManager, stream_id: u64, bytes: u64) !void {
        // Consume both connection and stream receive windows
        try self.connection_flow_control.consumeReceiveWindow(bytes);
        
        if (self.stream_flow_controls.getPtr(stream_id)) |stream_fc| {
            try stream_fc.consumeReceiveWindow(bytes);
        } else {
            return Error.ZquicError.StreamNotFound;
        }
    }
    
    pub fn updateStreamSendWindow(self: *FlowControlManager, stream_id: u64, new_max_data: u64) void {
        if (self.stream_flow_controls.getPtr(stream_id)) |stream_fc| {
            const was_blocked = !stream_fc.canSend(1);
            stream_fc.updateSendWindow(new_max_data);
            
            // Mark stream as ready if it was blocked and now unblocked
            if (was_blocked and stream_fc.canSend(1)) {
                self.scheduler.markStreamReady(stream_id);
            }
        }
    }
    
    pub fn updateConnectionSendWindow(self: *FlowControlManager, new_max_data: u64) void {
        self.connection_flow_control.updateSendWindow(new_max_data);
        
        // Unblock streams that may have been blocked by connection flow control
        for (self.scheduler.blocked_streams.items) |stream_id| {
            if (self.canSendOnStream(stream_id, 1)) {
                self.scheduler.markStreamReady(stream_id);
            }
        }
    }
    
    pub fn selectNextStreamToSend(self: *FlowControlManager) ?u64 {
        return self.scheduler.selectNextStream();
    }
    
    pub fn generateFlowControlUpdates(self: *FlowControlManager) ![]Frame {
        var frames = std.ArrayList(Frame).init(self.allocator);
        defer frames.deinit();
        
        // Check connection-level flow control
        if (self.connection_flow_control.shouldUpdateReceiveWindow()) {
            const frame = self.connection_flow_control.generateWindowUpdate();
            try frames.append(Frame{ .max_data = frame });
        }
        
        // Check stream-level flow control
        var iterator = self.stream_flow_controls.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.shouldUpdateReceiveWindow()) {
                const frame = entry.value_ptr.generateWindowUpdate();
                try frames.append(Frame{ .max_stream_data = frame });
            }
        }
        
        return frames.toOwnedSlice();
    }
    
    pub fn handleMaxDataFrame(self: *FlowControlManager, frame: MaxDataFrame) void {
        self.updateConnectionSendWindow(frame.maximum_data);
    }
    
    pub fn handleMaxStreamDataFrame(self: *FlowControlManager, frame: MaxStreamDataFrame) void {
        self.updateStreamSendWindow(frame.stream_id, frame.maximum_stream_data);
    }
    
    pub fn handleDataBlockedFrame(self: *FlowControlManager, frame: DataBlockedFrame) void {
        // Peer is blocked at connection level - consider increasing window
        if (self.enable_adaptive_windows) {
            const current_max = self.connection_flow_control.max_data_local;
            const new_max = @min(current_max * 2, current_max + 1024 * 1024 * 16); // Add up to 16MB
            self.connection_flow_control.max_data_local = new_max;
        }
        
        _ = frame;
    }
    
    pub fn handleStreamDataBlockedFrame(self: *FlowControlManager, frame: StreamDataBlockedFrame) void {
        // Peer is blocked at stream level - consider increasing window
        if (self.enable_adaptive_windows) {
            if (self.stream_flow_controls.getPtr(frame.stream_id)) |stream_fc| {
                const current_max = stream_fc.max_stream_data_local;
                const new_max = @min(current_max * 2, current_max + 1024 * 1024); // Add up to 1MB
                stream_fc.max_stream_data_local = new_max;
                stream_fc.receive_window = new_max;
            }
        }
    }
    
    pub fn getFlowControlStats(self: *const FlowControlManager) FlowControlStats {
        var stream_stats = std.ArrayList(StreamFlowControlStats).init(self.allocator);
        defer stream_stats.deinit();
        
        var iterator = self.stream_flow_controls.iterator();
        while (iterator.next()) |entry| {
            const stats = StreamFlowControlStats{
                .stream_id = entry.key_ptr.*,
                .send_window = entry.value_ptr.send_window,
                .receive_window = entry.value_ptr.receive_window,
                .bytes_sent = entry.value_ptr.bytes_sent,
                .bytes_received = entry.value_ptr.bytes_received,
                .is_blocked = entry.value_ptr.is_blocked,
                .utilization = entry.value_ptr.getUtilization(),
            };
            stream_stats.append(stats) catch continue;
        }
        
        return FlowControlStats{
            .connection_send_window = self.connection_flow_control.max_data_remote,
            .connection_receive_window = self.connection_flow_control.max_data_local,
            .connection_bytes_sent = self.connection_flow_control.bytes_sent,
            .connection_bytes_received = self.connection_flow_control.bytes_received,
            .connection_is_blocked = self.connection_flow_control.is_blocked,
            .stream_stats = stream_stats.toOwnedSlice() catch &[_]StreamFlowControlStats{},
            .scheduling_stats = self.scheduler.getSchedulingStats(),
        };
    }
    
    pub const FlowControlStats = struct {
        connection_send_window: u64,
        connection_receive_window: u64,
        connection_bytes_sent: u64,
        connection_bytes_received: u64,
        connection_is_blocked: bool,
        stream_stats: []const StreamFlowControlStats,
        scheduling_stats: StreamScheduler.SchedulingStats,
    };
    
    pub const StreamFlowControlStats = struct {
        stream_id: u64,
        send_window: u64,
        receive_window: u64,
        bytes_sent: u64,
        bytes_received: u64,
        is_blocked: bool,
        utilization: f64,
    };
};