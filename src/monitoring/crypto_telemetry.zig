//! Crypto-Focused Telemetry and Monitoring for ZQUIC
//!
//! Advanced monitoring system specifically designed for crypto/blockchain workloads
//! with real-time metrics, alerting, and performance analysis

const std = @import("std");
const Error = @import("../utils/error.zig");

/// Telemetry configuration for crypto workloads
pub const CryptoTelemetryConfig = struct {
    // Collection intervals
    metrics_collection_interval_ms: u64 = 1000, // 1 second for crypto
    performance_analysis_interval_ms: u64 = 5000, // 5 seconds
    health_check_interval_ms: u64 = 2000, // 2 seconds
    
    // Storage settings
    max_metric_history: u32 = 3600, // 1 hour at 1 second intervals
    enable_persistence: bool = true,
    metrics_file_path: ?[]const u8 = null,
    
    // Alert thresholds for crypto workloads
    latency_warning_threshold_us: u64 = 10_000, // 10ms warning
    latency_critical_threshold_us: u64 = 50_000, // 50ms critical
    loss_rate_warning_threshold: f32 = 0.01, // 1% warning
    loss_rate_critical_threshold: f32 = 0.05, // 5% critical
    throughput_warning_threshold_mbps: f32 = 10.0, // 10 Mbps minimum
    
    // Crypto-specific thresholds
    zero_rtt_success_rate_threshold: f32 = 0.8, // 80% minimum
    connection_establishment_threshold_us: u64 = 5000, // 5ms for new connections
    protocol_switch_threshold_us: u64 = 1000, // 1ms for protocol switching
    
    // Export settings
    enable_prometheus_export: bool = false,
    prometheus_port: u16 = 9090,
    enable_json_export: bool = true,
    enable_csv_export: bool = false,
};

/// Real-time performance metrics for crypto workloads
pub const CryptoPerformanceMetrics = struct {
    // Timestamp
    timestamp: i64,
    
    // Connection metrics
    total_connections: u32,
    active_connections: u32,
    connections_per_second: f32,
    connection_success_rate: f32,
    zero_rtt_success_rate: f32,
    
    // Latency metrics (microseconds)
    avg_latency_us: u64,
    min_latency_us: u64,
    max_latency_us: u64,
    p50_latency_us: u64,
    p95_latency_us: u64,
    p99_latency_us: u64,
    
    // Throughput metrics
    bytes_per_second: u64,
    packets_per_second: u64,
    requests_per_second: u64,
    bandwidth_utilization_percent: f32,
    
    // Quality metrics
    packet_loss_rate: f32,
    retransmission_rate: f32,
    congestion_window_avg: u64,
    rtt_variance_us: u64,
    
    // Crypto-specific metrics
    handshake_time_us: u64,
    post_quantum_usage_percent: f32,
    protocol_distribution: ProtocolDistribution,
    priority_distribution: PriorityDistribution,
    
    // Resource utilization
    cpu_usage_percent: f32,
    memory_usage_mb: u64,
    network_buffer_usage_percent: f32,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .timestamp = std.time.microTimestamp(),
            .total_connections = 0,
            .active_connections = 0,
            .connections_per_second = 0.0,
            .connection_success_rate = 1.0,
            .zero_rtt_success_rate = 1.0,
            .avg_latency_us = 0,
            .min_latency_us = std.math.maxInt(u64),
            .max_latency_us = 0,
            .p50_latency_us = 0,
            .p95_latency_us = 0,
            .p99_latency_us = 0,
            .bytes_per_second = 0,
            .packets_per_second = 0,
            .requests_per_second = 0,
            .bandwidth_utilization_percent = 0.0,
            .packet_loss_rate = 0.0,
            .retransmission_rate = 0.0,
            .congestion_window_avg = 0,
            .rtt_variance_us = 0,
            .handshake_time_us = 0,
            .post_quantum_usage_percent = 0.0,
            .protocol_distribution = ProtocolDistribution.init(),
            .priority_distribution = PriorityDistribution.init(),
            .cpu_usage_percent = 0.0,
            .memory_usage_mb = 0,
            .network_buffer_usage_percent = 0.0,
        };
    }
};

/// Protocol usage distribution
pub const ProtocolDistribution = struct {
    dns_over_quic_percent: f32,
    http3_percent: f32,
    grpc_over_quic_percent: f32,
    custom_protocol_percent: f32,
    
    pub fn init() @This() {
        return .{
            .dns_over_quic_percent = 0.0,
            .http3_percent = 0.0,
            .grpc_over_quic_percent = 0.0,
            .custom_protocol_percent = 0.0,
        };
    }
};

/// Priority level distribution
pub const PriorityDistribution = struct {
    critical_percent: f32,
    high_percent: f32,
    normal_percent: f32,
    background_percent: f32,
    
    pub fn init() @This() {
        return .{
            .critical_percent = 0.0,
            .high_percent = 0.0,
            .normal_percent = 0.0,
            .background_percent = 0.0,
        };
    }
};

/// Alert severity levels
pub const AlertSeverity = enum {
    info,
    warning,
    critical,
    emergency, // For trading/consensus critical issues
};

/// Alert information
pub const CryptoAlert = struct {
    id: u64,
    timestamp: i64,
    severity: AlertSeverity,
    category: []const u8,
    message: []const u8,
    metric_name: []const u8,
    current_value: f64,
    threshold_value: f64,
    suggested_action: ?[]const u8,
    
    const Self = @This();
    
    pub fn format(self: *const Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("[{}] {} - {s}: {s} (current: {d:.2}, threshold: {d:.2})", .{
            self.severity, self.timestamp, self.category, self.message, 
            self.current_value, self.threshold_value
        });
    }
};

/// Latency histogram for percentile calculations
pub const LatencyHistogram = struct {
    buckets: [20]u64, // Logarithmic buckets from 1us to 10s
    bucket_bounds: [20]u64,
    total_samples: u64,
    sum_latency: u64,
    
    const Self = @This();
    
    pub fn init() Self {
        var histogram = Self{
            .buckets = std.mem.zeroes([20]u64),
            .bucket_bounds = undefined,
            .total_samples = 0,
            .sum_latency = 0,
        };
        
        // Initialize logarithmic buckets (microseconds)
        histogram.bucket_bounds = [_]u64{
            1, 2, 5, 10, 20, 50, 100, 200, 500, 1000,
            2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000, 10000000
        };
        
        return histogram;
    }
    
    pub fn addSample(self: *Self, latency_us: u64) void {
        self.total_samples += 1;
        self.sum_latency += latency_us;
        
        // Find appropriate bucket
        for (self.bucket_bounds, 0..) |bound, i| {
            if (latency_us <= bound) {
                self.buckets[i] += 1;
                return;
            }
        }
        
        // If latency is higher than all buckets, add to last bucket
        self.buckets[self.buckets.len - 1] += 1;
    }
    
    pub fn getPercentile(self: *const Self, percentile: f32) u64 {
        if (self.total_samples == 0) return 0;
        
        const target_samples = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.total_samples)) * percentile / 100.0));
        var cumulative: u64 = 0;
        
        for (self.buckets, 0..) |bucket_count, i| {
            cumulative += bucket_count;
            if (cumulative >= target_samples) {
                return self.bucket_bounds[i];
            }
        }
        
        return self.bucket_bounds[self.bucket_bounds.len - 1];
    }
    
    pub fn getAverage(self: *const Self) u64 {
        if (self.total_samples == 0) return 0;
        return self.sum_latency / self.total_samples;
    }
    
    pub fn reset(self: *Self) void {
        self.buckets = std.mem.zeroes([20]u64);
        self.total_samples = 0;
        self.sum_latency = 0;
    }
};

/// Comprehensive telemetry system for crypto workloads
pub const CryptoTelemetrySystem = struct {
    config: CryptoTelemetryConfig,
    
    // Metrics storage
    current_metrics: CryptoPerformanceMetrics,
    metrics_history: std.ArrayList(CryptoPerformanceMetrics),
    
    // Latency tracking
    latency_histogram: LatencyHistogram,
    
    // Alert system
    active_alerts: std.ArrayList(CryptoAlert),
    alert_history: std.ArrayList(CryptoAlert),
    next_alert_id: std.atomic.Atomic(u64),
    
    // Collection state
    last_collection_time: i64,
    collection_counter: u64,
    
    // Real-time counters (atomic for thread safety)
    connection_count: std.atomic.Atomic(u32),
    request_count: std.atomic.Atomic(u64),
    bytes_transferred: std.atomic.Atomic(u64),
    error_count: std.atomic.Atomic(u64),
    zero_rtt_attempts: std.atomic.Atomic(u64),
    zero_rtt_successes: std.atomic.Atomic(u64),
    
    // Protocol counters
    doq_requests: std.atomic.Atomic(u64),
    http3_requests: std.atomic.Atomic(u64),
    grpc_requests: std.atomic.Atomic(u64),
    custom_requests: std.atomic.Atomic(u64),
    
    // Priority counters
    critical_requests: std.atomic.Atomic(u64),
    high_requests: std.atomic.Atomic(u64),
    normal_requests: std.atomic.Atomic(u64),
    background_requests: std.atomic.Atomic(u64),
    
    // Thread synchronization
    metrics_mutex: std.Thread.Mutex,
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, config: CryptoTelemetryConfig) Self {
        return Self{
            .config = config,
            .current_metrics = CryptoPerformanceMetrics.init(),
            .metrics_history = std.ArrayList(CryptoPerformanceMetrics).init(allocator),
            .latency_histogram = LatencyHistogram.init(),
            .active_alerts = std.ArrayList(CryptoAlert).init(allocator),
            .alert_history = std.ArrayList(CryptoAlert).init(allocator),
            .next_alert_id = std.atomic.Atomic(u64).init(1),
            .last_collection_time = std.time.microTimestamp(),
            .collection_counter = 0,
            .connection_count = std.atomic.Atomic(u32).init(0),
            .request_count = std.atomic.Atomic(u64).init(0),
            .bytes_transferred = std.atomic.Atomic(u64).init(0),
            .error_count = std.atomic.Atomic(u64).init(0),
            .zero_rtt_attempts = std.atomic.Atomic(u64).init(0),
            .zero_rtt_successes = std.atomic.Atomic(u64).init(0),
            .doq_requests = std.atomic.Atomic(u64).init(0),
            .http3_requests = std.atomic.Atomic(u64).init(0),
            .grpc_requests = std.atomic.Atomic(u64).init(0),
            .custom_requests = std.atomic.Atomic(u64).init(0),
            .critical_requests = std.atomic.Atomic(u64).init(0),
            .high_requests = std.atomic.Atomic(u64).init(0),
            .normal_requests = std.atomic.Atomic(u64).init(0),
            .background_requests = std.atomic.Atomic(u64).init(0),
            .metrics_mutex = std.Thread.Mutex{},
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.metrics_history.deinit();
        self.active_alerts.deinit();
        self.alert_history.deinit();
    }
    
    /// Record a request with protocol and priority tracking
    pub fn recordRequest(self: *Self, protocol: enum { doq, http3, grpc, custom }, priority: enum { critical, high, normal, background }, latency_us: u64, bytes: u64) void {
        _ = self.request_count.fetchAdd(1, .Monotonic);
        _ = self.bytes_transferred.fetchAdd(bytes, .Monotonic);
        
        // Record protocol usage
        switch (protocol) {
            .doq => _ = self.doq_requests.fetchAdd(1, .Monotonic),
            .http3 => _ = self.http3_requests.fetchAdd(1, .Monotonic),
            .grpc => _ = self.grpc_requests.fetchAdd(1, .Monotonic),
            .custom => _ = self.custom_requests.fetchAdd(1, .Monotonic),
        }
        
        // Record priority usage
        switch (priority) {
            .critical => _ = self.critical_requests.fetchAdd(1, .Monotonic),
            .high => _ = self.high_requests.fetchAdd(1, .Monotonic),
            .normal => _ = self.normal_requests.fetchAdd(1, .Monotonic),
            .background => _ = self.background_requests.fetchAdd(1, .Monotonic),
        }
        
        // Record latency
        self.metrics_mutex.lock();
        self.latency_histogram.addSample(latency_us);
        self.metrics_mutex.unlock();
        
        // Check for latency alerts
        if (latency_us > self.config.latency_critical_threshold_us) {
            self.raiseAlert(.critical, "Performance", "High latency detected", "latency", @as(f64, @floatFromInt(latency_us)), @as(f64, @floatFromInt(self.config.latency_critical_threshold_us)), "Check network conditions and server load");
        } else if (latency_us > self.config.latency_warning_threshold_us) {
            self.raiseAlert(.warning, "Performance", "Elevated latency detected", "latency", @as(f64, @floatFromInt(latency_us)), @as(f64, @floatFromInt(self.config.latency_warning_threshold_us)), "Monitor system performance");
        }
    }
    
    /// Record connection events
    pub fn recordConnection(self: *Self, connected: bool, zero_rtt_used: bool, zero_rtt_success: bool) void {
        if (connected) {
            _ = self.connection_count.fetchAdd(1, .Monotonic);
        } else {
            _ = self.connection_count.fetchSub(1, .Monotonic);
        }
        
        if (zero_rtt_used) {
            _ = self.zero_rtt_attempts.fetchAdd(1, .Monotonic);
            if (zero_rtt_success) {
                _ = self.zero_rtt_successes.fetchAdd(1, .Monotonic);
            }
        }
    }
    
    /// Record error event
    pub fn recordError(self: *Self, error_type: []const u8, severity: AlertSeverity) void {
        _ = self.error_count.fetchAdd(1, .Monotonic);
        
        if (severity == .critical or severity == .emergency) {
            self.raiseAlert(severity, "Error", error_type, "error_rate", 1.0, 0.0, "Investigate error cause immediately");
        }
    }
    
    /// Collect and update current metrics
    pub fn collectMetrics(self: *Self) !void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        
        const now = std.time.microTimestamp();
        const time_delta = now - self.last_collection_time;
        const time_delta_seconds = @as(f64, @floatFromInt(time_delta)) / 1_000_000.0;
        
        // Update current metrics
        self.current_metrics.timestamp = now;
        self.current_metrics.total_connections = self.connection_count.load(.Monotonic);
        self.current_metrics.active_connections = self.connection_count.load(.Monotonic); // Simplified
        
        // Calculate rates
        const requests_delta = self.request_count.load(.Monotonic) - (if (self.metrics_history.items.len > 0) 
            @as(u64, @intFromFloat(self.metrics_history.items[self.metrics_history.items.len - 1].requests_per_second * time_delta_seconds)) else 0);
        self.current_metrics.requests_per_second = @as(f32, @floatFromInt(requests_delta)) / @as(f32, @floatCast(time_delta_seconds));
        
        const bytes_delta = self.bytes_transferred.load(.Monotonic) - (if (self.metrics_history.items.len > 0)
            @as(u64, @intFromFloat(self.metrics_history.items[self.metrics_history.items.len - 1].bytes_per_second * time_delta_seconds)) else 0);
        self.current_metrics.bytes_per_second = @as(u64, @intFromFloat(@as(f64, @floatFromInt(bytes_delta)) / time_delta_seconds));
        
        // Update latency metrics from histogram
        self.current_metrics.avg_latency_us = self.latency_histogram.getAverage();
        self.current_metrics.p50_latency_us = self.latency_histogram.getPercentile(50);
        self.current_metrics.p95_latency_us = self.latency_histogram.getPercentile(95);
        self.current_metrics.p99_latency_us = self.latency_histogram.getPercentile(99);
        
        // Calculate Zero-RTT success rate
        const zero_rtt_attempts = self.zero_rtt_attempts.load(.Monotonic);
        if (zero_rtt_attempts > 0) {
            self.current_metrics.zero_rtt_success_rate = @as(f32, @floatFromInt(self.zero_rtt_successes.load(.Monotonic))) / @as(f32, @floatFromInt(zero_rtt_attempts));
        }
        
        // Calculate protocol distribution
        const total_protocol_requests = self.doq_requests.load(.Monotonic) + self.http3_requests.load(.Monotonic) + 
                                      self.grpc_requests.load(.Monotonic) + self.custom_requests.load(.Monotonic);
        if (total_protocol_requests > 0) {
            const total_f32 = @as(f32, @floatFromInt(total_protocol_requests));
            self.current_metrics.protocol_distribution.dns_over_quic_percent = @as(f32, @floatFromInt(self.doq_requests.load(.Monotonic))) / total_f32 * 100.0;
            self.current_metrics.protocol_distribution.http3_percent = @as(f32, @floatFromInt(self.http3_requests.load(.Monotonic))) / total_f32 * 100.0;
            self.current_metrics.protocol_distribution.grpc_over_quic_percent = @as(f32, @floatFromInt(self.grpc_requests.load(.Monotonic))) / total_f32 * 100.0;
            self.current_metrics.protocol_distribution.custom_protocol_percent = @as(f32, @floatFromInt(self.custom_requests.load(.Monotonic))) / total_f32 * 100.0;
        }
        
        // Calculate priority distribution
        const total_priority_requests = self.critical_requests.load(.Monotonic) + self.high_requests.load(.Monotonic) + 
                                      self.normal_requests.load(.Monotonic) + self.background_requests.load(.Monotonic);
        if (total_priority_requests > 0) {
            const total_f32 = @as(f32, @floatFromInt(total_priority_requests));
            self.current_metrics.priority_distribution.critical_percent = @as(f32, @floatFromInt(self.critical_requests.load(.Monotonic))) / total_f32 * 100.0;
            self.current_metrics.priority_distribution.high_percent = @as(f32, @floatFromInt(self.high_requests.load(.Monotonic))) / total_f32 * 100.0;
            self.current_metrics.priority_distribution.normal_percent = @as(f32, @floatFromInt(self.normal_requests.load(.Monotonic))) / total_f32 * 100.0;
            self.current_metrics.priority_distribution.background_percent = @as(f32, @floatFromInt(self.background_requests.load(.Monotonic))) / total_f32 * 100.0;
        }
        
        // Add to history
        try self.metrics_history.append(self.current_metrics);
        
        // Trim history if needed
        if (self.metrics_history.items.len > self.config.max_metric_history) {
            _ = self.metrics_history.orderedRemove(0);
        }
        
        // Check thresholds and raise alerts
        self.checkThresholds();
        
        // Reset histogram for next collection
        self.latency_histogram.reset();
        self.last_collection_time = now;
        self.collection_counter += 1;
        
        std.log.debug("Collected metrics: {} requests/sec, {} bytes/sec, {}us avg latency", .{
            self.current_metrics.requests_per_second,
            self.current_metrics.bytes_per_second,
            self.current_metrics.avg_latency_us,
        });
    }
    
    /// Check performance thresholds and raise alerts
    fn checkThresholds(self: *Self) void {
        const metrics = &self.current_metrics;
        
        // Check Zero-RTT success rate
        if (metrics.zero_rtt_success_rate < self.config.zero_rtt_success_rate_threshold) {
            self.raiseAlert(.warning, "Crypto", "Low Zero-RTT success rate", "zero_rtt_success_rate", 
                           metrics.zero_rtt_success_rate, self.config.zero_rtt_success_rate_threshold, 
                           "Check session ticket configuration and network conditions");
        }
        
        // Check packet loss rate
        if (metrics.packet_loss_rate > self.config.loss_rate_critical_threshold) {
            self.raiseAlert(.critical, "Network", "High packet loss rate", "packet_loss_rate", 
                           metrics.packet_loss_rate, self.config.loss_rate_critical_threshold, 
                           "Investigate network infrastructure");
        } else if (metrics.packet_loss_rate > self.config.loss_rate_warning_threshold) {
            self.raiseAlert(.warning, "Network", "Elevated packet loss rate", "packet_loss_rate", 
                           metrics.packet_loss_rate, self.config.loss_rate_warning_threshold, 
                           "Monitor network quality");
        }
        
        // Check throughput
        const throughput_mbps = @as(f32, @floatFromInt(metrics.bytes_per_second)) * 8.0 / 1_000_000.0;
        if (throughput_mbps < self.config.throughput_warning_threshold_mbps) {
            self.raiseAlert(.warning, "Performance", "Low throughput detected", "throughput_mbps", 
                           throughput_mbps, self.config.throughput_warning_threshold_mbps, 
                           "Check server capacity and network bandwidth");
        }
    }
    
    /// Raise an alert
    fn raiseAlert(self: *Self, severity: AlertSeverity, category: []const u8, message: []const u8, 
                  metric_name: []const u8, current_value: f64, threshold_value: f64, suggested_action: ?[]const u8) void {
        const alert = CryptoAlert{
            .id = self.next_alert_id.fetchAdd(1, .Monotonic),
            .timestamp = std.time.microTimestamp(),
            .severity = severity,
            .category = category,
            .message = message,
            .metric_name = metric_name,
            .current_value = current_value,
            .threshold_value = threshold_value,
            .suggested_action = suggested_action,
        };
        
        self.active_alerts.append(alert) catch |err| {
            std.log.err("Failed to add alert: {}", .{err});
            return;
        };
        
        self.alert_history.append(alert) catch |err| {
            std.log.err("Failed to add alert to history: {}", .{err});
        };
        
        // Log alert
        std.log.warn("ALERT: {}", .{alert});
        
        // For emergency alerts in crypto context
        if (severity == .emergency) {
            std.log.err("EMERGENCY ALERT: {}", .{alert});
            // In a real implementation, this would trigger immediate notifications
        }
    }
    
    /// Export metrics in JSON format
    pub fn exportJson(self: *const Self, writer: anytype) !void {
        try writer.writeAll("{");
        
        // Current metrics
        try writer.print("\"timestamp\":{},", .{self.current_metrics.timestamp});
        try writer.print("\"connections\":{{\"total\":{},\"active\":{}}},", .{
            self.current_metrics.total_connections, self.current_metrics.active_connections
        });
        
        // Performance metrics
        try writer.print("\"latency\":{{\"avg\":{},\"p50\":{},\"p95\":{},\"p99\":{}}},", .{
            self.current_metrics.avg_latency_us, self.current_metrics.p50_latency_us,
            self.current_metrics.p95_latency_us, self.current_metrics.p99_latency_us
        });
        
        try writer.print("\"throughput\":{{\"bytes_per_sec\":{},\"requests_per_sec\":{:.2}}},", .{
            self.current_metrics.bytes_per_second, self.current_metrics.requests_per_second
        });
        
        // Protocol distribution
        try writer.print("\"protocols\":{{\"doq\":{:.1},\"http3\":{:.1},\"grpc\":{:.1},\"custom\":{:.1}}},", .{
            self.current_metrics.protocol_distribution.dns_over_quic_percent,
            self.current_metrics.protocol_distribution.http3_percent,
            self.current_metrics.protocol_distribution.grpc_over_quic_percent,
            self.current_metrics.protocol_distribution.custom_protocol_percent,
        });
        
        // Zero-RTT metrics
        try writer.print("\"zero_rtt_success_rate\":{:.3},", .{self.current_metrics.zero_rtt_success_rate});
        
        // Active alerts
        try writer.writeAll("\"alerts\":[");
        for (self.active_alerts.items, 0..) |alert, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("{{\"id\":{},\"severity\":\"{}\",\"category\":\"{s}\",\"message\":\"{s}\",\"timestamp\":{}}}", .{
                alert.id, alert.severity, alert.category, alert.message, alert.timestamp
            });
        }
        try writer.writeAll("]");
        
        try writer.writeAll("}");
    }
    
    /// Get current performance summary
    pub fn getPerformanceSummary(self: *const Self) struct {
        total_connections: u32,
        requests_per_second: f32,
        avg_latency_us: u64,
        p99_latency_us: u64,
        zero_rtt_success_rate: f32,
        active_alerts_count: usize,
        throughput_mbps: f32,
        packet_loss_rate: f32,
    } {
        return .{
            .total_connections = self.current_metrics.total_connections,
            .requests_per_second = self.current_metrics.requests_per_second,
            .avg_latency_us = self.current_metrics.avg_latency_us,
            .p99_latency_us = self.current_metrics.p99_latency_us,
            .zero_rtt_success_rate = self.current_metrics.zero_rtt_success_rate,
            .active_alerts_count = self.active_alerts.items.len,
            .throughput_mbps = @as(f32, @floatFromInt(self.current_metrics.bytes_per_second)) * 8.0 / 1_000_000.0,
            .packet_loss_rate = self.current_metrics.packet_loss_rate,
        };
    }
};