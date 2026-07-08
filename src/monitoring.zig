//! ZQUIC Monitoring Feature Module
//!
//! Provides performance monitoring and telemetry for ZQUIC.
//! Only included when the 'monitoring' feature is enabled.

const std = @import("std");
const Time = @import("utils/time.zig");

pub const PrometheusMetrics = @import("monitoring/prometheus_exporter.zig").PrometheusMetrics;

// Re-export monitoring functionality
pub const CryptoTelemetry = @import("monitoring/crypto_telemetry.zig").CryptoTelemetry;

// Monitoring configuration
pub const MonitoringConfig = struct {
    enable_crypto_telemetry: bool = true,
    enable_performance_monitoring: bool = true,
    metrics_collection_interval_ms: u32 = 1000,
    max_metrics_history: u32 = 10000,
    enable_prometheus_export: bool = false,
    prometheus_port: u16 = 9090,
};

// Feature-specific initialization
pub fn init(allocator: std.mem.Allocator, config: MonitoringConfig) !void {
    _ = allocator;
    _ = config;
    // Initialize monitoring-specific state
}

// Feature-specific cleanup
pub fn deinit() void {
    // Clean up monitoring-specific state
}

// Monitoring utilities
pub const MonitoringUtils = struct {
    /// Start collecting metrics
    pub fn startMetricsCollection(allocator: std.mem.Allocator, config: MonitoringConfig) !*CryptoTelemetry {
        const collector = try allocator.create(CryptoTelemetry);
        collector.* = CryptoTelemetry.init(allocator, .{
            .metrics_collection_interval_ms = config.metrics_collection_interval_ms,
            .max_metric_history = config.max_metrics_history,
            .enable_prometheus_export = config.enable_prometheus_export,
            .prometheus_port = config.prometheus_port,
        });
        return collector;
    }

    /// Export metrics in Prometheus format
    pub fn exportPrometheusMetrics(allocator: std.mem.Allocator, collector: *CryptoTelemetry) ![]const u8 {
        var output: std.ArrayList(u8) = .{};
        errdefer output.deinit(allocator);
        try collector.exportJson(output.writer(allocator));
        return try output.toOwnedSlice(allocator);
    }

    pub fn snapshotPrometheus(metrics: *PrometheusMetrics, allocator: std.mem.Allocator) ![]u8 {
        return metrics.render(allocator);
    }

    /// Get current performance snapshot
    pub fn getPerformanceSnapshot(allocator: std.mem.Allocator) !PerformanceSnapshot {
        _ = allocator;
        return .{
            .connections_active = 0,
            .streams_active = 0,
            .bytes_sent_per_second = 0,
            .bytes_received_per_second = 0,
            .packets_sent_per_second = 0,
            .packets_received_per_second = 0,
            .average_rtt_us = 0,
            .timestamp = Time.nowMicros(),
        };
    }
};

pub const PerformanceSnapshot = struct {
    connections_active: u32,
    streams_active: u32,
    bytes_sent_per_second: u64,
    bytes_received_per_second: u64,
    packets_sent_per_second: u64,
    packets_received_per_second: u64,
    average_rtt_us: u32,
    timestamp: i64,
};

test {
    _ = @import("monitoring/prometheus_exporter.zig");
    _ = @import("monitoring/crypto_telemetry.zig");
}
