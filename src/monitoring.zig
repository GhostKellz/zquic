//! ZQUIC Monitoring Feature Module
//!
//! Provides performance monitoring and telemetry for ZQUIC.
//! Only included when the 'monitoring' feature is enabled.

const std = @import("std");
const zquic_core = @import("zquic_core");
const zcrypto = @import("zcrypto");

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
        _ = allocator;
        _ = config;
        // Implementation would create and start metrics collection
        return undefined;
    }

    /// Export metrics in Prometheus format
    pub fn exportPrometheusMetrics(allocator: std.mem.Allocator, collector: *CryptoTelemetry) ![]const u8 {
        _ = allocator;
        _ = collector;
        // Implementation would format metrics for Prometheus
        return undefined;
    }

    pub fn snapshotPrometheus(metrics: *PrometheusMetrics, allocator: std.mem.Allocator) ![]u8 {
        return metrics.render(allocator);
    }

    /// Get current performance snapshot
    pub fn getPerformanceSnapshot(allocator: std.mem.Allocator) !PerformanceSnapshot {
        _ = allocator;
        // Implementation would capture current performance metrics
        return undefined;
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
