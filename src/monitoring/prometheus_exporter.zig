//! Prometheus metrics exporter for ZQUIC runtimes
//!
//! Tracks high-value counters/gauges across HTTP/3, DoQ, and VPN components
//! and renders them using the Prometheus text-based exposition format.

const std = @import("std");
const build_options = @import("build_options");
const Time = @import("../utils/time.zig");

pub const PrometheusMetrics = struct {
    allocator: std.mem.Allocator,
    start_time: i64,

    http3_requests_total: std.atomic.Value(u64),
    http3_errors_total: std.atomic.Value(u64),
    http3_bytes_in_total: std.atomic.Value(u64),
    http3_bytes_out_total: std.atomic.Value(u64),
    http3_latency_total_us: std.atomic.Value(u64),
    http3_latency_samples: std.atomic.Value(u64),
    http3_connections_active: std.atomic.Value(i64),

    doq_queries_total: std.atomic.Value(u64),
    doq_failures_total: std.atomic.Value(u64),
    doq_bytes_in_total: std.atomic.Value(u64),
    doq_bytes_out_total: std.atomic.Value(u64),
    doq_connections_active: std.atomic.Value(i64),

    vpn_packets_forwarded_total: std.atomic.Value(u64),
    vpn_bytes_forwarded_total: std.atomic.Value(u64),
    vpn_routes_active: std.atomic.Value(u64),
    vpn_interfaces_active: std.atomic.Value(u64),
    vpn_nat_entries_active: std.atomic.Value(u64),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .start_time = Time.nowSeconds(),
            .http3_requests_total = std.atomic.Value(u64).init(0),
            .http3_errors_total = std.atomic.Value(u64).init(0),
            .http3_bytes_in_total = std.atomic.Value(u64).init(0),
            .http3_bytes_out_total = std.atomic.Value(u64).init(0),
            .http3_latency_total_us = std.atomic.Value(u64).init(0),
            .http3_latency_samples = std.atomic.Value(u64).init(0),
            .http3_connections_active = std.atomic.Value(i64).init(0),
            .doq_queries_total = std.atomic.Value(u64).init(0),
            .doq_failures_total = std.atomic.Value(u64).init(0),
            .doq_bytes_in_total = std.atomic.Value(u64).init(0),
            .doq_bytes_out_total = std.atomic.Value(u64).init(0),
            .doq_connections_active = std.atomic.Value(i64).init(0),
            .vpn_packets_forwarded_total = std.atomic.Value(u64).init(0),
            .vpn_bytes_forwarded_total = std.atomic.Value(u64).init(0),
            .vpn_routes_active = std.atomic.Value(u64).init(0),
            .vpn_interfaces_active = std.atomic.Value(u64).init(0),
            .vpn_nat_entries_active = std.atomic.Value(u64).init(0),
        };
    }

    pub fn recordHttp3ConnectionOpened(self: *Self) void {
        _ = self.http3_connections_active.fetchAdd(1, .acq_rel);
    }

    pub fn recordHttp3ConnectionClosed(self: *Self) void {
        _ = self.http3_connections_active.fetchSub(1, .acq_rel);
    }

    pub fn recordHttp3Request(self: *Self, bytes_in: usize, bytes_out: usize, latency_us: i64, success: bool) void {
        _ = self.http3_requests_total.fetchAdd(1, .acq_rel);
        _ = self.http3_bytes_in_total.fetchAdd(bytes_in, .acq_rel);
        _ = self.http3_bytes_out_total.fetchAdd(bytes_out, .acq_rel);
        _ = self.http3_latency_total_us.fetchAdd(@intCast(@max(latency_us, 0)), .acq_rel);
        _ = self.http3_latency_samples.fetchAdd(1, .acq_rel);
        if (!success) {
            _ = self.http3_errors_total.fetchAdd(1, .acq_rel);
        }
    }

    pub fn recordDoqConnectionOpened(self: *Self) void {
        _ = self.doq_connections_active.fetchAdd(1, .acq_rel);
    }

    pub fn recordDoqConnectionClosed(self: *Self) void {
        _ = self.doq_connections_active.fetchSub(1, .acq_rel);
    }

    pub fn recordDoqQuery(self: *Self, bytes_in: usize, bytes_out: usize, success: bool) void {
        _ = self.doq_queries_total.fetchAdd(1, .acq_rel);
        _ = self.doq_bytes_in_total.fetchAdd(bytes_in, .acq_rel);
        _ = self.doq_bytes_out_total.fetchAdd(bytes_out, .acq_rel);
        if (!success) {
            _ = self.doq_failures_total.fetchAdd(1, .acq_rel);
        }
    }

    pub fn recordVpnForward(self: *Self, bytes: usize) void {
        _ = self.vpn_packets_forwarded_total.fetchAdd(1, .acq_rel);
        _ = self.vpn_bytes_forwarded_total.fetchAdd(bytes, .acq_rel);
    }

    pub fn recordVpnSnapshot(self: *Self, route_count: usize, interface_count: u32, nat_entries: u32) void {
        self.vpn_routes_active.store(route_count, .release);
        self.vpn_interfaces_active.store(interface_count, .release);
        self.vpn_nat_entries_active.store(nat_entries, .release);
    }

    pub fn uptimeSeconds(self: *const Self) u64 {
        return @intCast(Time.nowSeconds() - self.start_time);
    }

    pub fn render(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.array_list.Managed(u8).init(allocator);
        errdefer buffer.deinit();

        try self.writeMetric(&buffer, "zquic_http3_requests_total", "counter", "Total HTTP/3 requests processed", self.http3_requests_total.load(.acquire));
        try self.writeMetric(&buffer, "zquic_http3_errors_total", "counter", "HTTP/3 request failures", self.http3_errors_total.load(.acquire));
        try self.writeMetric(&buffer, "zquic_http3_bytes_received_total", "counter", "HTTP/3 request payload bytes", self.http3_bytes_in_total.load(.acquire));
        try self.writeMetric(&buffer, "zquic_http3_bytes_sent_total", "counter", "HTTP/3 response payload bytes", self.http3_bytes_out_total.load(.acquire));

        const samples = self.http3_latency_samples.load(.acquire);
        const latency_sum = self.http3_latency_total_us.load(.acquire);
        const latency_avg = if (samples == 0) 0 else latency_sum / samples;
        try self.writeMetric(&buffer, "zquic_http3_latency_average_us", "gauge", "Average HTTP/3 latency (μs)", latency_avg);
        try self.writeMetric(&buffer, "zquic_http3_request_duration_us_sum", "counter", "Total HTTP/3 request latency in microseconds", latency_sum);
        try self.writeMetric(&buffer, "zquic_http3_request_duration_us_count", "counter", "HTTP/3 latency samples", samples);
        try self.writeMetric(&buffer, "zquic_http3_connections_active", "gauge", "Active HTTP/3 QUIC connections", @as(u64, @intCast(self.http3_connections_active.load(.acquire))));

        try self.writeMetric(&buffer, "zquic_doq_queries_total", "counter", "Total DNS-over-QUIC queries", self.doq_queries_total.load(.acquire));
        try self.writeMetric(&buffer, "zquic_doq_failures_total", "counter", "Failed DNS-over-QUIC queries", self.doq_failures_total.load(.acquire));
        try self.writeMetric(&buffer, "zquic_doq_bytes_received_total", "counter", "DNS-over-QUIC request bytes", self.doq_bytes_in_total.load(.acquire));
        try self.writeMetric(&buffer, "zquic_doq_bytes_sent_total", "counter", "DNS-over-QUIC response bytes", self.doq_bytes_out_total.load(.acquire));
        try self.writeMetric(&buffer, "zquic_doq_connections_active", "gauge", "Active DoQ connections", @as(u64, @intCast(self.doq_connections_active.load(.acquire))));

        try self.writeMetric(&buffer, "zquic_vpn_packets_forwarded_total", "counter", "Packets forwarded through the QUIC VPN router", self.vpn_packets_forwarded_total.load(.acquire));
        try self.writeMetric(&buffer, "zquic_vpn_bytes_forwarded_total", "counter", "Total bytes forwarded by the QUIC VPN router", self.vpn_bytes_forwarded_total.load(.acquire));
        try self.writeMetric(&buffer, "zquic_vpn_routes_active", "gauge", "Active VPN routes", self.vpn_routes_active.load(.acquire));
        try self.writeMetric(&buffer, "zquic_vpn_interfaces_active", "gauge", "Active VPN interfaces", self.vpn_interfaces_active.load(.acquire));
        try self.writeMetric(&buffer, "zquic_vpn_nat_entries_active", "gauge", "Active VPN NAT entries", self.vpn_nat_entries_active.load(.acquire));

        try self.writeMetric(&buffer, "zquic_metrics_uptime_seconds", "gauge", "Exporter uptime in seconds", self.uptimeSeconds());
        try self.writeInfoMetric(&buffer, "zquic_build_info", "Build metadata for this zquic exporter");

        return buffer.toOwnedSlice();
    }

    fn writeMetric(self: *const Self, buffer: *std.array_list.Managed(u8), name: []const u8, metric_type: []const u8, help: []const u8, value: anytype) !void {
        _ = self;
        try buffer.print("# HELP {s} {s}\n", .{ name, help });
        try buffer.print("# TYPE {s} {s}\n", .{ name, metric_type });
        try buffer.print("{s} {any}\n", .{ name, value });
    }

    fn writeInfoMetric(self: *const Self, buffer: *std.array_list.Managed(u8), name: []const u8, help: []const u8) !void {
        _ = self;
        try buffer.print("# HELP {s} {s}\n", .{ name, help });
        try buffer.print("# TYPE {s} gauge\n", .{name});
        try buffer.print("{s}{{version=\"{s}\",http3=\"{}\",doq=\"{}\",vpn=\"{}\",services=\"{}\",monitoring=\"{}\"}} 1\n", .{
            name,
            build_options.version,
            build_options.enable_http3,
            build_options.enable_doq,
            build_options.enable_vpn,
            build_options.enable_services,
            build_options.enable_monitoring,
        });
    }
};

test "prometheus exporter records metrics" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var metrics = PrometheusMetrics.init(allocator);
    metrics.recordHttp3ConnectionOpened();
    metrics.recordHttp3Request(128, 256, 42, true);
    metrics.recordDoqQuery(64, 64, false);
    metrics.recordVpnForward(512);
    metrics.recordVpnSnapshot(4, 2, 1);

    const output = try metrics.render(allocator);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "zquic_http3_requests_total 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "zquic_http3_request_duration_us_sum 42") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "zquic_http3_request_duration_us_count 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "zquic_doq_failures_total 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "zquic_vpn_routes_active 4") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "zquic_build_info{version=\"0.9.14\"") != null);
}
