//! Experimental QUIC VPN client demo
//!
//! Demonstrates how a client might build routes on the fly and consume the
//! Prometheus metrics emitted by the shared exporter.

const std = @import("std");
const zquic = @import("zquic");
const NetAddress = zquic.NetAddress;

comptime {
    if (!@hasDecl(zquic, "vpn") or !@hasDecl(zquic.vpn, "PacketRouter")) {
        @compileError("Build with -Dvpn=true to run the QUIC VPN demos.");
    }
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var router = zquic.vpn.PacketRouter.init(allocator, .{
        .enable_nat = false,
        .default_metric = 10,
    });
    defer router.deinit();

    var metrics = if (@hasDecl(zquic.monitoring, "PrometheusMetrics")) zquic.monitoring.PrometheusMetrics.init(allocator) else {};
    if (@hasDecl(zquic.monitoring, "PrometheusMetrics")) {
        router.attachPrometheus(&metrics);
    }

    const client_iface = try NetAddress.resolveIp("10.0.5.2", 0);
    try router.addInterface("ghostmesh-client0", client_iface, 1350);

    const exit_gateway = try NetAddress.resolveIp("100.64.0.1", 4433);
    const any_dest = try NetAddress.resolveIp("0.0.0.0", 0);
    const route_conn = try zquic.Packet.ConnectionId.init("client-demo");
    try router.addRoute(any_dest, exit_gateway, "ghostmesh-client0", route_conn);

    const payload = "client-probe";
    const local = try NetAddress.resolveIp("10.0.5.2", 4242);
    const remote = try NetAddress.resolveIp("192.0.2.99", 443);
    _ = try router.forwardPacket(payload, local, remote);

    if (@hasDecl(zquic.monitoring, "PrometheusMetrics")) {
        const metrics_blob = try metrics.render(allocator);
        defer allocator.free(metrics_blob);
        std.debug.print("Client metrics snapshot:\n{s}\n", .{metrics_blob});
    } else {
        std.debug.print("Client demo forwarded one packet; rebuild with -Dmonitoring=true for Prometheus output.\n", .{});
    }
}
