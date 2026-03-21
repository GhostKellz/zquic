//! Experimental QUIC VPN client demo
//!
//! Demonstrates how a client might build routes on the fly and consume the
//! Prometheus metrics emitted by the shared exporter.

const std = @import("std");
const zquic = @import("zquic");

comptime {
    if (!@hasDecl(zquic, "vpn") or !@hasDecl(zquic.vpn, "PacketRouter")) {
        @compileError("Build with -Dvpn=true to run the QUIC VPN demos.");
    }
    if (!@hasDecl(zquic, "monitoring") or !@hasDecl(zquic.monitoring, "PrometheusMetrics")) {
        @compileError("Build with -Dmonitoring=true to expose Prometheus metrics.");
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

    var metrics = zquic.monitoring.PrometheusMetrics.init(allocator);
    router.attachPrometheus(&metrics);

    const client_iface = try std.net.Address.resolveIp("10.0.5.2", 0);
    try router.addInterface("ghostmesh-client0", client_iface, 1350);

    const exit_gateway = try std.net.Address.resolveIp("100.64.0.1", 4433);
    const any_dest = try std.net.Address.resolveIp("0.0.0.0", 0);
    const route_conn = try zquic.Packet.ConnectionId.init("client-demo");
    try router.addRoute(any_dest, exit_gateway, "ghostmesh-client0", route_conn);

    const payload = "client-probe";
    const local = try std.net.Address.resolveIp("10.0.5.2", 4242);
    const remote = try std.net.Address.resolveIp("192.0.2.99", 443);
    _ = try router.forwardPacket(payload, local, remote);

    const metrics_blob = try metrics.render(allocator);
    defer allocator.free(metrics_blob);
    std.debug.print("Client metrics snapshot:\n{s}\n", .{metrics_blob});
}
