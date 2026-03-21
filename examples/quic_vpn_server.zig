//! Experimental QUIC-over-UDP VPN server demo
//!
//! Shows how to configure the PacketRouter, attach Prometheus metrics, and
//! forward a synthetic packet through the GhostMesh concept pipeline.

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

    std.debug.print("🔒 GhostMesh QUIC VPN — experimental concept\n", .{});

    var router = zquic.vpn.PacketRouter.init(allocator, .{
        .enable_nat = true,
        .max_routes = 32,
        .route_timeout_ms = 5 * 60 * 1000,
    });
    defer router.deinit();

    var metrics = zquic.monitoring.PrometheusMetrics.init(allocator);
    router.attachPrometheus(&metrics);

    const tunnel_interface = try std.net.Address.resolveIp("10.9.0.1", 0);
    try router.addInterface("ghostmesh0", tunnel_interface, 1400);

    const protected_subnet = try std.net.Address.resolveIp("10.42.0.0", 0);
    const peer_gateway = try std.net.Address.resolveIp("10.9.0.2", 4433);
    const route_conn = try zquic.Packet.ConnectionId.init("ghostmesh-demo");
    try router.addRoute(protected_subnet, peer_gateway, "ghostmesh0", route_conn);

    const packet = "hello-from-quic";
    const source = try std.net.Address.resolveIp("10.42.0.10", 5555);
    const destination = try std.net.Address.resolveIp("10.99.0.5", 8080);

    const forwarded = try router.forwardPacket(packet, source, destination);
    std.debug.print(
        "Forwarded {d} bytes from {any} -> {any} via {s} (next hop: {any})\n",
        .{ packet.len, forwarded.source, forwarded.destination, forwarded.interface, forwarded.next_hop },
    );

    const prom_snapshot = try metrics.render(allocator);
    defer allocator.free(prom_snapshot);
    std.debug.print("\n📈 Prometheus sample:\n{s}\n", .{prom_snapshot});

    std.debug.print("\n⚠️ Reminder: QUIC VPN support is experimental and not a Tailscale replacement yet.\n", .{});
}
