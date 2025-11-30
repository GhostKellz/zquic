# QUIC VPN (GhostMesh) — Experimental Concept

> **Status:** Research preview. The QUIC/UDP VPN router is **not** intended to replace Tailscale/NetBird/WireGuard today. It exists so we can prototype QUIC-native tunnels, policy hooks, and telemetry.

## Architecture Snapshot
- `PacketRouter` owns a routing table, NAT table, and interface registry.
- Interfaces are lightweight (`VpnInterface`) records that describe MTU, local address, and stats.
- Every forwarded packet can optionally be mirrored into Prometheus via `PrometheusMetrics.recordVpnForward`.
- Route/Interface/NAT counts are exposed as gauges and update whenever the router mutates state.

```
Client UDP Socket ─▶ QUIC Conn ─▶ PacketRouter ─▶ Interface (ghostmesh0)
                                  │
                                  ├─ NAT table (optional)
                                  └─ Next-hop (tunnel peer)
```

## Getting Started
1. Enable the VPN + monitoring features: `zig build -Dvpn=true -Dmonitoring=true`.
2. Run the installed demo binaries from `zig-out/bin/`:
   ```bash
   ./zig-out/bin/quic-vpn-server-demo --demo
   ./zig-out/bin/quic-vpn-client-demo --demo
   ```
3. For a quick smoke test use `./dev/vpn_smoke.sh` (builds with the right flags and dumps metrics automatically).

## Metrics & Telemetry
Attach the exporter and let the router keep gauges fresh:
```zig
var metrics = zquic.monitoring.PrometheusMetrics.init(allocator);
router.attachPrometheus(&metrics);
// ... after manipulating routes/interfaces ...
const payload = try metrics.render(allocator);
```
Exposed metrics include:
- `zquic_vpn_packets_forwarded_total`
- `zquic_vpn_bytes_forwarded_total`
- `zquic_vpn_routes_active`
- `zquic_vpn_interfaces_active`
- `zquic_vpn_nat_entries_active`

## Production Checklist
- [ ] Replace the placeholder NAT mapping with a proper pool allocator.
- [ ] Add ACL/policy evaluation hooks before `forwardPacket` returns.
- [ ] Bind router decisions to QUIC connection lifecycles.
- [ ] Integrate with actual QUIC sockets instead of the synthetic demo packets.

Until the above is complete, treat the VPN module as a blueprint for QUIC/UDP mesh research rather than a hardened overlay network.
