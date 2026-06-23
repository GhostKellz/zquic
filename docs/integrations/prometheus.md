# Prometheus Integration

ZQUIC 0.9.15 ships with a native Prometheus exporter (`src/monitoring/prometheus_exporter.zig`). Attach it to HTTP/3 servers, DoQ servers, or the QUIC VPN router to expose metrics for your scrape jobs.

## Quick Start
```zig
const zquic = @import("zquic");
var metrics = zquic.monitoring.PrometheusMetrics.init(allocator);

var http_server = try zquic.Http3.Http3Server.init(allocator, .{});
http_server.attachPrometheus(&metrics);

var doq_server = try zquic.DoQ.DoQServer.init(allocator, config);
doq_server.attachPrometheus(&metrics);

var router = zquic.vpn.PacketRouter.init(allocator, .{});
router.attachPrometheus(&metrics);
```
Render the snapshot and hand it to your HTTP control plane:
```zig
const payload = try metrics.render(allocator);
// Serve `payload` via your admin endpoint or write it to stdout for scraping
```

## Metric Reference
| Metric | Type | Description |
|--------|------|-------------|
| `zquic_http3_requests_total` | counter | Successful HTTP/3 responses |
| `zquic_http3_errors_total` | counter | HTTP/3 responses with status ≥ 500 |
| `zquic_http3_latency_average_us` | gauge | Mean latency derived from per-request samples |
| `zquic_http3_request_duration_us_sum` | counter | Sum of observed HTTP/3 request latency |
| `zquic_http3_request_duration_us_count` | counter | Count of observed HTTP/3 request latency samples |
| `zquic_http3_bytes_{received,sent}_total` | counter | Payload ingress/egress bytes |
| `zquic_http3_connections_active` | gauge | Currently registered QUIC conns |
| `zquic_http3_streams_active` | gauge | Active HTTP/3 streams |
| `zquic_http3_queue_depth` | gauge | HTTP/3 queued work items |
| `zquic_http3_status_{2xx,3xx,4xx,5xx}_total` | counter | HTTP/3 response status families |
| `zquic_doq_queries_total` | counter | Total DoQ queries processed |
| `zquic_doq_failures_total` | counter | Handler/parse failures |
| `zquic_doq_bytes_{received,sent}_total` | counter | DNS payload accounting |
| `zquic_doq_connections_active` | gauge | Active DoQ sessions |
| `zquic_doq_response_{noerror,nxdomain,servfail}_total` | counter | DoQ response code families |
| `zquic_quic_packet_loss_total` | counter | QUIC packets declared lost |
| `zquic_quic_retransmits_total` | counter | QUIC packet retransmissions |
| `zquic_handshake_failures_total` | counter | QUIC/TLS handshake failures |
| `zquic_key_updates_total` | counter | QUIC packet-protection key updates |
| `zquic_zero_rtt_rejected_total` | counter | Rejected 0-RTT attempts |
| `zquic_bad_transport_parameters_total` | counter | Rejected transport parameter sets |
| `zquic_retry_events_total` | counter | Retry events |
| `zquic_stateless_reset_events_total` | counter | Stateless reset events |
| `zquic_vpn_packets_forwarded_total` | counter | Packets forwarded through `PacketRouter` |
| `zquic_vpn_bytes_forwarded_total` | counter | Byte-level VPN throughput |
| `zquic_vpn_{routes,interfaces,nat}_active` | gauge | Routing table state |
| `zquic_metrics_uptime_seconds` | gauge | Exporter uptime |
| `zquic_build_info{...}` | gauge | Version and build-flag labels |

Metric names are intentionally stable and module-prefixed. Labels are kept to
low-cardinality build metadata for now; request paths, client addresses, and DNS
names should not be exported as labels.

## Scrape Example
Expose the exporter through your own admin HTTP endpoint (or embed it directly into the HTTP/3 router) and configure Prometheus:
```yaml
scrape_configs:
  - job_name: "zquic"
    static_configs:
      - targets: ["lab-gateway:9900"]
```

## Tips
- Share a single exporter across modules to gather a holistic view of the stack.
- The exporter is allocation-free after initialization; rendering builds a temporary buffer you own.
- Pair with `./dev/vpn_smoke.sh` or the HTTP/3 example to ensure metrics stay green before pushing to CI.
