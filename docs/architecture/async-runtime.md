# Async Runtime Notes

ZQUIC no longer depends on zsync; the async runtime is fully in-tree under `src/async/`. Highlights:

- **Event Loop**: `async/runtime.zig` drives connection, stream, and timer progress using a poll loop tuned for QUIC workloads.
- **Timer Wheel**: `async/event_loop.zig` exposes microsecond timers for retransmits, PTO, and keep-alives.
- **Load Balancer**: `async/load_balancer.zig` helps multiplex connections across cores without external executors.

## Migrating from zsync
Earlier builds asked you to pull zsync into your project. With 0.9.3:
1. Remove any zsync dependency from your `build.zig`.
2. Use `zquic.AsyncRuntime` (re-exported from `src/core.zig`) to spin workers.
3. The runtime integrates tightly with the packet multiplexer, so HTTP/3/DoQ benefit automatically.

Example:
```zig
var runtime = zquic.AsyncRuntime.init(allocator, .{});
try runtime.spawn(.{ .task = myServerTask });
```

## Next Steps
- Expose a tutorial showing how to embed the runtime inside a service binary.
- Publish latency benchmarks comparing the in-tree runtime vs. zsync-era builds.
- Surface runtime stats via the Prometheus exporter once the scheduler metrics are finalized.
