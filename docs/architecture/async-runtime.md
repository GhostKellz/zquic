# Async Runtime Notes

ZQUIC's runtime implementation is in-tree under `src/async/` and does not
import zsync. The package metadata still retains a pinned zsync dependency
entry, so this is a source/runtime boundary rather than a zero-metadata-dependency
claim. Highlights:

- **Event Loop**: `async/runtime.zig` drives connection, stream, and timer progress using a poll loop tuned for QUIC workloads.
- **Timer Wheel**: `async/event_loop.zig` exposes microsecond timers for retransmits, PTO, and keep-alives.
- **Load Balancer**: `async/load_balancer.zig` helps multiplex connections across cores without external executors.

## Migrating from zsync
Earlier builds asked you to pull zsync into your project. With 0.9.3:
1. Remove any zsync dependency from your `build.zig`.
2. Use `zquic.AsyncRuntime.QuicRuntime` (re-exported from `src/core.zig`) for
   the in-tree UDP runtime.
3. Integrate protocol work explicitly with the runtime and packet multiplexer.

Example:
```zig
const address = try zquic.NetAddress.resolveIp("127.0.0.1", 4433);
var runtime = try zquic.AsyncRuntime.QuicRuntime.init(allocator, address, .{});
defer runtime.deinit();

// `run()` owns the blocking event-loop call; `stop()` ends it.
try runtime.run();
```

## Next Steps
- Expose a tutorial showing how to embed the runtime inside a service binary.
- Publish latency benchmarks comparing the in-tree runtime vs. zsync-era builds.
- Surface runtime stats via the Prometheus exporter once the scheduler metrics are finalized.
