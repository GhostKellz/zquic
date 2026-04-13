# Async Runtime: Why zquic Has No External Async Dependency

## The Short Version

ZQUIC has **one external dependency**: [zcrypto](https://github.com/ghostkellz/zcrypto) for cryptographic operations. That's it.

We used to depend on zsync for async I/O, but that's gone. The async runtime is now built directly into zquic.

## Why We Moved Away from zsync

When zquic was younger, we pulled in zsync as an async executor. It worked, but it created problems:

1. **Dependency churn** - zsync had its own release cycle, API changes, and bugs. Every zsync update was a potential breaking change for zquic.

2. **Version conflicts** - Users embedding zquic in larger projects could hit diamond dependency issues if they also used zsync (or something that depended on zsync).

3. **Debugging complexity** - When something broke in the async layer, you had to understand two codebases. Stack traces crossed library boundaries.

4. **Build complexity** - More dependencies means more things that can fail during `zig fetch`, more cache invalidation, more CI flakiness.

For a library like zquic, minimizing dependencies isn't just nice-to-have. It's critical for adoption and maintenance.

## What We Built Instead

The async runtime lives in `src/async/` and consists of:

### Event Loop (`event_loop.zig`)

A simple poll-based event loop using `std.posix.poll()`:

```zig
pub const EventLoop = struct {
    handlers: std.AutoHashMapUnmanaged(posix.fd_t, EventHandler),
    poll_fds: std.ArrayListUnmanaged(posix.pollfd),
    running: bool,
    allocator: std.mem.Allocator,
    // ...
};
```

- Registers file descriptors for read/write/error events
- Dispatches callbacks when events fire
- No threads, no fancy schedulers - just poll() in a loop

### Timer Wheel (`event_loop.zig`)

QUIC needs precise timers for retransmission timeouts (RTO), probe timeouts (PTO), and idle timeouts:

```zig
pub const TimerWheel = struct {
    slots: [WHEEL_SIZE]std.ArrayListUnmanaged(Timer),
    current_slot: usize,
    resolution_ms: u64,
    // ...
};
```

- O(1) timer insertion and expiration
- Configurable resolution (default: 1ms)
- Handles thousands of concurrent timers efficiently

### Runtime (`runtime.zig`)

Ties everything together:

```zig
pub const QuicRuntime = struct {
    event_loop: EventLoop,
    timer_wheel: TimerWheel,
    multiplexer: ?*UdpMultiplexer,
    connection_pool: ?*ConnectionPool,
    config: QuicRuntimeConfig,
    stats: RuntimeStats,
    // ...
};
```

- Manages the event loop lifecycle
- Optional connection pooling for high-throughput scenarios
- Statistics tracking (connections, packets, bytes)

### Load Balancer (`load_balancer.zig`)

For multi-backend scenarios:

- Round-robin, least-connections, weighted, latency-based strategies
- Circuit breaker pattern for backend health
- Per-backend connection pooling

## Design Principles

### 1. No Hidden Allocations

Every struct that allocates takes an explicit `std.mem.Allocator`. No global allocators, no hidden heap usage. You control memory.

### 2. Poll-Based, Not Epoll-Only

We use `poll()` instead of `epoll`/`kqueue` for maximum portability. Yes, epoll scales better at 100K+ connections. But poll() works everywhere and is simpler to reason about. For most deployments, it's plenty fast.

### 3. Callbacks, Not Async/Await

Zig's async/await is powerful but adds complexity. Our event loop uses simple callbacks:

```zig
pub const EventCallback = *const fn (
    fd: posix.fd_t,
    event_type: EventType,
    user_data: ?*anyopaque
) void;
```

This is explicit, debuggable, and doesn't require understanding Zig's async frame machinery.

### 4. Everything Is Optional

Connection pooling? Optional. Load balancing? Optional. You can use just the event loop and timer wheel if that's all you need.

## What About zcrypto?

zcrypto remains as the sole external dependency because:

1. **Crypto is hard** - Rolling your own ML-KEM-768, X25519, AES-GCM, ChaCha20-Poly1305, etc. is a security footgun.

2. **zcrypto is maintained** - It's part of the same ecosystem, with aligned release cycles.

3. **It's optional-ish** - If you disable post-quantum features (`-Dpost-quantum=false`), you still need zcrypto for TLS, but the dependency is minimal.

The difference between zcrypto and zsync: crypto primitives are stable algorithms with known test vectors. An async runtime is an architectural choice that affects how your entire codebase is structured.

## Migration from zsync

If you were using zquic with zsync, the migration is straightforward:

**Before (with zsync):**
```zig
const zsync = @import("zsync");
var runtime = zsync.Runtime.init(allocator);
// ... use zsync APIs
```

**After (native):**
```zig
const zquic = @import("zquic");
var runtime = zquic.AsyncRuntime.init(allocator, config);
// ... runtime manages its own event loop
```

The `QuicRuntime` handles event loop creation internally. You don't need to wire up an external executor.

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Timer resolution | 1ms default (configurable) |
| Max connections per runtime | Configurable, tested to 10K+ |
| Event dispatch overhead | ~1-2μs per event |
| Memory per connection | ~2-4KB baseline |

For most QUIC workloads (HTTP/3 servers, DoQ resolvers, VPN tunnels), this is more than sufficient.

## When You Might Want More

If you're building something that needs:

- **io_uring** for zero-copy kernel bypass
- **True multi-threaded scheduling** with work stealing
- **Millions of connections** on a single machine

...then you might outgrow this runtime. But at that point, you're probably also customizing everything else. The modular design means you can replace `src/async/` with your own implementation.

## Summary

| Aspect | With zsync (legacy) | Current |
|--------|---------------------|---------|
| External deps | zsync + zcrypto | zcrypto only |
| Async model | zsync executor | Built-in poll loop |
| Timer handling | zsync timers | Native timer wheel |
| Complexity | Two codebases | One codebase |
| Debug story | Cross-library | Single library |

Less dependencies = less breakage = more stability.

That's the philosophy.
