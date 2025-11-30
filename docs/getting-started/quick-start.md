# Quick Start Guide

Get up and running with ZQUIC v0.9.3 in minutes!

## 🚀 Installation

### Method 1: Zig Package Manager (Recommended)

```bash
# Add ZQUIC to your project
zig fetch --save https://github.com/ghostkellz/zquic/archive/refs/heads/main.tar.gz
```

Add to your `build.zig.zon`:
```zig
.dependencies = .{
    .zquic = .{
        .url = "https://github.com/ghostkellz/zquic/archive/refs/heads/main.tar.gz",
        .hash = "1234...", // Auto-filled by zig fetch
    },
},
```

### Method 2: Git Clone

```bash
git clone https://github.com/ghostkellz/zquic
cd zquic
```

## 🔧 Building

```bash
# Build all working binaries
zig build

# Installed binaries (feature flags permitting):
./zig-out/bin/zquic               # Core demo / toolkit
./zig-out/bin/zquic-server        # Core QUIC server
./zig-out/bin/zquic-client        # QUIC client with PQ TLS
./zig-out/bin/zquic-http3-server  # HTTP/3 server with QPACK
./zig-out/bin/zquic-doq-server    # DNS-over-QUIC demo
./zig-out/bin/zquic-pq-demo       # Post-quantum crypto showcase
./zig-out/bin/crypto-trading-demo # High-frequency trading demo (services flag)
```

## 📦 Build Options

Choose your features for optimal size and performance:

```bash
# Minimal build (~1.5MB)
zig build -Dpost-quantum=false -Dservices=false -Dvpn=false

# Web server build (~3.5MB)
zig build -Dhttp3=true -Ddoq=true -Dpost-quantum=true

# Full enterprise build (~5.5MB) - default
zig build
```

## 🎯 Your First QUIC Server

Create `hello_quic.zig`:

```zig
const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Simple HTTP/3 server configuration
    const config = zquic.Http3.ServerConfig{
        .address = "127.0.0.1",
        .port = 8080,
        .max_connections = 1000,
        .enable_post_quantum = true,  // Quantum-safe by default
    };

    // Create and start server
    var server = try zquic.Http3.Http3Server.init(allocator, config);
    defer server.deinit();

    // Add a simple route
    try server.get("/", handleHome);
    
    std.log.info("🚀 QUIC server starting on https://127.0.0.1:8080");
    try server.start();
}

fn handleHome(req: *zquic.Http3.Request, res: *zquic.Http3.Response) !void {
    _ = req; // unused
    try res.json(.{
        .message = "Hello, QUIC World!",
        .version = "v0.9.3",
        .quantum_safe = true,
    });
}
```

Build and run:
```bash
zig build-exe hello_quic.zig --deps zquic
./hello_quic
```

### Adding Middleware

`Http3Server.use` wires middleware into the router chain, so you can run security filters, logging, or static file handlers before your route logic:

```zig
const NextFn = zquic.Http3.NextFn;

const auth = struct {
    fn middleware(req: *zquic.Http3.Request, res: *zquic.Http3.Response, next: NextFn) !void {
        if (req.getHeader("authorization") == null) {
            res.setStatus(.unauthorized);
            try res.text("auth required");
            return; // short-circuits the handler
        }
        try next(req, res);
    }
}.middleware;

try server.use(zquic.Http3.Middleware.LoggingMiddleware.init(allocator, .info).middleware());
try server.use(auth);
try server.router.getWithMiddleware("/secure", handleSecure, &.{auth});
```

Route-specific middleware can be attached with `router.getWithMiddleware` (or `addRouteMiddleware` later) to keep per-route logic isolated.

> Middleware chain guarantee: the router now routes unmatched requests through the global middleware stack before responding with 404, so logging/auth/static handlers still execute even when no route matches.

## 🌐 Your First QUIC Client

Create `hello_client.zig`:

```zig
const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Connect to QUIC server
    const config = zquic.ClientConfig{
        .server_address = "127.0.0.1",
        .server_port = 8080,
        .enable_post_quantum = true,
    };

    var client = try zquic.Client.init(allocator, config);
    defer client.deinit();

    // Make request
    const response = try client.get("/");
    defer response.deinit();

    std.log.info("Response: {s}", .{response.body});
}
```

## 🔐 Post-Quantum Security

ZQUIC includes post-quantum cryptography by default:

```zig
const config = zquic.Http3.ServerConfig{
    .enable_post_quantum = true,  // ML-KEM-768 + X25519 hybrid
    .pq_algorithms = .{
        .key_exchange = .ml_kem_768,
        .signatures = .slh_dsa_128f,
        .fallback_to_classical = true,
    },
};
```

## 📚 Next Steps

- **[Build Configuration](build-config.md)** - Customize your build
- **[API Reference](../api/core.md)** - Explore the full API
- **[Examples](../examples/)** - More detailed examples
- **[Production Guide](../guides/production.md)** - Deploy to production

## 🆘 Troubleshooting

### Build Issues
- Ensure you have Zig v0.16.0-dev or later
- Check that zcrypto dependencies are available
- Try `zig build clean` and rebuild

### Runtime Issues
- Verify port 8080 is available
- Check firewall settings for QUIC/UDP traffic
- Enable debug logging with `-Ddebug=true`

### Getting Help
- Check the [Examples](../examples/) directory
- Review [API Documentation](../api/)
- Open an issue on GitHub

---

## 🧪 Recommended Workflow

```bash
# Format, build, and run tests the way CI does
./dev/fmt.sh
./dev/test.sh   # zig build test + integration-tests + fuzz-tests
```

**🎉 Congratulations!** You now have a quantum-safe QUIC server running with ZQUIC v0.9.3!

## ⚙️ Zig 0.16 Migration Notes

Zig 0.16.0-dev introduced a few notable changes that ZQUIC now follows:

- `std.ArrayList` is unmanaged by default. Always pass an allocator to `append`, `appendSlice`, `resize`, and `deinit` (see `archive/ZIG_API_CHANGES.md`).
- Writer helpers like `.writer()` were removed for unmanaged lists—use helper functions that call `append`/`appendSlice` instead.
- Time utilities prefer `std.time.Instant`/`std.time.Timer` over `nanoTimestamp`.
- `std.io` moved under `std.Io`; swap legacy `std.io.Writer`/`Reader` helpers for the new `std.Io.Writer`/`Reader` interfaces and adopt `takeInt`, `takeByte`, `readSliceAll`, etc.
- Temporary directories/files now use `std.testing.tmpDir` (no allocator argument) and the new `std.fs.Dir.writeFile(.{ .data = ..., .flags = .{} })` options struct.

If you are upgrading existing code, start by reviewing `archive/ZIG_API_CHANGES.md` for a comprehensive checklist before rebuilding with `zig build test`.