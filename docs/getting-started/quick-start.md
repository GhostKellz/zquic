# Quick Start Guide

Get up and running with ZQUIC in minutes.

## Installation

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

## Building

```bash
# Default build (HTTP/3, DoQ enabled; PQ disabled)
zig build

# Installed binaries (feature flags permitting):
./zig-out/bin/zquic               # Core demo / toolkit
./zig-out/bin/zquic-server        # Core QUIC server
./zig-out/bin/zquic-client        # QUIC client
./zig-out/bin/zquic-http3-server  # HTTP/3 server with QPACK
./zig-out/bin/zquic-doq-server    # DNS-over-QUIC demo
```

## Build Options

Choose your features for optimal size and performance:

```bash
# Minimal build (~1.3 MB)
zig build -Dhttp3=false -Ddoq=false -Dservices=false -Dvpn=false

# Web server build (~3.5 MB)
zig build -Dhttp3=true -Ddoq=true

# Enterprise build (~5.5 MB)
zig build -Dservices=true -Dvpn=true -Dmonitoring=true

# With experimental post-quantum crypto
zig build -Dpost-quantum=true -Dexperimental-crypto=true
```

## Your First QUIC Server

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
    };

    // Create and start server
    var server = try zquic.Http3.Http3Server.init(allocator, config);
    defer server.deinit();

    // Add a simple route
    try server.get("/", handleHome);

    std.log.info("QUIC server starting on https://127.0.0.1:8080", .{});
    try server.start();
}

fn handleHome(req: *zquic.Http3.Request, res: *zquic.Http3.Response) !void {
    _ = req;
    try res.json(.{
        .message = "Hello, QUIC World!",
    });
}
```

Build and run:
```bash
zig build-exe hello_quic.zig --deps zquic
./hello_quic
```

### Adding Middleware

`Http3Server.use` wires middleware into the router chain:

```zig
const NextFn = zquic.Http3.NextFn;

const auth = struct {
    fn middleware(req: *zquic.Http3.Request, res: *zquic.Http3.Response, next: NextFn) !void {
        if (req.getHeader("authorization") == null) {
            res.setStatus(.unauthorized);
            try res.text("auth required");
            return;
        }
        try next(req, res);
    }
}.middleware;

try server.use(zquic.Http3.Middleware.LoggingMiddleware.init(allocator, .info).middleware());
try server.use(auth);
try server.router.getWithMiddleware("/secure", handleSecure, &.{auth});
```

## Your First QUIC Client

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
    };

    var client = try zquic.Client.init(allocator, config);
    defer client.deinit();

    // Make request
    const response = try client.get("/");
    defer response.deinit();

    std.log.info("Response: {s}", .{response.body});
}
```

## Post-Quantum Security (Experimental)

Post-quantum cryptography requires explicit build flags:

```bash
zig build -Dpost-quantum=true -Dexperimental-crypto=true
```

When enabled, ML-KEM-768 + X25519 hybrid key exchange is available. See [zcrypto Integration](../integrations/zcrypto.md) and [Feature Overview](../features/README.md) for the current experimental PQ posture.

## Next Steps

- **[Build Configuration](build-config.md)** - Customize your build
- **[API Reference](../api/core.md)** - Explore the full API
- **[Feature Overview](../features/README.md)** - Current module and feature map
- **[Future Features](../future-features.md)** - Scoped work deferred from the current release line

## Troubleshooting

### Build Issues
- Ensure you have Zig 0.17.0-dev.657+2faf8debf or later
- Check that zcrypto dependencies are available
- Try `rm -rf zig-cache .zig-cache` and rebuild

### Runtime Issues
- Verify port 8080 is available
- Check firewall settings for QUIC/UDP traffic

### Getting Help
- Check the [Examples](../examples/) directory
- Review [API Documentation](../api/)
- Open an issue on GitHub

---

## Recommended Workflow

```bash
# Format, build, and run tests
zig fmt src/ docs/ examples/
./dev/test.sh   # zig build test + integration-tests + fuzz-tests
```

## Zig 0.17 Migration Notes

Zig 0.17.0-dev introduced notable changes that ZQUIC follows:

- `std.ArrayList` is unmanaged by default - always pass an allocator
- Use `std.posix.clock_gettime()` for timing
- `std.io` moved under `std.Io`
- Temporary directories use `std.testing.tmpDir`

See `archive/ZIG_API_CHANGES.md` for a comprehensive checklist.
