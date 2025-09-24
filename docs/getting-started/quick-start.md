# Quick Start Guide

Get up and running with ZQUIC v0.9.0-RC1 in minutes!

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

# Working binaries ready for production:
./zig-out/bin/client              # QUIC client with post-quantum TLS
./zig-out/bin/server              # QUIC server with async processing
./zig-out/bin/doq_echo_server     # DNS-over-QUIC echo server
./zig-out/bin/http3_server        # HTTP/3 server with QPACK
./zig-out/bin/crypto_trading_demo # High-frequency trading demo
./zig-out/bin/pq_quic_demo       # Post-quantum cryptography demo
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
        .version = "v0.9.0-RC1",
        .quantum_safe = true 
    });
}
```

Build and run:
```bash
zig build-exe hello_quic.zig --deps zquic
./hello_quic
```

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

**🎉 Congratulations!** You now have a quantum-safe QUIC server running with ZQUIC v0.9.0-RC1!