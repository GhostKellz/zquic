# ZQUIC — Minimal QUIC/HTTP3 Library for Zig

[![Zig](https://img.shields.io/badge/Zig-0.15.0--dev-orange.svg)](https://ziglang.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

zquic is a lightweight, high-performance QUIC (HTTP/3 transport layer) implementation written in pure Zig. Designed for use in embedded systems, VPN stacks (like GhostMesh), decentralized services, and ultra-fast proxies (e.g., wraith), zquic offers a focused, dependency-free core.

## ⚙️ Purpose

- 🧪 Provide a Zig-native QUIC protocol implementation
- 🚀 Power libraries, proxies, and L7-aware services  
- 🌐 Serve as a transport layer for secure tunnels, APIs, and crypto nodes
- 🔧 Enable modern networking for embedded and high-performance applications

## ✨ Features

- **Full QUIC transport**: handshake, streams, encryption
- **HTTP/3 framing support**: frame parsing, serialization, and processing
- **TLS 1.3 handshake** with custom crypto backend
- **Built for async networking** (cooperates with tokioz, zvm-net)
- **Configurable congestion control** (CC) and retransmission logic
- **IPv6 and NAT traversal** considerations
- **Minimal allocations**, deterministic memory model
- **Zero-copy operations** where possible for maximum performance

## 🔍 Why Zig?

- **Manual memory management** for performance + predictability
- **Compile-time safety** with low runtime cost  
- **Works well** in high-performance and embedded networking environments
- **No hidden allocations** or runtime overhead
- **Cross-platform** support with consistent behavior

## � Quick Start

### Building

```bash
# Clone the repository
git clone <your-repo-url>
cd zquic

# Build the library and examples
zig build

# Run tests
zig build test

# Install executables (optional)
zig build install
```

### Basic Usage

```zig
const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a QUIC connection
    const conn_id = zquic.Packet.ConnectionId{ .data = [_]u8{1, 2, 3, 4} };
    var connection = zquic.Connection.Connection.init(allocator, .client, conn_id);
    defer connection.deinit();

    // Initialize flow control
    var flow_controller = zquic.FlowControl.FlowController.init(allocator, 1024 * 1024, 1024 * 1024);
    defer flow_controller.deinit();

    std.debug.print("ZQUIC connection initialized!\n", .{});
}
```

## 📦 Architecture

```
┌─────────────────┐
│   HTTP/3 Layer  │  <- frame.zig, qpack.zig, server.zig
├─────────────────┤
│   QUIC Core     │  <- connection.zig, packet.zig, stream.zig
├─────────────────┤  
│   Crypto/TLS    │  <- tls.zig, handshake.zig, keys.zig
├─────────────────┤
│   Networking    │  <- udp.zig, socket.zig, ipv6.zig  
└─────────────────┘
```

### Module Overview

- **`src/core/`** - Core QUIC protocol implementation
- **`src/crypto/`** - TLS 1.3 and cryptographic operations
- **`src/http3/`** - HTTP/3 frame handling and processing
- **`src/net/`** - UDP networking and IPv6 support
- **`src/utils/`** - Error handling and memory management utilities
- **`examples/`** - Sample client and server applications

## 🔐 Use Cases

- **WireGuard + QUIC** transport integration
- **HTTP3 reverse proxy** (wraith)
- **Fast tunnel entrypoints** for IoT/embedded
- **Gateway-to-gateway L7 communication** over encrypted streams
- **Blockchain node transport layer** over modern internet
- **VPN tunnel backends** with improved performance over traditional protocols
- **Real-time applications** requiring low-latency, reliable transport

## 🛠️ Development Status

- ✅ Core QUIC protocol structures
- ✅ HTTP/3 frame parsing and serialization  
- ✅ TLS 1.3 integration layer
- ✅ Flow control and congestion management
- ✅ UDP networking foundation
- ✅ Basic client/server examples
- 🚧 Advanced congestion control algorithms
- 🚧 Comprehensive test suite
- 🚧 Performance benchmarks
- 📋 Complete RFC 9000 compliance
- 📋 Production hardening

## 📚 Documentation

For detailed documentation, API reference, and implementation notes, see [DOCS.md](DOCS.md).

## 🤝 Contributing

Contributions are welcome! Please see our contributing guidelines and ensure all tests pass before submitting a PR.

```bash
# Run all tests
zig build test

# Check formatting
zig fmt --check src/
```

## 📄 License

MIT — Built to power modern decentralized and secure networking stacks in Zig.


