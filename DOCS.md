# ZQUIC Documentation

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [API Reference](#api-reference)
4. [Core Modules](#core-modules)
5. [Crypto Layer](#crypto-layer)
6. [HTTP/3 Implementation](#http3-implementation)
7. [Networking](#networking)
8. [Examples](#examples)
9. [Performance Considerations](#performance-considerations)
10. [Implementation Notes](#implementation-notes)

## Overview

ZQUIC is a minimal, high-performance QUIC/HTTP3 library implementation in Zig. It provides the foundational building blocks for modern network applications requiring secure, multiplexed transport with low latency and high throughput.

### Design Principles

- **Zero-copy where possible**: Minimize memory allocations and copies
- **Explicit memory management**: All allocations are explicit and trackable
- **Modular architecture**: Components can be used independently
- **Compile-time safety**: Leverage Zig's compile-time features for correctness
- **Performance first**: Optimized for high-throughput, low-latency scenarios

## Architecture

ZQUIC is organized into distinct layers, each with specific responsibilities:

```
┌─────────────────────────────────────────────────────┐
│                   Application                       │
├─────────────────────────────────────────────────────┤
│ HTTP/3 Layer (src/http3/)                          │
│ - Frame parsing/serialization                      │
│ - QPACK header compression                         │
│ - HTTP/3 server implementation                     │
├─────────────────────────────────────────────────────┤
│ QUIC Core (src/core/)                             │
│ - Connection management                            │
│ - Stream multiplexing                             │
│ - Flow control                                    │
│ - Congestion control                              │
│ - Packet handling                                 │
├─────────────────────────────────────────────────────┤
│ Crypto Layer (src/crypto/)                        │
│ - TLS 1.3 integration                            │
│ - Handshake management                            │
│ - Key derivation and rotation                     │
├─────────────────────────────────────────────────────┤
│ Networking (src/net/)                             │
│ - UDP socket abstraction                          │
│ - IPv6 support                                    │
│ - Address management                              │
├─────────────────────────────────────────────────────┤
│ Utilities (src/utils/)                            │
│ - Error handling                                  │
│ - Memory management                               │
└─────────────────────────────────────────────────────┘
```

## API Reference

### Core Types

```zig
// Connection management
const Connection = @import("core/connection.zig");
const Packet = @import("core/packet.zig");
const Stream = @import("core/stream.zig");

// Flow and congestion control
const FlowControl = @import("core/flow_control.zig");
const Congestion = @import("core/congestion.zig");

// Cryptographic operations
const Crypto = @import("crypto/tls.zig");
const Handshake = @import("crypto/handshake.zig");
const Keys = @import("crypto/keys.zig");

// HTTP/3 support
const Frame = @import("http3/frame.zig");
const Qpack = @import("http3/qpack.zig");
const Http3Server = @import("http3/server.zig");

// Networking
const Udp = @import("net/udp.zig");
const Socket = @import("net/socket.zig");
const Ipv6 = @import("net/ipv6.zig");
```

## Core Modules

### Connection Management (`src/core/connection.zig`)

The `Connection` module manages QUIC connection state and lifecycle.

```zig
pub const Connection = struct {
    role: Role,                    // Client or server
    state: ConnectionState,        // Connection state machine
    local_conn_id: ConnectionId,   // Local connection identifier
    remote_conn_id: ?ConnectionId, // Remote connection identifier
    params: ConnectionParams,      // Connection parameters
    stats: ConnectionStats,        // Connection statistics
    streams: ArrayList(Stream),    // Active streams
    allocator: Allocator,         // Memory allocator
    next_stream_id: u64,          // Next stream ID to allocate

    pub fn init(allocator: Allocator, role: Role, local_conn_id: ConnectionId) Self
    pub fn deinit(self: *Self) void
    pub fn createStream(self: *Self, stream_type: StreamType) !*Stream
    pub fn processPacket(self: *Self, packet: *const Packet) !void
    pub fn generatePacket(self: *Self, packet_type: PacketType) !Packet
};
```

### Packet Handling (`src/core/packet.zig`)

Defines QUIC packet structures and parsing logic.

```zig
pub const Packet = struct {
    header: PacketHeader,
    payload: []const u8,
    
    pub fn parse(data: []const u8, allocator: Allocator) !Self
    pub fn serialize(self: *const Self, writer: anytype) !void
};

pub const PacketHeader = struct {
    packet_type: PacketType,
    connection_id: ConnectionId,
    packet_number: u64,
    version: ?u32, // Only for Initial packets
};
```

### Stream Management (`src/core/stream.zig`)

Handles QUIC stream lifecycle and data transfer.

```zig
pub const Stream = struct {
    id: u64,
    stream_type: StreamType,
    state: StreamState,
    send_buffer: ArrayList(u8),
    recv_buffer: ArrayList(u8),
    flow_control: StreamFlowControl,
    
    pub fn init(allocator: Allocator, id: u64, stream_type: StreamType) Self
    pub fn write(self: *Self, data: []const u8) !usize
    pub fn read(self: *Self, buffer: []u8) !usize
    pub fn close(self: *Self) !void
};
```

### Flow Control (`src/core/flow_control.zig`)

Implements QUIC flow control mechanisms at both connection and stream levels.

```zig
pub const FlowController = struct {
    connection_fc: ConnectionFlowControl,
    stream_fc_map: ArrayList(StreamEntry),
    allocator: Allocator,
    
    pub fn init(allocator: Allocator, initial_max_data: u64, peer_max_data: u64) Self
    pub fn canSend(self: *const Self, stream_id: u64, bytes: u64) bool
    pub fn recordSent(self: *Self, stream_id: u64, bytes: u64) !void
    pub fn processMaxData(self: *Self, max_data: u64) void
};
```

## Crypto Layer

### TLS Integration (`src/crypto/tls.zig`)

Provides TLS 1.3 integration for QUIC's cryptographic needs.

```zig
pub const TlsContext = struct {
    state: HandshakeState,
    is_server: bool,
    cipher_suite: CipherSuite,
    keys: CryptoKeys,
    
    pub fn init(allocator: Allocator, is_server: bool) Self
    pub fn initializeInitialKeys(self: *Self, connection_id: []const u8) !void
    pub fn processCryptoData(self: *Self, data: []const u8, offset: u64) !void
    pub fn generateCryptoData(self: *Self, allocator: Allocator) ![]u8
};
```

### Handshake Management (`src/crypto/handshake.zig`)

Coordinates the QUIC+TLS handshake process.

```zig
pub const HandshakeManager = struct {
    tls_context: TlsContext,
    crypto_buffer: ArrayList(u8),
    handshake_complete: bool,
    
    pub fn init(allocator: Allocator, is_server: bool) Self
    pub fn startHandshake(self: *Self, connection_id: []const u8) !void
    pub fn processCryptoFrame(self: *Self, data: []const u8, offset: u64) !void
    pub fn isComplete(self: *const Self) bool
};
```

## HTTP/3 Implementation

### Frame Handling (`src/http3/frame.zig`)

Implements HTTP/3 frame parsing, serialization, and processing.

```zig
pub const FrameHeader = struct {
    frame_type: FrameType,
    length: u64,
    
    pub fn parse(data: []const u8) !struct { header: Self, consumed: usize }
    pub fn serialize(self: *const Self, writer: anytype) !void
};

pub const FrameParser = struct {
    buffer: ArrayList(u8),
    state: ParserState,
    
    pub fn init(allocator: Allocator) Self
    pub fn processData(self: *Self, data: []const u8, allocator: Allocator) ![]Frame
};
```

### QPACK (`src/http3/qpack.zig`)

Basic QPACK header compression support.

```zig
pub const QpackEncoder = struct {
    dynamic_table: ArrayList(HeaderField),
    
    pub fn init(allocator: Allocator) Self
    pub fn encode(self: *Self, headers: []const HeaderField, allocator: Allocator) ![]u8
};
```

## Networking

### UDP Layer (`src/net/udp.zig`)

UDP socket abstraction with async support.

```zig
pub const UdpSocket = struct {
    socket_fd: i32,
    local_addr: SocketAddr,
    
    pub fn init(local_addr: SocketAddr) !Self
    pub fn send(self: *Self, data: []const u8, dest_addr: SocketAddr) !usize
    pub fn recv(self: *Self, buffer: []u8) !struct { bytes: usize, addr: SocketAddr }
};
```

## Examples

### Basic Client

```zig
const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create connection
    const conn_id = zquic.Packet.ConnectionId{ .data = [_]u8{1, 2, 3, 4} };
    var connection = zquic.Connection.Connection.init(allocator, .client, conn_id);
    defer connection.deinit();

    // Initialize handshake
    var handshake_manager = zquic.Handshake.HandshakeManager.init(allocator, false);
    defer handshake_manager.deinit();

    try handshake_manager.startHandshake(&conn_id.data);
    
    std.debug.print("Client initialized and handshake started\n", .{});
}
```

### Basic Server

```zig
const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create server connection
    const conn_id = zquic.Packet.ConnectionId{ .data = [_]u8{4, 3, 2, 1} };
    var connection = zquic.Connection.Connection.init(allocator, .server, conn_id);
    defer connection.deinit();

    // Initialize server-side handshake
    var handshake_manager = zquic.Handshake.HandshakeManager.init(allocator, true);
    defer handshake_manager.deinit();

    std.debug.print("Server initialized and ready for connections\n", .{});
}
```

## Performance Considerations

### Memory Management

- **Arena Allocators**: Use arena allocators for temporary allocations during packet processing
- **Pool Allocators**: Consider pool allocators for frequently allocated objects (packets, frames)
- **Stack Allocation**: Prefer stack allocation for small, short-lived objects

### Zero-Copy Operations

- Frame parsing operates on slices of input data without copying
- Packet serialization writes directly to output buffers
- String operations avoid unnecessary allocations where possible

### Optimization Tips

1. **Batch Operations**: Process multiple packets/frames in single calls
2. **Pre-allocation**: Pre-allocate buffers for known maximum sizes
3. **Avoid Allocations**: Use fixed-size arrays where possible
4. **Lazy Evaluation**: Defer expensive operations until necessary

## Implementation Notes

### Current Limitations

- Basic congestion control implementation (needs enhancement)
- Limited QPACK dynamic table support
- Simplified packet number encryption
- No loss detection/recovery implementation yet

### Future Enhancements

- Advanced congestion control algorithms (BBR, Cubic)
- Complete QPACK implementation
- Packet pacing and scheduling
- Connection migration support
- Multipath QUIC support

### Testing

The test suite covers:
- Packet parsing and serialization
- Frame handling
- Basic flow control
- Connection state management
- Error handling

Run tests with:
```bash
zig build test
```

### Compliance

ZQUIC aims for RFC 9000 (QUIC) and RFC 9114 (HTTP/3) compliance. Current implementation covers core functionality with ongoing work toward full compliance.

For the latest implementation status and detailed API documentation, refer to the source code and inline comments.
