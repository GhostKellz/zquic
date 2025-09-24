# Core API Reference

Complete API documentation for ZQUIC v0.9.0-RC1 core modules.

## 📋 Quick Reference

```zig
const zquic = @import("zquic");

// Core types
const Connection = zquic.Connection;
const Packet = zquic.Packet;  
const Stream = zquic.Stream;
const Config = zquic.Config;

// Crypto types
const PacketCrypto = zquic.PacketCrypto;
const TlsContext = zquic.TlsContext;

// HTTP/3 types
const Http3Server = zquic.Http3.Http3Server;
const Request = zquic.Http3.Request;
const Response = zquic.Http3.Response;
```

## 🔌 Connection Management

### Connection

The core QUIC connection type managing connection state and lifecycle.

```zig
pub const Connection = struct {
    allocator: std.mem.Allocator,
    connection_id: [16]u8,
    state: ConnectionState,
    streams: HashMap(u64, Stream),
    flow_control: FlowControl,
    congestion: CongestionControl,
    packet_crypto: PacketCrypto,
    
    const Self = @This();
    
    /// Initialize new QUIC connection
    pub fn init(allocator: std.mem.Allocator, config: ConnectionConfig) !Self;
    
    /// Clean up connection resources
    pub fn deinit(self: *Self) void;
    
    /// Process incoming packet
    pub fn processPacket(self: *Self, packet_data: []const u8) !void;
    
    /// Create new stream
    pub fn createStream(self: *Self, stream_id: u64) !*Stream;
    
    /// Send data on connection
    pub fn sendData(self: *Self, stream_id: u64, data: []const u8) !void;
    
    /// Handle connection events
    pub fn poll(self: *Self) !?Event;
    
    /// Get connection statistics
    pub fn getStats(self: *const Self) ConnectionStats;
};
```

### ConnectionConfig

Configuration for QUIC connections.

```zig
pub const ConnectionConfig = struct {
    /// Maximum number of concurrent streams
    max_streams: u32 = 1000,
    
    /// Connection idle timeout in milliseconds
    idle_timeout_ms: u32 = 30000,
    
    /// Enable post-quantum cryptography
    enable_post_quantum: bool = true,
    
    /// Initial flow control window size
    initial_window_size: u32 = 65536,
    
    /// Maximum UDP payload size
    max_udp_payload_size: u16 = 1472,
    
    /// Enable connection migration
    enable_migration: bool = false,
};
```

### ConnectionState

```zig
pub const ConnectionState = enum {
    initial,
    handshake_in_progress,
    handshake_complete,
    connected,
    closing,
    closed,
    error,
};
```

## 📦 Packet Handling

### Packet

QUIC packet representation and processing.

```zig
pub const Packet = struct {
    header: PacketHeader,
    payload: []const u8,
    packet_number: u64,
    encryption_level: EncryptionLevel,
    
    const Self = @This();
    
    /// Parse packet from raw bytes
    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Self;
    
    /// Serialize packet to bytes
    pub fn serialize(self: *const Self, allocator: std.mem.Allocator) ![]u8;
    
    /// Decrypt packet payload
    pub fn decrypt(self: *Self, crypto: *PacketCrypto) ![]u8;
    
    /// Encrypt packet payload  
    pub fn encrypt(self: *Self, crypto: *PacketCrypto, plaintext: []const u8) !void;
    
    /// Validate packet integrity
    pub fn validate(self: *const Self) bool;
};
```

### PacketHeader

```zig
pub const PacketHeader = struct {
    packet_type: PacketType,
    connection_id: []const u8,
    version: u32,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: ?[]const u8,
    packet_number_length: u8,
};
```

## 🌊 Stream Management

### Stream

QUIC stream for data transmission.

```zig
pub const Stream = struct {
    stream_id: u64,
    state: StreamState,
    send_buffer: RingBuffer,
    recv_buffer: RingBuffer,
    flow_control: StreamFlowControl,
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize new stream
    pub fn init(allocator: std.mem.Allocator, stream_id: u64) !Self;
    
    /// Clean up stream resources
    pub fn deinit(self: *Self) void;
    
    /// Write data to stream
    pub fn write(self: *Self, data: []const u8) !usize;
    
    /// Read data from stream
    pub fn read(self: *Self, buffer: []u8) !usize;
    
    /// Close stream for writing
    pub fn close(self: *Self) !void;
    
    /// Reset stream with error code
    pub fn reset(self: *Self, error_code: u64) !void;
    
    /// Get stream statistics
    pub fn getStats(self: *const Self) StreamStats;
};
```

### StreamState

```zig
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
    reset,
};
```

## 🔐 Cryptographic Operations

### PacketCrypto

Handles packet encryption and decryption.

```zig
pub const PacketCrypto = struct {
    tls_context: *TlsContext,
    current_keys: CryptoKeys,
    next_keys: ?CryptoKeys,
    key_generation: u32,
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize packet crypto with TLS context
    pub fn init(allocator: std.mem.Allocator, tls_context: *TlsContext) !Self;
    
    /// Clean up crypto resources
    pub fn deinit(self: *Self) void;
    
    /// Encrypt packet data
    pub fn encryptPacket(
        self: *Self,
        plaintext: []const u8,
        packet_number: u64,
        encryption_level: EncryptionLevel,
        output: []u8,
    ) ![]u8;
    
    /// Decrypt packet data
    pub fn decryptPacket(
        self: *Self,
        ciphertext: []const u8,
        packet_number: u64,
        encryption_level: EncryptionLevel,
        output: []u8,
    ) ![]u8;
    
    /// Update cryptographic keys
    pub fn updateKeys(self: *Self) !void;
    
    /// Derive traffic keys from shared secret
    pub fn deriveTrafficKeys(
        self: *Self,
        shared_secret: []const u8,
        salt: []const u8,
        client_key: *[32]u8,
        server_key: *[32]u8,
    ) !void;
};
```

## ⚙️ Flow Control

### FlowControl

Connection-level flow control.

```zig
pub const FlowControl = struct {
    max_data: u64,
    data_sent: u64,
    data_received: u64,
    max_stream_data_bidi_local: u64,
    max_stream_data_bidi_remote: u64,
    max_stream_data_uni: u64,
    
    const Self = @This();
    
    /// Initialize flow control with limits
    pub fn init(initial_max_data: u64) Self;
    
    /// Check if data can be sent
    pub fn canSend(self: *const Self, amount: u64) bool;
    
    /// Record data sent
    pub fn recordSent(self: *Self, amount: u64) void;
    
    /// Record data received
    pub fn recordReceived(self: *Self, amount: u64) void;
    
    /// Update flow control limits
    pub fn updateLimits(self: *Self, max_data: u64) void;
    
    /// Get available send window
    pub fn getSendWindow(self: *const Self) u64;
};
```

## 🚀 High-Level APIs

### Client

High-level QUIC client interface.

```zig
pub const Client = struct {
    connection: Connection,
    config: ClientConfig,
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize QUIC client
    pub fn init(allocator: std.mem.Allocator, config: ClientConfig) !Self;
    
    /// Clean up client resources
    pub fn deinit(self: *Self) void;
    
    /// Connect to server
    pub fn connect(self: *Self) !void;
    
    /// Make HTTP/3 request
    pub fn request(self: *Self, method: []const u8, path: []const u8, body: ?[]const u8) !Response;
    
    /// Create new stream
    pub fn createStream(self: *Self) !*Stream;
    
    /// Close connection
    pub fn close(self: *Self) !void;
};
```

### Server

High-level QUIC server interface.

```zig
pub const Server = struct {
    listener: Listener,
    connections: HashMap(ConnectionId, Connection),
    config: ServerConfig,
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize QUIC server
    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) !Self;
    
    /// Clean up server resources
    pub fn deinit(self: *Self) void;
    
    /// Start listening for connections
    pub fn listen(self: *Self) !void;
    
    /// Accept new connection
    pub fn accept(self: *Self) !Connection;
    
    /// Handle connection events
    pub fn poll(self: *Self) !?Event;
    
    /// Stop server
    pub fn stop(self: *Self) !void;
};
```

## 📊 Statistics and Monitoring

### ConnectionStats

```zig
pub const ConnectionStats = struct {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    packets_lost: u64,
    rtt_estimate: u32,
    congestion_window: u32,
    streams_created: u32,
    streams_closed: u32,
    handshake_duration_ms: u32,
};
```

### StreamStats

```zig
pub const StreamStats = struct {
    stream_id: u64,
    bytes_sent: u64,
    bytes_received: u64,
    state: StreamState,
    created_at: i64,
    first_byte_at: ?i64,
    last_byte_at: ?i64,
};
```

## 🔄 Event System

### Event

Events generated by QUIC connections.

```zig
pub const Event = union(enum) {
    connection_established: ConnectionId,
    connection_closed: struct {
        connection_id: ConnectionId,
        error_code: u64,
        reason: []const u8,
    },
    stream_created: struct {
        connection_id: ConnectionId,
        stream_id: u64,
    },
    stream_data_available: struct {
        connection_id: ConnectionId,
        stream_id: u64,
        data: []const u8,
    },
    stream_closed: struct {
        connection_id: ConnectionId,
        stream_id: u64,
    },
    datagram_received: struct {
        connection_id: ConnectionId,
        data: []const u8,
    },
};
```

## 🛠️ Error Handling

### ZquicError

Comprehensive error types for ZQUIC operations.

```zig
pub const ZquicError = error{
    // Connection errors
    ConnectionRefused,
    ConnectionTimeout,
    ConnectionClosed,
    ConnectionReset,
    
    // Protocol errors  
    ProtocolViolation,
    InvalidPacket,
    InvalidFrame,
    FlowControlError,
    
    // Crypto errors
    CryptoError,
    TlsError,
    KeyUpdateError,
    
    // Stream errors
    StreamClosed,
    StreamReset,
    StreamLimitExceeded,
    
    // System errors
    OutOfMemory,
    NetworkError,
    InvalidInput,
    InvalidState,
    
    // HTTP/3 errors
    Http3Error,
    QpackError,
    HeaderError,
};
```

---

**Next**: [Crypto API](crypto.md) - Post-quantum cryptography API