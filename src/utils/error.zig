//! Error definitions for ZQUIC library

const std = @import("std");

/// ZQUIC-specific error types
pub const ZquicError = error{
    // Connection errors
    ConnectionClosed,
    ConnectionTimeout,
    ConnectionRefused,
    InvalidConnectionId,

    // Protocol errors
    ProtocolViolation,
    InvalidPacket,
    InvalidFrame,
    FlowControlError,
    StreamLimitError,
    StreamStateError,

    // Crypto errors
    CryptoError,
    TlsError,
    HandshakeTimeout,
    CertificateError,

    // Network errors
    NetworkError,
    SocketError,
    AddressError,
    AddressInUse,
    NetworkUnreachable,
    ConnectionReset,
    PacketTooLarge,
    WouldBlock,
    
    // VPN and multiplexing errors
    UnknownConnection,
    ConnectionLimitReached,
    SendQueueFull,

    // Resource errors
    OutOfMemory,
    BufferTooSmall,
    ResourceExhausted,

    // HTTP/3 specific errors
    Http3Error,
    QpackError,
    HeaderError,

    // General errors
    InvalidArgument,
    NotSupported,
    InternalError,
};

/// QUIC transport error codes (RFC 9000)
pub const TransportError = enum(u64) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
};

/// HTTP/3 error codes (RFC 9114)
pub const Http3Error = enum(u64) {
    h3_no_error = 0x100,
    h3_general_protocol_error = 0x101,
    h3_internal_error = 0x102,
    h3_stream_creation_error = 0x103,
    h3_closed_critical_stream = 0x104,
    h3_frame_unexpected = 0x105,
    h3_frame_error = 0x106,
    h3_excessive_load = 0x107,
    h3_id_error = 0x108,
    h3_settings_error = 0x109,
    h3_missing_settings = 0x10a,
    h3_request_rejected = 0x10b,
    h3_request_cancelled = 0x10c,
    h3_request_incomplete = 0x10d,
    h3_message_error = 0x10e,
    h3_connect_error = 0x10f,
    h3_version_fallback = 0x110,
};

/// Convert a transport error to a ZquicError
pub fn transportErrorToZquicError(transport_error: TransportError) ZquicError {
    return switch (transport_error) {
        .no_error => ZquicError.InternalError, // Should not happen
        .internal_error => ZquicError.InternalError,
        .connection_refused => ZquicError.ConnectionRefused,
        .flow_control_error => ZquicError.FlowControlError,
        .stream_limit_error => ZquicError.StreamLimitError,
        .protocol_violation => ZquicError.ProtocolViolation,
        .crypto_buffer_exceeded => ZquicError.CryptoError,
        .key_update_error => ZquicError.CryptoError,
        else => ZquicError.ProtocolViolation,
    };
}

test "error code conversions" {
    const err = transportErrorToZquicError(.connection_refused);
    try std.testing.expect(err == ZquicError.ConnectionRefused);
}
