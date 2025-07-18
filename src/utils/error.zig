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
    BatchFull,
    PacketTooShort,
    InvalidData,

    // HTTP/3 specific errors
    Http3Error,
    QpackError,
    HeaderError,

    // Service-specific errors
    BackendNotFound,
    LabelTooLong,
    ServiceUnavailable,
    InvalidState,
    Timeout,

    // Migration and state errors
    ConnectionMigrationDisabled,
    ConnectionMigrationInProgress,
    StatelessReset,

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

/// Error context for debugging and logging
pub const ErrorContext = struct {
    file: []const u8,
    function: []const u8,
    line: u32,
    message: ?[]const u8 = null,
    cause: ?ZquicError = null,
    
    pub fn init(file: []const u8, function: []const u8, line: u32) ErrorContext {
        return ErrorContext{
            .file = file,
            .function = function,
            .line = line,
        };
    }
    
    pub fn withMessage(self: ErrorContext, message: []const u8) ErrorContext {
        var result = self;
        result.message = message;
        return result;
    }
    
    pub fn withCause(self: ErrorContext, cause: ZquicError) ErrorContext {
        var result = self;
        result.cause = cause;
        return result;
    }
};

/// Standardized error handling utilities
pub const ErrorHandling = struct {
    /// Map standard library errors to ZquicError
    pub fn mapStdError(err: anyerror) ZquicError {
        return switch (err) {
            error.OutOfMemory => ZquicError.OutOfMemory,
            error.InvalidArgument => ZquicError.InvalidArgument,
            error.AddressInUse => ZquicError.AddressInUse,
            error.AddressNotAvailable => ZquicError.AddressError,
            error.NetworkUnreachable => ZquicError.NetworkUnreachable,
            error.ConnectionRefused => ZquicError.ConnectionRefused,
            error.ConnectionResetByPeer => ZquicError.ConnectionReset,
            error.ConnectionTimedOut => ZquicError.ConnectionTimeout,
            error.WouldBlock => ZquicError.WouldBlock,
            error.BrokenPipe => ZquicError.ConnectionClosed,
            error.NotFound => ZquicError.BackendNotFound,
            error.InvalidData => ZquicError.InvalidData,
            error.BufferTooSmall => ZquicError.BufferTooSmall,
            else => ZquicError.InternalError,
        };
    }
    
    /// Map crypto-specific errors
    pub fn mapCryptoError(err: anyerror) ZquicError {
        return switch (err) {
            error.AuthenticationFailed => ZquicError.CryptoError,
            error.IdentityElement => ZquicError.CryptoError,
            error.NonCanonical => ZquicError.CryptoError,
            error.NotSquare => ZquicError.CryptoError,
            error.WeakPublicKey => ZquicError.CryptoError,
            error.InvalidLength => ZquicError.CryptoError,
            else => mapStdError(err),
        };
    }
    
    /// Map network operation errors with context
    pub fn mapNetworkError(err: anyerror, operation: []const u8) ZquicError {
        std.log.warn("Network operation '{s}' failed: {}", .{ operation, err });
        return switch (err) {
            error.SocketNotConnected => ZquicError.ConnectionClosed,
            error.MessageTooBig => ZquicError.PacketTooLarge,
            error.SystemResources => ZquicError.ResourceExhausted,
            error.ProcessFdQuotaExceeded => ZquicError.ResourceExhausted,
            error.SystemFdQuotaExceeded => ZquicError.ResourceExhausted,
            else => mapStdError(err),
        };
    }
    
    /// Log error with context
    pub fn logError(err: ZquicError, context: ErrorContext) void {
        const message = context.message orelse "No message";
        std.log.err("Error in {}:{s}:{d} - {}: {s}", .{ 
            context.file, context.function, context.line, err, message 
        });
        if (context.cause) |cause| {
            std.log.err("  Caused by: {}", .{cause});
        }
    }
    
    /// Convert error to user-friendly string
    pub fn errorToString(err: ZquicError) []const u8 {
        return switch (err) {
            .ConnectionClosed => "Connection closed",
            .ConnectionTimeout => "Connection timed out",
            .ConnectionRefused => "Connection refused",
            .InvalidConnectionId => "Invalid connection ID",
            .ProtocolViolation => "Protocol violation",
            .InvalidPacket => "Invalid packet format",
            .InvalidFrame => "Invalid frame format",
            .FlowControlError => "Flow control error",
            .StreamLimitError => "Stream limit exceeded",
            .StreamStateError => "Invalid stream state",
            .CryptoError => "Cryptographic error",
            .TlsError => "TLS handshake error",
            .HandshakeTimeout => "Handshake timeout",
            .CertificateError => "Certificate validation error",
            .NetworkError => "Network error",
            .SocketError => "Socket error",
            .AddressError => "Address error",
            .AddressInUse => "Address already in use",
            .NetworkUnreachable => "Network unreachable",
            .ConnectionReset => "Connection reset",
            .PacketTooLarge => "Packet too large",
            .WouldBlock => "Operation would block",
            .UnknownConnection => "Unknown connection",
            .ConnectionLimitReached => "Connection limit reached",
            .SendQueueFull => "Send queue full",
            .OutOfMemory => "Out of memory",
            .BufferTooSmall => "Buffer too small",
            .ResourceExhausted => "Resources exhausted",
            .BatchFull => "Batch operation full",
            .PacketTooShort => "Packet too short",
            .InvalidData => "Invalid data",
            .Http3Error => "HTTP/3 error",
            .QpackError => "QPACK compression error",
            .HeaderError => "Header processing error",
            .BackendNotFound => "Backend service not found",
            .LabelTooLong => "Label too long",
            .ServiceUnavailable => "Service unavailable",
            .InvalidState => "Invalid state",
            .Timeout => "Operation timed out",
            .ConnectionMigrationDisabled => "Connection migration disabled",
            .ConnectionMigrationInProgress => "Connection migration in progress",
            .StatelessReset => "Stateless reset received",
            .InvalidArgument => "Invalid argument",
            .NotSupported => "Operation not supported",
            .InternalError => "Internal error",
        };
    }
    
    /// Check if error is recoverable
    pub fn isRecoverable(err: ZquicError) bool {
        return switch (err) {
            ZquicError.WouldBlock, ZquicError.SendQueueFull, ZquicError.ResourceExhausted, ZquicError.Timeout => true,
            ZquicError.ConnectionClosed, ZquicError.ConnectionRefused, ZquicError.CertificateError, ZquicError.InternalError => false,
            else => true,
        };
    }
    
    /// Get error severity level
    pub fn getSeverity(err: ZquicError) enum { low, medium, high, critical } {
        return switch (err) {
            ZquicError.WouldBlock, ZquicError.PacketTooShort => .low,
            ZquicError.InvalidArgument, ZquicError.NotSupported, ZquicError.BufferTooSmall => .medium,
            ZquicError.NetworkError, ZquicError.ConnectionTimeout, ZquicError.ResourceExhausted => .high,
            ZquicError.InternalError, ZquicError.CryptoError, ZquicError.ProtocolViolation => .critical,
            else => .medium,
        };
    }
};

/// Convenience macros for error handling
pub fn ZQUIC_TRY(operation: anytype) !@TypeOf(operation) {
    return operation catch |err| {
        return ErrorHandling.mapStdError(err);
    };
}

pub fn ZQUIC_TRY_NET(operation: anytype, op_name: []const u8) !@TypeOf(operation) {
    return operation catch |err| {
        return ErrorHandling.mapNetworkError(err, op_name);
    };
}

pub fn ZQUIC_TRY_CRYPTO(operation: anytype) !@TypeOf(operation) {
    return operation catch |err| {
        return ErrorHandling.mapCryptoError(err);
    };
}

test "error code conversions" {
    const err = transportErrorToZquicError(.connection_refused);
    try std.testing.expect(err == ZquicError.ConnectionRefused);
}

test "error mapping utilities" {
    const std_err = ErrorHandling.mapStdError(error.OutOfMemory);
    try std.testing.expect(std_err == ZquicError.OutOfMemory);
    
    const net_err = ErrorHandling.mapNetworkError(error.ConnectionRefused, "connect");
    try std.testing.expect(net_err == ZquicError.ConnectionRefused);
    
    try std.testing.expect(ErrorHandling.isRecoverable(ZquicError.WouldBlock));
    try std.testing.expect(!ErrorHandling.isRecoverable(ZquicError.InternalError));
    
    try std.testing.expect(ErrorHandling.getSeverity(ZquicError.InternalError) == .critical);
    try std.testing.expect(ErrorHandling.getSeverity(ZquicError.WouldBlock) == .low);
}
