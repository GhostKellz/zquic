//! QUIC Error Management Module
//!
//! Provides centralized error definitions, error context, and error handling
//! utilities for the ZQUIC library. All modules should use these error types
//! for consistent error handling across the codebase.
//!
//! Features:
//! - Hierarchical error sets for different layers
//! - Error context with debugging information
//! - QUIC protocol error codes (RFC 9000)
//! - TLS error integration
//! - Error recovery utilities

const std = @import("std");

/// Core ZQUIC errors that can occur at any layer
pub const ZquicError = error{
    // Memory management errors
    OutOfMemory,
    InvalidParameter,
    BufferTooSmall,
    BufferOverflow,

    // Connection state errors
    ConnectionClosed,
    ConnectionRefused,
    ConnectionTimeout,
    ConnectionReset,

    // Protocol errors
    ProtocolViolation,
    InvalidPacket,
    InvalidFrame,
    InvalidStream,

    // Crypto errors
    CryptoError,
    KeyNotFound,
    DecryptionFailed,
    EncryptionFailed,

    // Transport errors
    NetworkError,
    AddressNotAvailable,
    PortInUse,

    // Stream errors
    StreamClosed,
    StreamNotFound,
    StreamLimitExceeded,
    FlowControlViolation,

    // Configuration errors
    InvalidConfiguration,
    UnsupportedVersion,
    UnsupportedFeature,

    // Internal errors
    InternalError,
    NotImplemented,

    // Async/timing errors
    Timeout,
    WouldBlock,
    OperationCancelled,
};

/// QUIC transport error codes as defined in RFC 9000
pub const TransportError = enum(u64) {
    // Connection close reasons
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
    protocol_violation = 0x0A,
    invalid_token = 0x0B,
    application_error = 0x0C,
    crypto_buffer_exceeded = 0x0D,
    key_update_error = 0x0E,
    aead_limit_reached = 0x0F,
    no_viable_path = 0x10,

    // Crypto errors (TLS alerts)
    crypto_error_base = 0x100,

    pub fn toString(self: TransportError) []const u8 {
        return switch (self) {
            .no_error => "NO_ERROR",
            .internal_error => "INTERNAL_ERROR",
            .connection_refused => "CONNECTION_REFUSED",
            .flow_control_error => "FLOW_CONTROL_ERROR",
            .stream_limit_error => "STREAM_LIMIT_ERROR",
            .stream_state_error => "STREAM_STATE_ERROR",
            .final_size_error => "FINAL_SIZE_ERROR",
            .frame_encoding_error => "FRAME_ENCODING_ERROR",
            .transport_parameter_error => "TRANSPORT_PARAMETER_ERROR",
            .connection_id_limit_error => "CONNECTION_ID_LIMIT_ERROR",
            .protocol_violation => "PROTOCOL_VIOLATION",
            .invalid_token => "INVALID_TOKEN",
            .application_error => "APPLICATION_ERROR",
            .crypto_buffer_exceeded => "CRYPTO_BUFFER_EXCEEDED",
            .key_update_error => "KEY_UPDATE_ERROR",
            .aead_limit_reached => "AEAD_LIMIT_REACHED",
            .no_viable_path => "NO_VIABLE_PATH",
            .crypto_error_base => "CRYPTO_ERROR",
        };
    }

    /// Check if this is a crypto-related error
    pub fn isCryptoError(self: TransportError) bool {
        return @intFromEnum(self) >= @intFromEnum(TransportError.crypto_error_base);
    }
};

/// Application protocol error codes
pub const ApplicationError = enum(u64) {
    // HTTP/3 error codes (RFC 9114)
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
    h3_missing_settings = 0x10A,
    h3_request_rejected = 0x10B,
    h3_request_cancelled = 0x10C,
    h3_request_incomplete = 0x10D,
    h3_message_error = 0x10E,
    h3_connect_error = 0x10F,
    h3_version_fallback = 0x110,

    // DoQ error codes (RFC 9250)
    doq_no_error = 0x00,
    doq_internal_error = 0x01,
    doq_protocol_error = 0x02,
    doq_request_cancelled = 0x03,
    doq_excessive_load = 0x04,
    doq_unspecified_error = 0x05,

    // Custom application errors
    app_custom_base = 0x1000,

    pub fn toString(self: ApplicationError) []const u8 {
        return switch (self) {
            .h3_no_error => "H3_NO_ERROR",
            .h3_general_protocol_error => "H3_GENERAL_PROTOCOL_ERROR",
            .h3_internal_error => "H3_INTERNAL_ERROR",
            .h3_stream_creation_error => "H3_STREAM_CREATION_ERROR",
            .h3_closed_critical_stream => "H3_CLOSED_CRITICAL_STREAM",
            .h3_frame_unexpected => "H3_FRAME_UNEXPECTED",
            .h3_frame_error => "H3_FRAME_ERROR",
            .h3_excessive_load => "H3_EXCESSIVE_LOAD",
            .h3_id_error => "H3_ID_ERROR",
            .h3_settings_error => "H3_SETTINGS_ERROR",
            .h3_missing_settings => "H3_MISSING_SETTINGS",
            .h3_request_rejected => "H3_REQUEST_REJECTED",
            .h3_request_cancelled => "H3_REQUEST_CANCELLED",
            .h3_request_incomplete => "H3_REQUEST_INCOMPLETE",
            .h3_message_error => "H3_MESSAGE_ERROR",
            .h3_connect_error => "H3_CONNECT_ERROR",
            .h3_version_fallback => "H3_VERSION_FALLBACK",
            .doq_no_error => "DOQ_NO_ERROR",
            .doq_internal_error => "DOQ_INTERNAL_ERROR",
            .doq_protocol_error => "DOQ_PROTOCOL_ERROR",
            .doq_request_cancelled => "DOQ_REQUEST_CANCELLED",
            .doq_excessive_load => "DOQ_EXCESSIVE_LOAD",
            .doq_unspecified_error => "DOQ_UNSPECIFIED_ERROR",
            .app_custom_base => "APP_CUSTOM",
        };
    }
};

/// Error severity levels for logging and debugging
pub const ErrorSeverity = enum {
    /// Informational - operation succeeded with notes
    info,
    /// Warning - operation succeeded but with issues
    warning,
    /// Error - operation failed but recoverable
    @"error",
    /// Critical - operation failed, may require connection close
    critical,
    /// Fatal - unrecoverable error, library shutdown required
    fatal,

    pub fn toString(self: ErrorSeverity) []const u8 {
        return switch (self) {
            .info => "INFO",
            .warning => "WARN",
            .@"error" => "ERROR",
            .critical => "CRITICAL",
            .fatal => "FATAL",
        };
    }
};

/// Error context with debugging information
pub const ErrorContext = struct {
    /// The error that occurred
    error_code: ZquicError,
    /// Human-readable description
    description: []const u8,
    /// Source location where error occurred
    source_location: std.builtin.SourceLocation,
    /// Error severity
    severity: ErrorSeverity,
    /// Optional transport error code
    transport_error: ?TransportError,
    /// Optional application error code
    app_error: ?ApplicationError,
    /// Additional context data
    context_data: ?[]const u8,
    /// Timestamp when error occurred
    timestamp: i64,

    const Self = @This();

    /// Create error context with current source location
    pub fn init(
        error_code: ZquicError,
        description: []const u8,
        severity: ErrorSeverity,
        src: std.builtin.SourceLocation,
    ) Self {
        return Self{
            .error_code = error_code,
            .description = description,
            .source_location = src,
            .severity = severity,
            .transport_error = null,
            .app_error = null,
            .context_data = null,
            .timestamp = std.time.timestamp(),
        };
    }

    /// Create error context with transport error
    pub fn initWithTransportError(
        error_code: ZquicError,
        transport_error: TransportError,
        description: []const u8,
        src: std.builtin.SourceLocation,
    ) Self {
        var ctx = init(error_code, description, .@"error", src);
        ctx.transport_error = transport_error;
        return ctx;
    }

    /// Create error context with application error
    pub fn initWithAppError(
        error_code: ZquicError,
        app_error: ApplicationError,
        description: []const u8,
        src: std.builtin.SourceLocation,
    ) Self {
        var ctx = init(error_code, description, .@"error", src);
        ctx.app_error = app_error;
        return ctx;
    }

    /// Add context data to error
    pub fn withContext(self: Self, context_data: []const u8) Self {
        var ctx = self;
        ctx.context_data = context_data;
        return ctx;
    }

    /// Format error for logging
    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        try writer.print("[{s}] {s}: {s}", .{
            self.severity.toString(),
            @errorName(self.error_code),
            self.description,
        });

        if (self.transport_error) |te| {
            try writer.print(" (transport: {s})", .{te.toString()});
        }

        if (self.app_error) |ae| {
            try writer.print(" (app: {s})", .{ae.toString()});
        }

        try writer.print(" at {s}:{d}:{d}", .{
            self.source_location.file,
            self.source_location.line,
            self.source_location.column,
        });

        if (self.context_data) |data| {
            try writer.print(" [{}]", .{std.fmt.fmtSliceHexLower(data)});
        }
    }
};

/// Error result type that includes context
pub fn ErrorResult(comptime T: type) type {
    return union(enum) {
        ok: T,
        err: ErrorContext,

        const Self = @This();

        /// Check if result is successful
        pub fn isOk(self: Self) bool {
            return switch (self) {
                .ok => true,
                .err => false,
            };
        }

        /// Check if result is an error
        pub fn isErr(self: Self) bool {
            return !self.isOk();
        }

        /// Unwrap successful result or return error
        pub fn unwrap(self: Self) ZquicError!T {
            return switch (self) {
                .ok => |value| value,
                .err => |ctx| ctx.error_code,
            };
        }

        /// Unwrap successful result or panic
        pub fn unwrapOrPanic(self: Self) T {
            return switch (self) {
                .ok => |value| value,
                .err => |ctx| std.debug.panic("Unwrapped error: {}", .{ctx}),
            };
        }

        /// Get error context if result is error
        pub fn getError(self: Self) ?ErrorContext {
            return switch (self) {
                .ok => null,
                .err => |ctx| ctx,
            };
        }
    };
}

/// Utility functions for error handling
pub const ErrorUtils = struct {
    /// Convert stdlib errors to ZQUIC errors
    pub fn fromStdError(err: anyerror) ZquicError {
        return switch (err) {
            error.OutOfMemory => ZquicError.OutOfMemory,
            error.InvalidArgument => ZquicError.InvalidParameter,
            error.BrokenPipe => ZquicError.ConnectionClosed,
            error.ConnectionResetByPeer => ZquicError.ConnectionReset,
            error.NetworkUnreachable => ZquicError.NetworkError,
            error.AddressInUse => ZquicError.PortInUse,
            error.AddressNotAvailable => ZquicError.AddressNotAvailable,
            error.WouldBlock => ZquicError.WouldBlock,
            error.TimedOut => ZquicError.Timeout,
            else => ZquicError.InternalError,
        };
    }

    /// Check if error is recoverable
    pub fn isRecoverable(err: ZquicError) bool {
        return switch (err) {
            ZquicError.WouldBlock,
            ZquicError.Timeout,
            ZquicError.BufferTooSmall,
            ZquicError.FlowControlViolation,
            => true,
            else => false,
        };
    }

    /// Check if error requires connection close
    pub fn requiresConnectionClose(err: ZquicError) bool {
        return switch (err) {
            ZquicError.ProtocolViolation,
            ZquicError.InvalidPacket,
            ZquicError.CryptoError,
            ZquicError.DecryptionFailed,
            ZquicError.ConnectionTimeout,
            ZquicError.InternalError,
            => true,
            else => false,
        };
    }

    /// Get suggested transport error for ZQUIC error
    pub fn getTransportError(err: ZquicError) TransportError {
        return switch (err) {
            ZquicError.ProtocolViolation => TransportError.protocol_violation,
            ZquicError.InvalidPacket => TransportError.frame_encoding_error,
            ZquicError.InvalidFrame => TransportError.frame_encoding_error,
            ZquicError.FlowControlViolation => TransportError.flow_control_error,
            ZquicError.StreamLimitExceeded => TransportError.stream_limit_error,
            ZquicError.CryptoError => TransportError.crypto_error_base,
            ZquicError.DecryptionFailed => TransportError.crypto_error_base,
            ZquicError.EncryptionFailed => TransportError.crypto_error_base,
            ZquicError.InvalidConfiguration => TransportError.transport_parameter_error,
            else => TransportError.internal_error,
        };
    }
};

/// Macro-like function to create error context with current location
pub fn makeError(
    error_code: ZquicError,
    description: []const u8,
    severity: ErrorSeverity,
) ErrorContext {
    return ErrorContext.init(error_code, description, severity, @src());
}

/// Macro-like function to create transport error with current location
pub fn makeTransportError(
    error_code: ZquicError,
    transport_error: TransportError,
    description: []const u8,
) ErrorContext {
    return ErrorContext.initWithTransportError(error_code, transport_error, description, @src());
}

/// Macro-like function to create application error with current location
pub fn makeAppError(
    error_code: ZquicError,
    app_error: ApplicationError,
    description: []const u8,
) ErrorContext {
    return ErrorContext.initWithAppError(error_code, app_error, description, @src());
}

// Tests
test "error context creation" {
    const ctx = makeError(ZquicError.InvalidPacket, "Test error", .@"error");
    try std.testing.expectEqual(ZquicError.InvalidPacket, ctx.error_code);
    try std.testing.expectEqualStrings("Test error", ctx.description);
    try std.testing.expectEqual(ErrorSeverity.@"error", ctx.severity);
}

test "transport error mapping" {
    const transport_err = ErrorUtils.getTransportError(ZquicError.ProtocolViolation);
    try std.testing.expectEqual(TransportError.protocol_violation, transport_err);

    try std.testing.expectEqualStrings("PROTOCOL_VIOLATION", transport_err.toString());
}

test "error result operations" {
    const SuccessResult = ErrorResult(i32);

    const success = SuccessResult{ .ok = 42 };
    try std.testing.expect(success.isOk());
    try std.testing.expectEqual(@as(i32, 42), try success.unwrap());

    const failure = SuccessResult{ .err = makeError(ZquicError.InvalidParameter, "Test", .@"error") };
    try std.testing.expect(failure.isErr());
    try std.testing.expectError(ZquicError.InvalidParameter, failure.unwrap());
}

test "error recoverability" {
    try std.testing.expect(ErrorUtils.isRecoverable(ZquicError.WouldBlock));
    try std.testing.expect(!ErrorUtils.isRecoverable(ZquicError.ProtocolViolation));

    try std.testing.expect(ErrorUtils.requiresConnectionClose(ZquicError.ProtocolViolation));
    try std.testing.expect(!ErrorUtils.requiresConnectionClose(ZquicError.WouldBlock));
}
