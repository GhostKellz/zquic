//! QUIC transport parameter encoding and decoding.
//!
//! Implements the RFC 9000 transport parameter container for the stable core
//! fields zquic currently negotiates. Preferred address is detected and
//! rejected explicitly until address migration support is wired end-to-end.

const std = @import("std");
const Io = std.Io;
const Error = @import("../utils/error.zig");
const Frames = @import("quic_frames.zig");

pub const ParameterId = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
};

pub const PreferredAddressPosture = enum {
    absent,
    unsupported,
};

pub const PeerRole = enum {
    client,
    server,
};

pub const NegotiationContext = struct {
    peer_role: PeerRole,
    original_destination_connection_id: []const u8 = &.{},
    initial_source_connection_id: []const u8 = &.{},
    retry_source_connection_id: []const u8 = &.{},
    require_disable_active_migration: bool = false,
};

pub const TransportParameters = struct {
    max_idle_timeout: u64 = 30_000,
    max_udp_payload_size: u64 = 1472,
    initial_max_data: u64 = 1_048_576,
    initial_max_stream_data_bidi_local: u64 = 65_536,
    initial_max_stream_data_bidi_remote: u64 = 65_536,
    initial_max_stream_data_uni: u64 = 65_536,
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
    ack_delay_exponent: u8 = 3,
    max_ack_delay: u64 = 25,
    disable_active_migration: bool = false,
    active_connection_id_limit: u64 = 2,
    original_destination_connection_id: []const u8 = &.{},
    initial_source_connection_id: []const u8 = &.{},
    retry_source_connection_id: []const u8 = &.{},
    preferred_address: PreferredAddressPosture = .absent,

    pub fn validate(self: TransportParameters) Error.ZquicError!void {
        if (self.max_udp_payload_size < 1200) return Error.ZquicError.InvalidArgument;
        if (self.ack_delay_exponent > 20) return Error.ZquicError.InvalidArgument;
        if (self.active_connection_id_limit < 2) return Error.ZquicError.InvalidArgument;
        if (self.original_destination_connection_id.len > 20) return Error.ZquicError.InvalidConnectionId;
        if (self.initial_source_connection_id.len > 20) return Error.ZquicError.InvalidConnectionId;
        if (self.retry_source_connection_id.len > 20) return Error.ZquicError.InvalidConnectionId;
        if (self.preferred_address != .absent) return Error.ZquicError.NotSupported;
    }
};

pub fn validateForHandshake(params: TransportParameters, context: NegotiationContext) Error.ZquicError!void {
    try params.validate();

    if (context.initial_source_connection_id.len > 0 and
        !std.mem.eql(u8, params.initial_source_connection_id, context.initial_source_connection_id))
    {
        return Error.ZquicError.ProtocolViolation;
    }

    if (context.require_disable_active_migration and !params.disable_active_migration) {
        return Error.ZquicError.ProtocolViolation;
    }

    switch (context.peer_role) {
        .server => {
            if (context.original_destination_connection_id.len == 0) {
                return Error.ZquicError.InvalidConnectionId;
            }
            if (!std.mem.eql(u8, params.original_destination_connection_id, context.original_destination_connection_id)) {
                return Error.ZquicError.ProtocolViolation;
            }

            if (context.retry_source_connection_id.len > 0) {
                if (!std.mem.eql(u8, params.retry_source_connection_id, context.retry_source_connection_id)) {
                    return Error.ZquicError.ProtocolViolation;
                }
            } else if (params.retry_source_connection_id.len != 0) {
                return Error.ZquicError.ProtocolViolation;
            }
        },
        .client => {
            if (params.original_destination_connection_id.len != 0) {
                return Error.ZquicError.ProtocolViolation;
            }
            if (params.retry_source_connection_id.len != 0) {
                return Error.ZquicError.ProtocolViolation;
            }
        },
    }
}

const SeenParameters = struct {
    original_destination_connection_id: bool = false,
    max_idle_timeout: bool = false,
    stateless_reset_token: bool = false,
    max_udp_payload_size: bool = false,
    initial_max_data: bool = false,
    initial_max_stream_data_bidi_local: bool = false,
    initial_max_stream_data_bidi_remote: bool = false,
    initial_max_stream_data_uni: bool = false,
    initial_max_streams_bidi: bool = false,
    initial_max_streams_uni: bool = false,
    ack_delay_exponent: bool = false,
    max_ack_delay: bool = false,
    disable_active_migration: bool = false,
    preferred_address: bool = false,
    active_connection_id_limit: bool = false,
    initial_source_connection_id: bool = false,
    retry_source_connection_id: bool = false,

    fn mark(self: *SeenParameters, id: ParameterId) Error.ZquicError!void {
        const seen = switch (id) {
            .original_destination_connection_id => &self.original_destination_connection_id,
            .max_idle_timeout => &self.max_idle_timeout,
            .stateless_reset_token => &self.stateless_reset_token,
            .max_udp_payload_size => &self.max_udp_payload_size,
            .initial_max_data => &self.initial_max_data,
            .initial_max_stream_data_bidi_local => &self.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote => &self.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni => &self.initial_max_stream_data_uni,
            .initial_max_streams_bidi => &self.initial_max_streams_bidi,
            .initial_max_streams_uni => &self.initial_max_streams_uni,
            .ack_delay_exponent => &self.ack_delay_exponent,
            .max_ack_delay => &self.max_ack_delay,
            .disable_active_migration => &self.disable_active_migration,
            .preferred_address => &self.preferred_address,
            .active_connection_id_limit => &self.active_connection_id_limit,
            .initial_source_connection_id => &self.initial_source_connection_id,
            .retry_source_connection_id => &self.retry_source_connection_id,
        };
        if (seen.*) return Error.ZquicError.ProtocolViolation;
        seen.* = true;
    }
};

pub fn encode(params: TransportParameters, writer: anytype) Error.ZquicError!void {
    try params.validate();

    try writeVarintParameter(writer, .max_idle_timeout, params.max_idle_timeout);
    try writeVarintParameter(writer, .max_udp_payload_size, params.max_udp_payload_size);
    try writeVarintParameter(writer, .initial_max_data, params.initial_max_data);
    try writeVarintParameter(writer, .initial_max_stream_data_bidi_local, params.initial_max_stream_data_bidi_local);
    try writeVarintParameter(writer, .initial_max_stream_data_bidi_remote, params.initial_max_stream_data_bidi_remote);
    try writeVarintParameter(writer, .initial_max_stream_data_uni, params.initial_max_stream_data_uni);
    try writeVarintParameter(writer, .initial_max_streams_bidi, params.initial_max_streams_bidi);
    try writeVarintParameter(writer, .initial_max_streams_uni, params.initial_max_streams_uni);
    try writeVarintParameter(writer, .ack_delay_exponent, params.ack_delay_exponent);
    try writeVarintParameter(writer, .max_ack_delay, params.max_ack_delay);
    if (params.disable_active_migration) {
        try writeRawParameter(writer, .disable_active_migration, &.{});
    }
    try writeVarintParameter(writer, .active_connection_id_limit, params.active_connection_id_limit);
    if (params.original_destination_connection_id.len > 0) {
        try writeRawParameter(writer, .original_destination_connection_id, params.original_destination_connection_id);
    }
    if (params.initial_source_connection_id.len > 0) {
        try writeRawParameter(writer, .initial_source_connection_id, params.initial_source_connection_id);
    }
    if (params.retry_source_connection_id.len > 0) {
        try writeRawParameter(writer, .retry_source_connection_id, params.retry_source_connection_id);
    }
}

pub fn decode(data: []const u8) Error.ZquicError!TransportParameters {
    var reader = Io.Reader.fixed(data);
    var params = TransportParameters{};
    var seen = SeenParameters{};

    while (reader.seek < reader.end) {
        const raw_id = Frames.readVarint(&reader) catch return Error.ZquicError.InvalidData;
        const length = Frames.readVarint(&reader) catch return Error.ZquicError.InvalidData;
        if (reader.seek + length > reader.end) return Error.ZquicError.InvalidData;

        const value = data[reader.seek .. reader.seek + length];
        reader.seek += length;

        const id = parameterIdFromInt(raw_id) orelse continue;
        try seen.mark(id);
        try applyParameter(&params, id, value);
    }

    try params.validate();
    return params;
}

fn parameterIdFromInt(raw_id: u64) ?ParameterId {
    return switch (raw_id) {
        0x00 => .original_destination_connection_id,
        0x01 => .max_idle_timeout,
        0x02 => .stateless_reset_token,
        0x03 => .max_udp_payload_size,
        0x04 => .initial_max_data,
        0x05 => .initial_max_stream_data_bidi_local,
        0x06 => .initial_max_stream_data_bidi_remote,
        0x07 => .initial_max_stream_data_uni,
        0x08 => .initial_max_streams_bidi,
        0x09 => .initial_max_streams_uni,
        0x0a => .ack_delay_exponent,
        0x0b => .max_ack_delay,
        0x0c => .disable_active_migration,
        0x0d => .preferred_address,
        0x0e => .active_connection_id_limit,
        0x0f => .initial_source_connection_id,
        0x10 => .retry_source_connection_id,
        else => null,
    };
}

fn writeRawParameter(writer: anytype, id: ParameterId, value: []const u8) Error.ZquicError!void {
    Frames.writeVarint(writer, @backingInt(id)) catch return Error.ZquicError.BufferTooSmall;
    Frames.writeVarint(writer, value.len) catch return Error.ZquicError.BufferTooSmall;
    writer.writeAll(value) catch return Error.ZquicError.BufferTooSmall;
}

fn writeVarintParameter(writer: anytype, id: ParameterId, value: u64) Error.ZquicError!void {
    var value_buffer: [8]u8 = undefined;
    var value_writer = Io.Writer.fixed(&value_buffer);
    Frames.writeVarint(&value_writer, value) catch return Error.ZquicError.BufferTooSmall;
    try writeRawParameter(writer, id, Io.Writer.buffered(&value_writer));
}

fn readParameterVarint(value: []const u8) Error.ZquicError!u64 {
    if (value.len == 0) return Error.ZquicError.InvalidData;
    var reader = Io.Reader.fixed(value);
    const result = Frames.readVarint(&reader) catch return Error.ZquicError.InvalidData;
    if (reader.bufferedLen() != 0) return Error.ZquicError.InvalidData;
    return result;
}

fn applyParameter(params: *TransportParameters, id: ParameterId, value: []const u8) Error.ZquicError!void {
    switch (id) {
        .original_destination_connection_id => params.original_destination_connection_id = value,
        .max_idle_timeout => params.max_idle_timeout = try readParameterVarint(value),
        .stateless_reset_token => {
            if (value.len != 16) return Error.ZquicError.InvalidData;
        },
        .max_udp_payload_size => params.max_udp_payload_size = try readParameterVarint(value),
        .initial_max_data => params.initial_max_data = try readParameterVarint(value),
        .initial_max_stream_data_bidi_local => params.initial_max_stream_data_bidi_local = try readParameterVarint(value),
        .initial_max_stream_data_bidi_remote => params.initial_max_stream_data_bidi_remote = try readParameterVarint(value),
        .initial_max_stream_data_uni => params.initial_max_stream_data_uni = try readParameterVarint(value),
        .initial_max_streams_bidi => params.initial_max_streams_bidi = try readParameterVarint(value),
        .initial_max_streams_uni => params.initial_max_streams_uni = try readParameterVarint(value),
        .ack_delay_exponent => {
            const exponent = try readParameterVarint(value);
            if (exponent > std.math.maxInt(u8)) return Error.ZquicError.InvalidData;
            params.ack_delay_exponent = @intCast(exponent);
        },
        .max_ack_delay => params.max_ack_delay = try readParameterVarint(value),
        .disable_active_migration => {
            if (value.len != 0) return Error.ZquicError.InvalidData;
            params.disable_active_migration = true;
        },
        .preferred_address => {
            if (value.len == 0) return Error.ZquicError.InvalidData;
            params.preferred_address = .unsupported;
        },
        .active_connection_id_limit => params.active_connection_id_limit = try readParameterVarint(value),
        .initial_source_connection_id => params.initial_source_connection_id = value,
        .retry_source_connection_id => params.retry_source_connection_id = value,
    }
}
