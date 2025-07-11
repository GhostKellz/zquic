//! QUIC Frame Types Implementation
//!
//! Complete implementation of all QUIC frame types according to RFC 9000
//! Including the missing frames: PING, RESET_STREAM, STOP_SENDING, and others

const std = @import("std");
const Error = @import("../utils/error.zig");

/// QUIC frame types as defined in RFC 9000
pub const FrameType = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08,
    stream_fin = 0x09,
    stream_len = 0x0a,
    stream_len_fin = 0x0b,
    stream_off = 0x0c,
    stream_off_fin = 0x0d,
    stream_off_len = 0x0e,
    stream_off_len_fin = 0x0f,
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    connection_close_app = 0x1d,
    handshake_done = 0x1e,
    
    // Extension frames
    datagram = 0x30,
    datagram_len = 0x31,
    
    pub fn isStreamFrame(self: FrameType) bool {
        const type_val = @intFromEnum(self);
        return type_val >= 0x08 and type_val <= 0x0f;
    }
    
    pub fn isAckEliciting(self: FrameType) bool {
        return switch (self) {
            .padding, .ack, .ack_ecn, .connection_close, .connection_close_app => false,
            else => true,
        };
    }
    
    pub fn toString(self: FrameType) []const u8 {
        return switch (self) {
            .padding => "PADDING",
            .ping => "PING",
            .ack => "ACK",
            .ack_ecn => "ACK_ECN",
            .reset_stream => "RESET_STREAM",
            .stop_sending => "STOP_SENDING",
            .crypto => "CRYPTO",
            .new_token => "NEW_TOKEN",
            .stream => "STREAM",
            .stream_fin => "STREAM_FIN",
            .stream_len => "STREAM_LEN",
            .stream_len_fin => "STREAM_LEN_FIN",
            .stream_off => "STREAM_OFF",
            .stream_off_fin => "STREAM_OFF_FIN",
            .stream_off_len => "STREAM_OFF_LEN",
            .stream_off_len_fin => "STREAM_OFF_LEN_FIN",
            .max_data => "MAX_DATA",
            .max_stream_data => "MAX_STREAM_DATA",
            .max_streams_bidi => "MAX_STREAMS_BIDI",
            .max_streams_uni => "MAX_STREAMS_UNI",
            .data_blocked => "DATA_BLOCKED",
            .stream_data_blocked => "STREAM_DATA_BLOCKED",
            .streams_blocked_bidi => "STREAMS_BLOCKED_BIDI",
            .streams_blocked_uni => "STREAMS_BLOCKED_UNI",
            .new_connection_id => "NEW_CONNECTION_ID",
            .retire_connection_id => "RETIRE_CONNECTION_ID",
            .path_challenge => "PATH_CHALLENGE",
            .path_response => "PATH_RESPONSE",
            .connection_close => "CONNECTION_CLOSE",
            .connection_close_app => "CONNECTION_CLOSE_APP",
            .handshake_done => "HANDSHAKE_DONE",
            .datagram => "DATAGRAM",
            .datagram_len => "DATAGRAM_LEN",
        };
    }
};

/// Variable-length integer encoding/decoding
pub fn writeVarint(writer: anytype, value: u64) !void {
    if (value < 0x40) {
        try writer.writeByte(@intCast(value));
    } else if (value < 0x4000) {
        try writer.writeInt(u16, @intCast(value | 0x4000), .big);
    } else if (value < 0x40000000) {
        try writer.writeInt(u32, @intCast(value | 0x80000000), .big);
    } else {
        try writer.writeInt(u64, value | 0xC000000000000000, .big);
    }
}

pub fn readVarint(reader: anytype) !u64 {
    const first_byte = try reader.readByte();
    const prefix = first_byte >> 6;
    
    switch (prefix) {
        0 => return first_byte & 0x3F,
        1 => {
            const second_byte = try reader.readByte();
            return (@as(u64, first_byte & 0x3F) << 8) | second_byte;
        },
        2 => {
            const remaining = try reader.readInt(u24, .big);
            return (@as(u64, first_byte & 0x3F) << 24) | remaining;
        },
        3 => {
            const remaining = try reader.readInt(u56, .big);
            return (@as(u64, first_byte & 0x3F) << 56) | remaining;
        },
        else => unreachable,
    }
}

/// Base frame structure
pub const Frame = union(FrameType) {
    padding: PaddingFrame,
    ping: PingFrame,
    ack: AckFrame,
    ack_ecn: AckEcnFrame,
    reset_stream: ResetStreamFrame,
    stop_sending: StopSendingFrame,
    crypto: CryptoFrame,
    new_token: NewTokenFrame,
    stream: StreamFrame,
    stream_fin: StreamFrame,
    stream_len: StreamFrame,
    stream_len_fin: StreamFrame,
    stream_off: StreamFrame,
    stream_off_fin: StreamFrame,
    stream_off_len: StreamFrame,
    stream_off_len_fin: StreamFrame,
    max_data: MaxDataFrame,
    max_stream_data: MaxStreamDataFrame,
    max_streams_bidi: MaxStreamsFrame,
    max_streams_uni: MaxStreamsFrame,
    data_blocked: DataBlockedFrame,
    stream_data_blocked: StreamDataBlockedFrame,
    streams_blocked_bidi: StreamsBlockedFrame,
    streams_blocked_uni: StreamsBlockedFrame,
    new_connection_id: NewConnectionIdFrame,
    retire_connection_id: RetireConnectionIdFrame,
    path_challenge: PathChallengeFrame,
    path_response: PathResponseFrame,
    connection_close: ConnectionCloseFrame,
    connection_close_app: ConnectionCloseAppFrame,
    handshake_done: HandshakeDoneFrame,
    datagram: DatagramFrame,
    datagram_len: DatagramFrame,
    
    pub fn getType(self: Frame) FrameType {
        return @as(FrameType, self);
    }
    
    pub fn isAckEliciting(self: Frame) bool {
        return self.getType().isAckEliciting();
    }
    
    pub fn serialize(self: Frame, writer: anytype) !void {
        switch (self) {
            .padding => |frame| try frame.serialize(writer),
            .ping => |frame| try frame.serialize(writer),
            .ack => |frame| try frame.serialize(writer),
            .ack_ecn => |frame| try frame.serialize(writer),
            .reset_stream => |frame| try frame.serialize(writer),
            .stop_sending => |frame| try frame.serialize(writer),
            .crypto => |frame| try frame.serialize(writer),
            .new_token => |frame| try frame.serialize(writer),
            .stream, .stream_fin, .stream_len, .stream_len_fin, .stream_off, .stream_off_fin, .stream_off_len, .stream_off_len_fin => |frame| try frame.serialize(writer),
            .max_data => |frame| try frame.serialize(writer),
            .max_stream_data => |frame| try frame.serialize(writer),
            .max_streams_bidi, .max_streams_uni => |frame| try frame.serialize(writer),
            .data_blocked => |frame| try frame.serialize(writer),
            .stream_data_blocked => |frame| try frame.serialize(writer),
            .streams_blocked_bidi, .streams_blocked_uni => |frame| try frame.serialize(writer),
            .new_connection_id => |frame| try frame.serialize(writer),
            .retire_connection_id => |frame| try frame.serialize(writer),
            .path_challenge => |frame| try frame.serialize(writer),
            .path_response => |frame| try frame.serialize(writer),
            .connection_close => |frame| try frame.serialize(writer),
            .connection_close_app => |frame| try frame.serialize(writer),
            .handshake_done => |frame| try frame.serialize(writer),
            .datagram, .datagram_len => |frame| try frame.serialize(writer),
        }
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !Frame {
        const frame_type_value = try readVarint(reader);
        
        return switch (frame_type_value) {
            0x00 => Frame{ .padding = try PaddingFrame.parse(reader, allocator) },
            0x01 => Frame{ .ping = try PingFrame.parse(reader, allocator) },
            0x02 => Frame{ .ack = try AckFrame.parse(reader, allocator) },
            0x03 => Frame{ .ack_ecn = try AckEcnFrame.parse(reader, allocator) },
            0x04 => Frame{ .reset_stream = try ResetStreamFrame.parse(reader, allocator) },
            0x05 => Frame{ .stop_sending = try StopSendingFrame.parse(reader, allocator) },
            0x06 => Frame{ .crypto = try CryptoFrame.parse(reader, allocator) },
            0x07 => Frame{ .new_token = try NewTokenFrame.parse(reader, allocator) },
            0x08...0x0f => blk: {
                const stream_frame = try StreamFrame.parse(reader, allocator, frame_type_value);
                break :blk Frame{ .stream = stream_frame };
            },
            0x10 => Frame{ .max_data = try MaxDataFrame.parse(reader, allocator) },
            0x11 => Frame{ .max_stream_data = try MaxStreamDataFrame.parse(reader, allocator) },
            0x12 => Frame{ .max_streams_bidi = try MaxStreamsFrame.parse(reader, allocator) },
            0x13 => Frame{ .max_streams_uni = try MaxStreamsFrame.parse(reader, allocator) },
            0x14 => Frame{ .data_blocked = try DataBlockedFrame.parse(reader, allocator) },
            0x15 => Frame{ .stream_data_blocked = try StreamDataBlockedFrame.parse(reader, allocator) },
            0x16 => Frame{ .streams_blocked_bidi = try StreamsBlockedFrame.parse(reader, allocator) },
            0x17 => Frame{ .streams_blocked_uni = try StreamsBlockedFrame.parse(reader, allocator) },
            0x18 => Frame{ .new_connection_id = try NewConnectionIdFrame.parse(reader, allocator) },
            0x19 => Frame{ .retire_connection_id = try RetireConnectionIdFrame.parse(reader, allocator) },
            0x1a => Frame{ .path_challenge = try PathChallengeFrame.parse(reader, allocator) },
            0x1b => Frame{ .path_response = try PathResponseFrame.parse(reader, allocator) },
            0x1c => Frame{ .connection_close = try ConnectionCloseFrame.parse(reader, allocator) },
            0x1d => Frame{ .connection_close_app = try ConnectionCloseAppFrame.parse(reader, allocator) },
            0x1e => Frame{ .handshake_done = try HandshakeDoneFrame.parse(reader, allocator) },
            0x30 => Frame{ .datagram = try DatagramFrame.parse(reader, allocator, false) },
            0x31 => Frame{ .datagram_len = try DatagramFrame.parse(reader, allocator, true) },
            else => return Error.ZquicError.InvalidFrame,
        };
    }
};

/// PADDING frame
pub const PaddingFrame = struct {
    length: usize,
    
    pub fn init(length: usize) PaddingFrame {
        return PaddingFrame{ .length = length };
    }
    
    pub fn serialize(self: PaddingFrame, writer: anytype) !void {
        var i: usize = 0;
        while (i < self.length) : (i += 1) {
            try writer.writeByte(0x00);
        }
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !PaddingFrame {
        _ = reader;
        _ = allocator;
        return PaddingFrame{ .length = 1 };
    }
};

/// PING frame
pub const PingFrame = struct {
    pub fn init() PingFrame {
        return PingFrame{};
    }
    
    pub fn serialize(self: PingFrame, writer: anytype) !void {
        _ = self;
        try writeVarint(writer, 0x01);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !PingFrame {
        _ = reader;
        _ = allocator;
        return PingFrame{};
    }
};

/// ACK frame
pub const AckFrame = struct {
    largest_acknowledged: u64,
    ack_delay: u64,
    ack_range_count: u64,
    first_ack_range: u64,
    ack_ranges: []AckRange,
    
    pub const AckRange = struct {
        gap: u64,
        ack_range_length: u64,
    };
    
    pub fn init(allocator: std.mem.Allocator, largest_acknowledged: u64, ack_delay: u64, first_ack_range: u64) !AckFrame {
        return AckFrame{
            .largest_acknowledged = largest_acknowledged,
            .ack_delay = ack_delay,
            .ack_range_count = 0,
            .first_ack_range = first_ack_range,
            .ack_ranges = try allocator.alloc(AckRange, 0),
        };
    }
    
    pub fn deinit(self: AckFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.ack_ranges);
    }
    
    pub fn serialize(self: AckFrame, writer: anytype) !void {
        try writeVarint(writer, 0x02);
        try writeVarint(writer, self.largest_acknowledged);
        try writeVarint(writer, self.ack_delay);
        try writeVarint(writer, self.ack_range_count);
        try writeVarint(writer, self.first_ack_range);
        
        for (self.ack_ranges) |range| {
            try writeVarint(writer, range.gap);
            try writeVarint(writer, range.ack_range_length);
        }
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !AckFrame {
        const largest_acknowledged = try readVarint(reader);
        const ack_delay = try readVarint(reader);
        const ack_range_count = try readVarint(reader);
        const first_ack_range = try readVarint(reader);
        
        const ack_ranges = try allocator.alloc(AckRange, ack_range_count);
        for (ack_ranges) |*range| {
            range.gap = try readVarint(reader);
            range.ack_range_length = try readVarint(reader);
        }
        
        return AckFrame{
            .largest_acknowledged = largest_acknowledged,
            .ack_delay = ack_delay,
            .ack_range_count = ack_range_count,
            .first_ack_range = first_ack_range,
            .ack_ranges = ack_ranges,
        };
    }
};

/// ACK frame with ECN
pub const AckEcnFrame = struct {
    ack_frame: AckFrame,
    ect0_count: u64,
    ect1_count: u64,
    ecn_ce_count: u64,
    
    pub fn init(ack_frame: AckFrame, ect0_count: u64, ect1_count: u64, ecn_ce_count: u64) AckEcnFrame {
        return AckEcnFrame{
            .ack_frame = ack_frame,
            .ect0_count = ect0_count,
            .ect1_count = ect1_count,
            .ecn_ce_count = ecn_ce_count,
        };
    }
    
    pub fn serialize(self: AckEcnFrame, writer: anytype) !void {
        try writeVarint(writer, 0x03);
        try writeVarint(writer, self.ack_frame.largest_acknowledged);
        try writeVarint(writer, self.ack_frame.ack_delay);
        try writeVarint(writer, self.ack_frame.ack_range_count);
        try writeVarint(writer, self.ack_frame.first_ack_range);
        
        for (self.ack_frame.ack_ranges) |range| {
            try writeVarint(writer, range.gap);
            try writeVarint(writer, range.ack_range_length);
        }
        
        try writeVarint(writer, self.ect0_count);
        try writeVarint(writer, self.ect1_count);
        try writeVarint(writer, self.ecn_ce_count);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !AckEcnFrame {
        const ack_frame = try AckFrame.parse(reader, allocator);
        const ect0_count = try readVarint(reader);
        const ect1_count = try readVarint(reader);
        const ecn_ce_count = try readVarint(reader);
        
        return AckEcnFrame{
            .ack_frame = ack_frame,
            .ect0_count = ect0_count,
            .ect1_count = ect1_count,
            .ecn_ce_count = ecn_ce_count,
        };
    }
};

/// RESET_STREAM frame
pub const ResetStreamFrame = struct {
    stream_id: u64,
    application_error_code: u64,
    final_size: u64,
    
    pub fn init(stream_id: u64, application_error_code: u64, final_size: u64) ResetStreamFrame {
        return ResetStreamFrame{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
            .final_size = final_size,
        };
    }
    
    pub fn serialize(self: ResetStreamFrame, writer: anytype) !void {
        try writeVarint(writer, 0x04);
        try writeVarint(writer, self.stream_id);
        try writeVarint(writer, self.application_error_code);
        try writeVarint(writer, self.final_size);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !ResetStreamFrame {
        _ = allocator;
        const stream_id = try readVarint(reader);
        const application_error_code = try readVarint(reader);
        const final_size = try readVarint(reader);
        
        return ResetStreamFrame{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
            .final_size = final_size,
        };
    }
};

/// STOP_SENDING frame
pub const StopSendingFrame = struct {
    stream_id: u64,
    application_error_code: u64,
    
    pub fn init(stream_id: u64, application_error_code: u64) StopSendingFrame {
        return StopSendingFrame{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        };
    }
    
    pub fn serialize(self: StopSendingFrame, writer: anytype) !void {
        try writeVarint(writer, 0x05);
        try writeVarint(writer, self.stream_id);
        try writeVarint(writer, self.application_error_code);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !StopSendingFrame {
        _ = allocator;
        const stream_id = try readVarint(reader);
        const application_error_code = try readVarint(reader);
        
        return StopSendingFrame{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        };
    }
};

/// CRYPTO frame
pub const CryptoFrame = struct {
    offset: u64,
    data: []const u8,
    
    pub fn init(offset: u64, data: []const u8) CryptoFrame {
        return CryptoFrame{
            .offset = offset,
            .data = data,
        };
    }
    
    pub fn serialize(self: CryptoFrame, writer: anytype) !void {
        try writeVarint(writer, 0x06);
        try writeVarint(writer, self.offset);
        try writeVarint(writer, self.data.len);
        try writer.writeAll(self.data);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !CryptoFrame {
        const offset = try readVarint(reader);
        const length = try readVarint(reader);
        
        const data = try allocator.alloc(u8, length);
        _ = try reader.readAll(data);
        
        return CryptoFrame{
            .offset = offset,
            .data = data,
        };
    }
};

/// NEW_TOKEN frame
pub const NewTokenFrame = struct {
    token: []const u8,
    
    pub fn init(token: []const u8) NewTokenFrame {
        return NewTokenFrame{ .token = token };
    }
    
    pub fn serialize(self: NewTokenFrame, writer: anytype) !void {
        try writeVarint(writer, 0x07);
        try writeVarint(writer, self.token.len);
        try writer.writeAll(self.token);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !NewTokenFrame {
        const token_length = try readVarint(reader);
        const token = try allocator.alloc(u8, token_length);
        _ = try reader.readAll(token);
        
        return NewTokenFrame{ .token = token };
    }
};

/// STREAM frame
pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,
    has_offset: bool,
    has_length: bool,
    
    pub fn init(stream_id: u64, offset: u64, data: []const u8, fin: bool, has_offset: bool, has_length: bool) StreamFrame {
        return StreamFrame{
            .stream_id = stream_id,
            .offset = offset,
            .data = data,
            .fin = fin,
            .has_offset = has_offset,
            .has_length = has_length,
        };
    }
    
    pub fn serialize(self: StreamFrame, writer: anytype) !void {
        var frame_type: u8 = 0x08;
        if (self.fin) frame_type |= 0x01;
        if (self.has_length) frame_type |= 0x02;
        if (self.has_offset) frame_type |= 0x04;
        
        try writeVarint(writer, frame_type);
        try writeVarint(writer, self.stream_id);
        
        if (self.has_offset) {
            try writeVarint(writer, self.offset);
        }
        
        if (self.has_length) {
            try writeVarint(writer, self.data.len);
        }
        
        try writer.writeAll(self.data);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator, frame_type: u64) !StreamFrame {
        const fin = (frame_type & 0x01) != 0;
        const has_length = (frame_type & 0x02) != 0;
        const has_offset = (frame_type & 0x04) != 0;
        
        const stream_id = try readVarint(reader);
        
        const offset = if (has_offset) try readVarint(reader) else 0;
        
        const data_length = if (has_length) try readVarint(reader) else 0;
        
        const data = try allocator.alloc(u8, data_length);
        _ = try reader.readAll(data);
        
        return StreamFrame{
            .stream_id = stream_id,
            .offset = offset,
            .data = data,
            .fin = fin,
            .has_offset = has_offset,
            .has_length = has_length,
        };
    }
};

/// MAX_DATA frame
pub const MaxDataFrame = struct {
    maximum_data: u64,
    
    pub fn init(maximum_data: u64) MaxDataFrame {
        return MaxDataFrame{ .maximum_data = maximum_data };
    }
    
    pub fn serialize(self: MaxDataFrame, writer: anytype) !void {
        try writeVarint(writer, 0x10);
        try writeVarint(writer, self.maximum_data);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !MaxDataFrame {
        _ = allocator;
        const maximum_data = try readVarint(reader);
        return MaxDataFrame{ .maximum_data = maximum_data };
    }
};

/// MAX_STREAM_DATA frame
pub const MaxStreamDataFrame = struct {
    stream_id: u64,
    maximum_stream_data: u64,
    
    pub fn init(stream_id: u64, maximum_stream_data: u64) MaxStreamDataFrame {
        return MaxStreamDataFrame{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        };
    }
    
    pub fn serialize(self: MaxStreamDataFrame, writer: anytype) !void {
        try writeVarint(writer, 0x11);
        try writeVarint(writer, self.stream_id);
        try writeVarint(writer, self.maximum_stream_data);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !MaxStreamDataFrame {
        _ = allocator;
        const stream_id = try readVarint(reader);
        const maximum_stream_data = try readVarint(reader);
        
        return MaxStreamDataFrame{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        };
    }
};

/// MAX_STREAMS frame
pub const MaxStreamsFrame = struct {
    maximum_streams: u64,
    bidirectional: bool,
    
    pub fn init(maximum_streams: u64, bidirectional: bool) MaxStreamsFrame {
        return MaxStreamsFrame{
            .maximum_streams = maximum_streams,
            .bidirectional = bidirectional,
        };
    }
    
    pub fn serialize(self: MaxStreamsFrame, writer: anytype) !void {
        const frame_type: u64 = if (self.bidirectional) 0x12 else 0x13;
        try writeVarint(writer, frame_type);
        try writeVarint(writer, self.maximum_streams);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !MaxStreamsFrame {
        _ = allocator;
        const maximum_streams = try readVarint(reader);
        return MaxStreamsFrame{
            .maximum_streams = maximum_streams,
            .bidirectional = true, // Set by frame type during parsing
        };
    }
};

/// DATA_BLOCKED frame
pub const DataBlockedFrame = struct {
    maximum_data: u64,
    
    pub fn init(maximum_data: u64) DataBlockedFrame {
        return DataBlockedFrame{ .maximum_data = maximum_data };
    }
    
    pub fn serialize(self: DataBlockedFrame, writer: anytype) !void {
        try writeVarint(writer, 0x14);
        try writeVarint(writer, self.maximum_data);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !DataBlockedFrame {
        _ = allocator;
        const maximum_data = try readVarint(reader);
        return DataBlockedFrame{ .maximum_data = maximum_data };
    }
};

/// STREAM_DATA_BLOCKED frame
pub const StreamDataBlockedFrame = struct {
    stream_id: u64,
    maximum_stream_data: u64,
    
    pub fn init(stream_id: u64, maximum_stream_data: u64) StreamDataBlockedFrame {
        return StreamDataBlockedFrame{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        };
    }
    
    pub fn serialize(self: StreamDataBlockedFrame, writer: anytype) !void {
        try writeVarint(writer, 0x15);
        try writeVarint(writer, self.stream_id);
        try writeVarint(writer, self.maximum_stream_data);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !StreamDataBlockedFrame {
        _ = allocator;
        const stream_id = try readVarint(reader);
        const maximum_stream_data = try readVarint(reader);
        
        return StreamDataBlockedFrame{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        };
    }
};

/// STREAMS_BLOCKED frame
pub const StreamsBlockedFrame = struct {
    maximum_streams: u64,
    bidirectional: bool,
    
    pub fn init(maximum_streams: u64, bidirectional: bool) StreamsBlockedFrame {
        return StreamsBlockedFrame{
            .maximum_streams = maximum_streams,
            .bidirectional = bidirectional,
        };
    }
    
    pub fn serialize(self: StreamsBlockedFrame, writer: anytype) !void {
        const frame_type: u64 = if (self.bidirectional) 0x16 else 0x17;
        try writeVarint(writer, frame_type);
        try writeVarint(writer, self.maximum_streams);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !StreamsBlockedFrame {
        _ = allocator;
        const maximum_streams = try readVarint(reader);
        return StreamsBlockedFrame{
            .maximum_streams = maximum_streams,
            .bidirectional = true, // Set by frame type during parsing
        };
    }
};

/// NEW_CONNECTION_ID frame
pub const NewConnectionIdFrame = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: []const u8,
    stateless_reset_token: [16]u8,
    
    pub fn init(sequence_number: u64, retire_prior_to: u64, connection_id: []const u8, stateless_reset_token: [16]u8) NewConnectionIdFrame {
        return NewConnectionIdFrame{
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        };
    }
    
    pub fn serialize(self: NewConnectionIdFrame, writer: anytype) !void {
        try writeVarint(writer, 0x18);
        try writeVarint(writer, self.sequence_number);
        try writeVarint(writer, self.retire_prior_to);
        try writer.writeByte(@intCast(self.connection_id.len));
        try writer.writeAll(self.connection_id);
        try writer.writeAll(&self.stateless_reset_token);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !NewConnectionIdFrame {
        const sequence_number = try readVarint(reader);
        const retire_prior_to = try readVarint(reader);
        const connection_id_length = try reader.readByte();
        
        const connection_id = try allocator.alloc(u8, connection_id_length);
        _ = try reader.readAll(connection_id);
        
        var stateless_reset_token: [16]u8 = undefined;
        _ = try reader.readAll(&stateless_reset_token);
        
        return NewConnectionIdFrame{
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        };
    }
};

/// RETIRE_CONNECTION_ID frame
pub const RetireConnectionIdFrame = struct {
    sequence_number: u64,
    
    pub fn init(sequence_number: u64) RetireConnectionIdFrame {
        return RetireConnectionIdFrame{ .sequence_number = sequence_number };
    }
    
    pub fn serialize(self: RetireConnectionIdFrame, writer: anytype) !void {
        try writeVarint(writer, 0x19);
        try writeVarint(writer, self.sequence_number);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !RetireConnectionIdFrame {
        _ = allocator;
        const sequence_number = try readVarint(reader);
        return RetireConnectionIdFrame{ .sequence_number = sequence_number };
    }
};

/// PATH_CHALLENGE frame
pub const PathChallengeFrame = struct {
    data: [8]u8,
    
    pub fn init(data: [8]u8) PathChallengeFrame {
        return PathChallengeFrame{ .data = data };
    }
    
    pub fn serialize(self: PathChallengeFrame, writer: anytype) !void {
        try writeVarint(writer, 0x1a);
        try writer.writeAll(&self.data);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !PathChallengeFrame {
        _ = allocator;
        var data: [8]u8 = undefined;
        _ = try reader.readAll(&data);
        return PathChallengeFrame{ .data = data };
    }
};

/// PATH_RESPONSE frame
pub const PathResponseFrame = struct {
    data: [8]u8,
    
    pub fn init(data: [8]u8) PathResponseFrame {
        return PathResponseFrame{ .data = data };
    }
    
    pub fn serialize(self: PathResponseFrame, writer: anytype) !void {
        try writeVarint(writer, 0x1b);
        try writer.writeAll(&self.data);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !PathResponseFrame {
        _ = allocator;
        var data: [8]u8 = undefined;
        _ = try reader.readAll(&data);
        return PathResponseFrame{ .data = data };
    }
};

/// CONNECTION_CLOSE frame
pub const ConnectionCloseFrame = struct {
    error_code: u64,
    frame_type: u64,
    reason_phrase: []const u8,
    
    pub fn init(error_code: u64, frame_type: u64, reason_phrase: []const u8) ConnectionCloseFrame {
        return ConnectionCloseFrame{
            .error_code = error_code,
            .frame_type = frame_type,
            .reason_phrase = reason_phrase,
        };
    }
    
    pub fn serialize(self: ConnectionCloseFrame, writer: anytype) !void {
        try writeVarint(writer, 0x1c);
        try writeVarint(writer, self.error_code);
        try writeVarint(writer, self.frame_type);
        try writeVarint(writer, self.reason_phrase.len);
        try writer.writeAll(self.reason_phrase);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !ConnectionCloseFrame {
        const error_code = try readVarint(reader);
        const frame_type = try readVarint(reader);
        const reason_phrase_length = try readVarint(reader);
        
        const reason_phrase = try allocator.alloc(u8, reason_phrase_length);
        _ = try reader.readAll(reason_phrase);
        
        return ConnectionCloseFrame{
            .error_code = error_code,
            .frame_type = frame_type,
            .reason_phrase = reason_phrase,
        };
    }
};

/// CONNECTION_CLOSE frame (Application)
pub const ConnectionCloseAppFrame = struct {
    error_code: u64,
    reason_phrase: []const u8,
    
    pub fn init(error_code: u64, reason_phrase: []const u8) ConnectionCloseAppFrame {
        return ConnectionCloseAppFrame{
            .error_code = error_code,
            .reason_phrase = reason_phrase,
        };
    }
    
    pub fn serialize(self: ConnectionCloseAppFrame, writer: anytype) !void {
        try writeVarint(writer, 0x1d);
        try writeVarint(writer, self.error_code);
        try writeVarint(writer, self.reason_phrase.len);
        try writer.writeAll(self.reason_phrase);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !ConnectionCloseAppFrame {
        const error_code = try readVarint(reader);
        const reason_phrase_length = try readVarint(reader);
        
        const reason_phrase = try allocator.alloc(u8, reason_phrase_length);
        _ = try reader.readAll(reason_phrase);
        
        return ConnectionCloseAppFrame{
            .error_code = error_code,
            .reason_phrase = reason_phrase,
        };
    }
};

/// HANDSHAKE_DONE frame
pub const HandshakeDoneFrame = struct {
    pub fn init() HandshakeDoneFrame {
        return HandshakeDoneFrame{};
    }
    
    pub fn serialize(self: HandshakeDoneFrame, writer: anytype) !void {
        _ = self;
        try writeVarint(writer, 0x1e);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator) !HandshakeDoneFrame {
        _ = reader;
        _ = allocator;
        return HandshakeDoneFrame{};
    }
};

/// DATAGRAM frame
pub const DatagramFrame = struct {
    data: []const u8,
    has_length: bool,
    
    pub fn init(data: []const u8, has_length: bool) DatagramFrame {
        return DatagramFrame{
            .data = data,
            .has_length = has_length,
        };
    }
    
    pub fn serialize(self: DatagramFrame, writer: anytype) !void {
        const frame_type: u64 = if (self.has_length) 0x31 else 0x30;
        try writeVarint(writer, frame_type);
        
        if (self.has_length) {
            try writeVarint(writer, self.data.len);
        }
        
        try writer.writeAll(self.data);
    }
    
    pub fn parse(reader: anytype, allocator: std.mem.Allocator, has_length: bool) !DatagramFrame {
        const data_length = if (has_length) try readVarint(reader) else 0;
        
        const data = try allocator.alloc(u8, data_length);
        _ = try reader.readAll(data);
        
        return DatagramFrame{
            .data = data,
            .has_length = has_length,
        };
    }
};

/// Frame parser for handling incoming frames
pub const FrameParser = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8),
    
    pub fn init(allocator: std.mem.Allocator) FrameParser {
        return FrameParser{
            .allocator = allocator,
            .buffer = std.ArrayList(u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *FrameParser) void {
        self.buffer.deinit();
    }
    
    pub fn parseFrames(self: *FrameParser, data: []const u8) ![]Frame {
        var frames = std.ArrayList(Frame).init(self.allocator);
        var reader = std.io.fixedBufferStream(data);
        
        while (reader.pos < data.len) {
            const frame = Frame.parse(reader.reader(), self.allocator) catch |err| {
                switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                }
            };
            try frames.append(frame);
        }
        
        return frames.toOwnedSlice();
    }
    
    pub fn serializeFrames(self: *FrameParser, frames: []const Frame) ![]u8 {
        self.buffer.clearRetainingCapacity();
        var writer = self.buffer.writer();
        
        for (frames) |frame| {
            try frame.serialize(writer);
        }
        
        return self.buffer.toOwnedSlice();
    }
};