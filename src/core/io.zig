//! QUIC I/O Interface Module
//!
//! Provides clean Reader/Writer abstractions for QUIC packet and stream I/O.
//! This module serves as a glue layer between QUIC's internal buffers and
//! Zig's standard library I/O patterns.
//!
//! Features:
//! - PacketReader/PacketWriter for UDP packet I/O
//! - StreamReader/StreamWriter for QUIC stream I/O
//! - BufferedReader/BufferedWriter for performance
//! - Explicit allocator management
//! - Error propagation aligned with Zig stdlib

const std = @import("std");
const Error = @import("../utils/error.zig");

/// Errors that can occur during I/O operations
pub const IoError = error{
    /// Connection closed during operation
    ConnectionClosed,
    /// Stream closed during operation
    StreamClosed,
    /// Buffer overflow - packet too large
    BufferOverflow,
    /// Invalid packet format
    InvalidPacket,
    /// Network error occurred
    NetworkError,
    /// Timeout waiting for data
    Timeout,
    /// Resource temporarily unavailable
    WouldBlock,
} || std.mem.Allocator.Error;

/// Generic Reader interface for QUIC data sources
pub fn Reader(comptime _: type, comptime Context: type) type {
    return struct {
        context: Context,
        readFn: *const fn (context: Context, buffer: []u8) IoError!usize,

        const Self = @This();

        /// Read data into the provided buffer
        pub fn read(self: Self, buffer: []u8) IoError!usize {
            return self.readFn(self.context, buffer);
        }

        /// Read exactly `len` bytes or return an error
        pub fn readAll(self: Self, buffer: []u8) IoError!void {
            var bytes_read: usize = 0;
            while (bytes_read < buffer.len) {
                const n = try self.read(buffer[bytes_read..]);
                if (n == 0) return IoError.ConnectionClosed;
                bytes_read += n;
            }
        }

        /// Read until delimiter or buffer is full
        pub fn readUntilDelimiter(
            self: Self,
            buffer: []u8,
            delimiter: u8,
        ) IoError![]u8 {
            var bytes_read: usize = 0;
            while (bytes_read < buffer.len) {
                const n = try self.read(buffer[bytes_read .. bytes_read + 1]);
                if (n == 0) return buffer[0..bytes_read];
                if (buffer[bytes_read] == delimiter) {
                    return buffer[0..bytes_read];
                }
                bytes_read += 1;
            }
            return buffer;
        }
    };
}

/// Generic Writer interface for QUIC data destinations
pub fn Writer(comptime _: type, comptime Context: type) type {
    return struct {
        context: Context,
        writeFn: *const fn (context: Context, bytes: []const u8) IoError!usize,

        const Self = @This();

        /// Write data from the provided buffer
        pub fn write(self: Self, bytes: []const u8) IoError!usize {
            return self.writeFn(self.context, bytes);
        }

        /// Write all bytes or return an error
        pub fn writeAll(self: Self, bytes: []const u8) IoError!void {
            var bytes_written: usize = 0;
            while (bytes_written < bytes.len) {
                const n = try self.write(bytes[bytes_written..]);
                if (n == 0) return IoError.ConnectionClosed;
                bytes_written += n;
            }
        }

        /// Write formatted data
        pub fn print(self: Self, comptime format: []const u8, args: anytype) IoError!void {
            // For now, use a fixed buffer - in real implementation would be dynamic
            var buffer: [4096]u8 = undefined;
            const formatted = std.fmt.bufPrint(&buffer, format, args) catch |err| switch (err) {
                error.NoSpaceLeft => return IoError.BufferOverflow,
            };
            try self.writeAll(formatted);
        }
    };
}

/// UDP packet reader for receiving QUIC packets from network
pub const PacketReader = struct {
    socket: std.posix.socket_t,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize packet reader with UDP socket
    pub fn init(allocator: std.mem.Allocator, socket: std.posix.socket_t) Self {
        return Self{
            .socket = socket,
            .allocator = allocator,
        };
    }

    /// Read packet context for the reader interface
    const ReadContext = *Self;

    /// Reader interface for packet reading
    pub const ReaderInterface = Reader(*Self, ReadContext);

    /// Get reader interface for this packet reader
    pub fn reader(self: *Self) ReaderInterface {
        return ReaderInterface{
            .context = self,
            .readFn = readPacket,
        };
    }

    /// Internal read function for packet reader
    fn readPacket(context: ReadContext, buffer: []u8) IoError!usize {
        const bytes_read = std.posix.recv(context.socket, buffer, 0) catch |err| switch (err) {
            error.WouldBlock => return IoError.WouldBlock,
            error.ConnectionResetByPeer => return IoError.ConnectionClosed,
            error.NetworkUnreachable => return IoError.NetworkError,
            else => return IoError.NetworkError,
        };
        return bytes_read;
    }

    /// Read packet with source address information
    pub fn readFrom(self: *Self, buffer: []u8, address: *std.net.Address) IoError!usize {
        var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
        const bytes_read = std.posix.recvfrom(
            self.socket,
            buffer,
            0,
            @ptrCast(&address.any),
            &addr_len,
        ) catch |err| switch (err) {
            error.WouldBlock => return IoError.WouldBlock,
            error.ConnectionResetByPeer => return IoError.ConnectionClosed,
            error.NetworkUnreachable => return IoError.NetworkError,
            else => return IoError.NetworkError,
        };
        return bytes_read;
    }
};

/// UDP packet writer for sending QUIC packets to network
pub const PacketWriter = struct {
    socket: std.posix.socket_t,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize packet writer with UDP socket
    pub fn init(allocator: std.mem.Allocator, socket: std.posix.socket_t) Self {
        return Self{
            .socket = socket,
            .allocator = allocator,
        };
    }

    /// Write context for the writer interface
    const WriteContext = *Self;

    /// Writer interface for packet writing
    pub const WriterInterface = Writer(*Self, WriteContext);

    /// Get writer interface for this packet writer
    pub fn writer(self: *Self) WriterInterface {
        return WriterInterface{
            .context = self,
            .writeFn = writePacket,
        };
    }

    /// Internal write function for packet writer
    fn writePacket(context: WriteContext, bytes: []const u8) IoError!usize {
        const bytes_written = std.posix.send(context.socket, bytes, 0) catch |err| switch (err) {
            error.WouldBlock => return IoError.WouldBlock,
            error.ConnectionResetByPeer => return IoError.ConnectionClosed,
            error.NetworkUnreachable => return IoError.NetworkError,
            else => return IoError.NetworkError,
        };
        return bytes_written;
    }

    /// Write packet to specific address
    pub fn writeTo(self: *Self, bytes: []const u8, address: std.net.Address) IoError!usize {
        const bytes_written = std.posix.sendto(
            self.socket,
            bytes,
            0,
            &address.any,
            address.getOsSockLen(),
        ) catch |err| switch (err) {
            error.WouldBlock => return IoError.WouldBlock,
            error.ConnectionResetByPeer => return IoError.ConnectionClosed,
            error.NetworkUnreachable => return IoError.NetworkError,
            else => return IoError.NetworkError,
        };
        return bytes_written;
    }
};

/// QUIC stream reader for application data
pub const StreamReader = struct {
    stream_id: u64,
    buffer: std.ArrayList(u8),
    offset: usize,
    closed: bool,

    const Self = @This();

    /// Initialize stream reader
    pub fn init(allocator: std.mem.Allocator, stream_id: u64) Self {
        return Self{
            .stream_id = stream_id,
            .buffer = .{ },
            .offset = 0,
            .closed = false,
        };
    }

    /// Clean up stream reader
    pub fn deinit(self: *Self) void {
        self.buffer.deinit();
    }

    /// Read context for the reader interface
    const ReadContext = *Self;

    /// Reader interface for stream reading
    pub const ReaderInterface = Reader(*Self, ReadContext);

    /// Get reader interface for this stream reader
    pub fn reader(self: *Self) ReaderInterface {
        return ReaderInterface{
            .context = self,
            .readFn = readStream,
        };
    }

    /// Internal read function for stream reader
    fn readStream(context: ReadContext, buffer: []u8) IoError!usize {
        if (context.closed and context.offset >= context.buffer.items.len) {
            return 0; // EOF
        }

        const available = context.buffer.items.len - context.offset;
        const to_read = @min(buffer.len, available);

        if (to_read == 0) {
            if (context.closed) return 0;
            return IoError.WouldBlock;
        }

        @memcpy(buffer[0..to_read], context.buffer.items[context.offset .. context.offset + to_read]);
        context.offset += to_read;
        return to_read;
    }

    /// Add data to stream buffer (called by QUIC implementation)
    pub fn addData(self: *Self, data: []const u8) IoError!void {
        try self.buffer.appendSlice(self.buffer.allocator, data);
    }

    /// Mark stream as closed
    pub fn close(self: *Self) void {
        self.closed = true;
    }

    /// Check if stream has data available
    pub fn hasData(self: *Self) bool {
        return self.offset < self.buffer.items.len;
    }
};

/// QUIC stream writer for application data
pub const StreamWriter = struct {
    stream_id: u64,
    send_buffer: std.ArrayList(u8),
    closed: bool,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize stream writer
    pub fn init(allocator: std.mem.Allocator, stream_id: u64) Self {
        return Self{
            .stream_id = stream_id,
            .send_buffer = .{ },
            .closed = false,
            .allocator = allocator,
        };
    }

    /// Clean up stream writer
    pub fn deinit(self: *Self) void {
        self.send_buffer.deinit();
    }

    /// Write context for the writer interface
    const WriteContext = *Self;

    /// Writer interface for stream writing
    pub const WriterInterface = Writer(*Self, WriteContext);

    /// Get writer interface for this stream writer
    pub fn writer(self: *Self) WriterInterface {
        return WriterInterface{
            .context = self,
            .writeFn = writeStream,
        };
    }

    /// Internal write function for stream writer
    fn writeStream(context: WriteContext, bytes: []const u8) IoError!usize {
        if (context.closed) return IoError.StreamClosed;

        try context.send_buffer.appendSlice(context.allocator, bytes);
        return bytes.len;
    }

    /// Flush buffered data (called by QUIC implementation)
    pub fn flush(self: *Self) IoError![]const u8 {
        if (self.send_buffer.items.len == 0) return &[_]u8{};

        const data = try self.send_buffer.toOwnedSlice(self.allocator);
        return data;
    }

    /// Close stream for writing
    pub fn close(self: *Self) void {
        self.closed = true;
    }

    /// Check if stream has buffered data to send
    pub fn hasPendingData(self: *Self) bool {
        return self.send_buffer.items.len > 0;
    }
};

/// Buffered reader wrapper for improved performance
pub fn BufferedReader(comptime ReaderType: type) type {
    return struct {
        unbuffered_reader: ReaderType,
        buffer: []u8,
        start: usize,
        end: usize,

        const Self = @This();

        /// Initialize buffered reader
        pub fn init(reader: ReaderType, buffer: []u8) Self {
            return Self{
                .unbuffered_reader = reader,
                .buffer = buffer,
                .start = 0,
                .end = 0,
            };
        }

        /// Fill internal buffer from underlying reader
        fn fillBuffer(self: *Self) IoError!void {
            if (self.start < self.end) return; // Buffer has data

            const bytes_read = try self.unbuffered_reader.read(self.buffer);
            self.start = 0;
            self.end = bytes_read;
        }

        /// Read from buffered reader
        pub fn read(self: *Self, dest: []u8) IoError!usize {
            if (self.start >= self.end) {
                try self.fillBuffer();
                if (self.start >= self.end) return 0; // EOF
            }

            const available = self.end - self.start;
            const to_read = @min(dest.len, available);
            @memcpy(dest[0..to_read], self.buffer[self.start .. self.start + to_read]);
            self.start += to_read;
            return to_read;
        }
    };
}

/// Buffered writer wrapper for improved performance
pub fn BufferedWriter(comptime WriterType: type) type {
    return struct {
        unbuffered_writer: WriterType,
        buffer: []u8,
        end: usize,

        const Self = @This();

        /// Initialize buffered writer
        pub fn init(writer: WriterType, buffer: []u8) Self {
            return Self{
                .unbuffered_writer = writer,
                .buffer = buffer,
                .end = 0,
            };
        }

        /// Flush internal buffer to underlying writer
        pub fn flush(self: *Self) IoError!void {
            if (self.end == 0) return;

            try self.unbuffered_writer.writeAll(self.buffer[0..self.end]);
            self.end = 0;
        }

        /// Write to buffered writer
        pub fn write(self: *Self, bytes: []const u8) IoError!usize {
            if (bytes.len >= self.buffer.len) {
                // Large write - flush buffer and write directly
                try self.flush();
                return self.unbuffered_writer.write(bytes);
            }

            if (self.end + bytes.len > self.buffer.len) {
                try self.flush();
            }

            @memcpy(self.buffer[self.end .. self.end + bytes.len], bytes);
            self.end += bytes.len;
            return bytes.len;
        }

        /// Write all bytes to buffered writer
        pub fn writeAll(self: *Self, bytes: []const u8) IoError!void {
            var bytes_written: usize = 0;
            while (bytes_written < bytes.len) {
                const n = try self.write(bytes[bytes_written..]);
                bytes_written += n;
            }
        }
    };
}

// Tests
test "packet reader/writer initialization" {
    const allocator = std.testing.allocator;

    // Mock socket for testing
    const mock_socket: std.posix.socket_t = 0;

    var packet_reader = PacketReader.init(allocator, mock_socket);
    var packet_writer = PacketWriter.init(allocator, mock_socket);

    // Test reader interface
    const reader = packet_reader.reader();
    _ = reader;

    // Test writer interface
    const writer = packet_writer.writer();
    _ = writer;
}

test "stream reader/writer operations" {
    const allocator = std.testing.allocator;

    var stream_reader = StreamReader.init(allocator, 1);
    defer stream_reader.deinit();

    var stream_writer = StreamWriter.init(allocator, 2);
    defer stream_writer.deinit();

    // Test adding data to reader
    try stream_reader.addData("hello world");
    try std.testing.expect(stream_reader.hasData());

    // Test reading data
    var buffer: [20]u8 = undefined;
    const reader = stream_reader.reader();
    const bytes_read = try reader.read(&buffer);
    try std.testing.expectEqual(@as(usize, 11), bytes_read);
    try std.testing.expectEqualStrings("hello world", buffer[0..bytes_read]);

    // Test writing data
    const writer = stream_writer.writer();
    const bytes_written = try writer.write("test data");
    try std.testing.expectEqual(@as(usize, 9), bytes_written);
    try std.testing.expect(stream_writer.hasPendingData());
}

test "buffered I/O operations" {
    const allocator = std.testing.allocator;

    // Create a mock stream for testing
    var stream_reader = StreamReader.init(allocator, 1);
    defer stream_reader.deinit();

    try stream_reader.addData("abcdefghijklmnopqrstuvwxyz");

    // Test buffered reader
    var buffer: [10]u8 = undefined;
    var buffered = BufferedReader(StreamReader.ReaderInterface).init(stream_reader.reader(), &buffer);

    var read_buffer: [5]u8 = undefined;
    const bytes_read = try buffered.read(&read_buffer);
    try std.testing.expectEqual(@as(usize, 5), bytes_read);
}
