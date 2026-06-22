//! Low-level socket operations isolated from QUIC transport logic.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const NetAddress = @import("address.zig");

pub const Socket = posix.socket_t;
pub const PosixAddress = NetAddress.PosixAddress;

pub fn createDatagramSocket(local_address: *const NetAddress.Address) !Socket {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.socket(
            @intCast(NetAddress.family(local_address)),
            linux.SOCK.DGRAM | linux.SOCK.CLOEXEC,
            linux.IPPROTO.UDP,
        );
        return switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .ACCES => error.PermissionDenied,
            .AFNOSUPPORT => error.AddressFamilyNotSupported,
            .MFILE => error.ProcessFdQuotaExceeded,
            .NFILE => error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => error.SystemResources,
            .PROTONOSUPPORT => error.ProtocolNotSupported,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    @compileError("zquic net.sys needs socket support for this target");
}

pub fn bind(socket_fd: Socket, bind_addr: *const PosixAddress, bind_addr_len: posix.socklen_t) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.bind(socket_fd, @ptrCast(bind_addr), bind_addr_len);
        return switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES => error.AccessDenied,
            .ADDRINUSE => error.AddressInUse,
            .ADDRNOTAVAIL => error.AddressNotAvailable,
            .AFNOSUPPORT => error.AddressFamilyNotSupported,
            .BADF => error.FileDescriptorNotASocket,
            .INVAL => error.InvalidArgument,
            .NOTSOCK => error.FileDescriptorNotASocket,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    @compileError("zquic net.sys needs bind support for this target");
}

pub fn getSocketName(socket_fd: Socket, bound_addr_storage: *PosixAddress, addr_len: *posix.socklen_t) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.getsockname(socket_fd, @ptrCast(bound_addr_storage), addr_len);
        return switch (linux.errno(rc)) {
            .SUCCESS => {},
            .BADF => error.FileDescriptorNotASocket,
            .FAULT => error.InvalidArgument,
            .INVAL => error.InvalidArgument,
            .NOTSOCK => error.FileDescriptorNotASocket,
            .NOBUFS => error.SystemResources,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    @compileError("zquic net.sys needs getsockname support for this target");
}

pub fn setReuseAddress(socket_fd: Socket, enabled: bool) !void {
    const value: c_int = if (enabled) 1 else 0;
    try posix.setsockopt(socket_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(value));
}

pub fn setReceiveBufferSize(socket_fd: Socket, size: usize) !void {
    const value: c_int = @intCast(@min(size, @as(usize, @intCast(std.math.maxInt(c_int)))));
    try posix.setsockopt(socket_fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(value));
}

pub fn setSendBufferSize(socket_fd: Socket, size: usize) !void {
    const value: c_int = @intCast(@min(size, @as(usize, @intCast(std.math.maxInt(c_int)))));
    try posix.setsockopt(socket_fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &std.mem.toBytes(value));
}

pub fn setNonBlocking(socket_fd: Socket, non_blocking: bool) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const flags_rc = linux.fcntl(socket_fd, linux.F.GETFL, 0);
        const flags: u32 = switch (linux.errno(flags_rc)) {
            .SUCCESS => @intCast(flags_rc),
            else => |err| return posix.unexpectedErrno(err),
        };

        const new_flags = if (non_blocking)
            flags | @as(u32, linux.O.NONBLOCK)
        else
            flags & ~@as(u32, linux.O.NONBLOCK);

        const set_rc = linux.fcntl(socket_fd, linux.F.SETFL, new_flags);
        return switch (linux.errno(set_rc)) {
            .SUCCESS => {},
            else => |err| posix.unexpectedErrno(err),
        };
    }

    @compileError("zquic net.sys needs nonblocking socket support for this target");
}

pub fn sendTo(socket_fd: Socket, data: []const u8, dest_addr_storage: *const PosixAddress, dest_addr_len: posix.socklen_t) !usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.sendto(socket_fd, data.ptr, data.len, 0, @ptrCast(dest_addr_storage), dest_addr_len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .ACCES => error.AccessDenied,
            .AGAIN => error.WouldBlock,
            .BADF => error.FileDescriptorNotASocket,
            .CONNREFUSED => error.ConnectionRefused,
            .DESTADDRREQ => error.DestinationAddressRequired,
            .INTR => error.Interrupted,
            .INVAL => error.InvalidArgument,
            .MSGSIZE => error.MessageTooBig,
            .NETUNREACH => error.NetworkUnreachable,
            .NOBUFS, .NOMEM => error.SystemResources,
            .NOTSOCK => error.FileDescriptorNotASocket,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    @compileError("zquic net.sys needs sendto support for this target");
}

pub fn send(socket_fd: Socket, data: []const u8) !usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.sendto(socket_fd, data.ptr, data.len, 0, null, 0);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .ACCES => error.AccessDenied,
            .AGAIN => error.WouldBlock,
            .BADF => error.FileDescriptorNotASocket,
            .CONNRESET => error.ConnectionResetByPeer,
            .DESTADDRREQ => error.DestinationAddressRequired,
            .INTR => error.Interrupted,
            .INVAL => error.InvalidArgument,
            .MSGSIZE => error.MessageTooBig,
            .NETUNREACH => error.NetworkUnreachable,
            .NOBUFS, .NOMEM => error.SystemResources,
            .NOTCONN => error.SocketNotConnected,
            .NOTSOCK => error.FileDescriptorNotASocket,
            .PIPE => error.BrokenPipe,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    @compileError("zquic net.sys needs send support for this target");
}

pub fn receiveFrom(socket_fd: Socket, buffer: []u8, src_addr_storage: *PosixAddress, addr_len: *posix.socklen_t) !usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.recvfrom(socket_fd, buffer.ptr, buffer.len, 0, @ptrCast(src_addr_storage), addr_len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            .BADF => error.FileDescriptorNotASocket,
            .CONNREFUSED => error.ConnectionRefused,
            .FAULT => error.InvalidArgument,
            .INTR => error.Interrupted,
            .INVAL => error.InvalidArgument,
            .NOMEM => error.SystemResources,
            .NOTCONN => error.SocketNotConnected,
            .NOTSOCK => error.FileDescriptorNotASocket,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    @compileError("zquic net.sys needs recvfrom support for this target");
}

pub fn receive(socket_fd: Socket, buffer: []u8) !usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.recvfrom(socket_fd, buffer.ptr, buffer.len, 0, null, null);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            .BADF => error.FileDescriptorNotASocket,
            .CONNRESET => error.ConnectionResetByPeer,
            .FAULT => error.InvalidArgument,
            .INTR => error.Interrupted,
            .INVAL => error.InvalidArgument,
            .NOMEM => error.SystemResources,
            .NOTCONN => error.SocketNotConnected,
            .NOTSOCK => error.FileDescriptorNotASocket,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    @compileError("zquic net.sys needs recv support for this target");
}

pub fn close(socket_fd: Socket) void {
    _ = posix.system.close(socket_fd);
}
