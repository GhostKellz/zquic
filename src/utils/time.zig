//! Time utilities for ZQUIC
//! Provides portable sleep and time helpers compatible with Zig 0.17.0-dev.

const std = @import("std");
const builtin = @import("builtin");

/// Platform-specific timespec type
pub const Timespec = switch (builtin.os.tag) {
    .linux => std.os.linux.timespec,
    .windows => struct { sec: i64, nsec: i64 },
    else => extern struct { sec: isize, nsec: isize },
};

/// Get current time using platform-specific clock.
/// Returns a timespec with seconds and nanoseconds.
fn getClockTime() Timespec {
    switch (builtin.os.tag) {
        .linux => {
            const linux = std.os.linux;
            var ts: linux.timespec = undefined;
            const result = linux.clock_gettime(.REALTIME, &ts);
            if (result != 0) {
                return .{ .sec = 0, .nsec = 0 };
            }
            return ts;
        },
        .windows => {
            // Windows: use GetSystemTimeAsFileTime
            var ft: std.os.windows.FILETIME = undefined;
            std.os.windows.GetSystemTimeAsFileTime(&ft);
            const ft_u64 = (@as(u64, ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
            // Convert from 100-nanosecond intervals since 1601 to Unix epoch
            const unix_epoch_diff: u64 = 116444736000000000;
            if (ft_u64 < unix_epoch_diff) {
                return .{ .sec = 0, .nsec = 0 };
            }
            const intervals = ft_u64 - unix_epoch_diff;
            const sec: i64 = @intCast(intervals / 10000000);
            const nsec: i64 = @intCast((intervals % 10000000) * 100);
            return .{ .sec = sec, .nsec = nsec };
        },
        else => {
            @compileError("getClockTime not implemented for this platform");
        },
    }
}

/// Sleep for the specified number of nanoseconds.
/// Falls back to platform-specific implementations now that std.time.sleep
/// has been removed from Zig's standard library.
pub fn sleep(ns: u64) void {
    if (ns == 0) return;

    switch (builtin.os.tag) {
        .windows => {
            const raw_ms = if (ns < std.time.ns_per_ms) 1 else ns / std.time.ns_per_ms;
            // Windows Sleep API only accepts milliseconds; clamp to u32 max.
            const clamped = @min(raw_ms, std.math.maxInt(u32));
            std.os.windows.Sleep(@intCast(clamped));
        },
        .linux => {
            const linux = std.os.linux;
            const req = linux.timespec{
                .sec = @intCast(ns / std.time.ns_per_s),
                .nsec = @intCast(ns % std.time.ns_per_s),
            };
            _ = linux.nanosleep(&req, null);
        },
        else => {
            // For other POSIX platforms, use clock_nanosleep or similar
            const seconds = ns / std.time.ns_per_s;
            const nanoseconds = ns % std.time.ns_per_s;
            _ = seconds;
            _ = nanoseconds;
            @compileError("sleep not implemented for this platform");
        },
    }
}

/// Return current UNIX timestamp in seconds without propagating errors.
pub fn nowSeconds() i64 {
    const ts = getClockTime();
    return @intCast(ts.sec);
}

/// Return current timestamp in microseconds without propagating errors.
pub fn nowMicros() i64 {
    const ts = getClockTime();
    const micros = @as(i128, ts.sec) * std.time.us_per_s + @divTrunc(ts.nsec, std.time.ns_per_us);
    return @intCast(micros);
}

/// Return current timestamp in nanoseconds without propagating errors.
/// Returns 0 on clock failure (safe fallback for production).
pub fn nowNanos() i128 {
    const ts = getClockTime();
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

/// Return current timestamp as timespec without propagating errors.
/// Returns zero timespec on failure.
pub fn nowTimespec() Timespec {
    return getClockTime();
}
