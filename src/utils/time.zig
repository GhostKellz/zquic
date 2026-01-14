//! Time utilities for ZQUIC
//! Provides portable sleep helpers compatible with Zig 0.16.0-dev.

const std = @import("std");
const builtin = @import("builtin");

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
    const instant = std.time.Instant.now() catch return 0;
    return instant.timestamp.sec;
}

/// Return current timestamp in microseconds without propagating errors.
pub fn nowMicros() i64 {
    const instant = std.time.Instant.now() catch return 0;

    const micros = @as(i128, instant.timestamp.sec) * std.time.us_per_s + instant.timestamp.nsec / std.time.ns_per_us;
    return @intCast(micros);
}
