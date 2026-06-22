//! ZQUIC Internal Event Loop
//!
//! Simple, efficient event loop for QUIC networking using poll/epoll.
//! No external dependencies - pure Zig stdlib.

const std = @import("std");
const posix = std.posix;
const Time = @import("../utils/time.zig");

/// Event types for the event loop
pub const EventType = enum {
    read,
    write,
    error_event,
    hangup,
};

/// Event callback function type
pub const EventCallback = *const fn (fd: posix.fd_t, event_type: EventType, user_data: ?*anyopaque) void;

/// Registered event handler
pub const EventHandler = struct {
    fd: posix.fd_t,
    events: u32,
    callback: EventCallback,
    user_data: ?*anyopaque,
};

/// Simple event loop using poll()
pub const EventLoop = struct {
    handlers: std.AutoHashMapUnmanaged(posix.fd_t, EventHandler),
    poll_fds: std.ArrayListUnmanaged(posix.pollfd),
    running: bool,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .handlers = .empty,
            .poll_fds = .empty,
            .running = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.handlers.deinit(self.allocator);
        self.poll_fds.deinit(self.allocator);
    }

    /// Register a file descriptor for events.
    /// If fd is already registered, updates the handler (idempotent).
    pub fn register(self: *Self, fd: posix.fd_t, events: u32, callback: EventCallback, user_data: ?*anyopaque) !void {
        const handler = EventHandler{
            .fd = fd,
            .events = events,
            .callback = callback,
            .user_data = user_data,
        };

        // Check if fd is already registered
        const existing = self.handlers.get(fd);
        try self.handlers.put(self.allocator, fd, handler);

        if (existing == null) {
            // Only add to poll_fds if this is a new registration
            try self.poll_fds.append(self.allocator, .{
                .fd = fd,
                .events = @intCast(events),
                .revents = 0,
            });
        } else {
            // Update existing poll_fd entry
            for (self.poll_fds.items) |*pfd| {
                if (pfd.fd == fd) {
                    pfd.events = @intCast(events);
                    break;
                }
            }
        }
    }

    /// Unregister a file descriptor.
    /// Removes all occurrences from poll_fds (idempotent).
    pub fn unregister(self: *Self, fd: posix.fd_t) void {
        _ = self.handlers.remove(fd);

        // Remove ALL occurrences from poll_fds (iterate backward to handle swapRemove correctly)
        var i: usize = self.poll_fds.items.len;
        while (i > 0) {
            i -= 1;
            if (self.poll_fds.items[i].fd == fd) {
                _ = self.poll_fds.swapRemove(i);
                // Continue checking in case of duplicates
            }
        }
    }

    /// Run the event loop once with timeout (milliseconds)
    pub fn pollOnce(self: *Self, timeout_ms: i32) !usize {
        if (self.poll_fds.items.len == 0) return 0;

        const ready = try posix.poll(self.poll_fds.items, timeout_ms);

        if (ready == 0) return 0; // Timeout

        var events_processed: usize = 0;

        for (self.poll_fds.items) |*pfd| {
            if (pfd.revents == 0) continue;

            if (self.handlers.get(pfd.fd)) |handler| {
                if (pfd.revents & posix.POLL.IN != 0) {
                    handler.callback(pfd.fd, .read, handler.user_data);
                    events_processed += 1;
                }
                if (pfd.revents & posix.POLL.OUT != 0) {
                    handler.callback(pfd.fd, .write, handler.user_data);
                    events_processed += 1;
                }
                if (pfd.revents & posix.POLL.ERR != 0) {
                    handler.callback(pfd.fd, .error_event, handler.user_data);
                    events_processed += 1;
                }
                if (pfd.revents & posix.POLL.HUP != 0) {
                    handler.callback(pfd.fd, .hangup, handler.user_data);
                    events_processed += 1;
                }
            }

            pfd.revents = 0;
        }

        return events_processed;
    }

    /// Run the event loop until stopped
    pub fn run(self: *Self) !void {
        self.running = true;
        while (self.running) {
            _ = try self.pollOnce(100); // 100ms timeout
        }
    }

    /// Stop the event loop
    pub fn stop(self: *Self) void {
        self.running = false;
    }
};

/// Timer for scheduling delayed operations
pub const Timer = struct {
    deadline_ns: i128,
    callback: *const fn (?*anyopaque) void,
    user_data: ?*anyopaque,
    repeating: bool,
    interval_ns: i128,

    const Self = @This();

    pub fn init(delay_ms: u64, callback: *const fn (?*anyopaque) void, user_data: ?*anyopaque) Self {
        const now = Time.nowNanos();
        return Self{
            .deadline_ns = now + @as(i128, delay_ms) * std.time.ns_per_ms,
            .callback = callback,
            .user_data = user_data,
            .repeating = false,
            .interval_ns = 0,
        };
    }

    pub fn initRepeating(interval_ms: u64, callback: *const fn (?*anyopaque) void, user_data: ?*anyopaque) Self {
        const now = Time.nowNanos();
        const interval = @as(i128, interval_ms) * std.time.ns_per_ms;
        return Self{
            .deadline_ns = now + interval,
            .callback = callback,
            .user_data = user_data,
            .repeating = true,
            .interval_ns = interval,
        };
    }

    pub fn isExpired(self: *const Self) bool {
        return Time.nowNanos() >= self.deadline_ns;
    }

    pub fn fire(self: *Self) void {
        self.callback(self.user_data);
        if (self.repeating) {
            self.deadline_ns = Time.nowNanos() + self.interval_ns;
        }
    }

    pub fn timeUntilDeadline(self: *const Self) i64 {
        const now = Time.nowNanos();
        const diff = self.deadline_ns - now;
        if (diff < 0) return 0;
        return @intCast(@divFloor(diff, std.time.ns_per_ms));
    }
};

/// Timer wheel for efficient timer management
pub const TimerWheel = struct {
    timers: std.ArrayListUnmanaged(Timer),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .timers = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.timers.deinit(self.allocator);
    }

    pub fn addTimer(self: *Self, timer: Timer) !void {
        try self.timers.append(self.allocator, timer);
    }

    pub fn cancelTimer(self: *Self, callback: *const fn (?*anyopaque) void, user_data: ?*anyopaque) bool {
        var i: usize = 0;
        while (i < self.timers.items.len) {
            const timer = self.timers.items[i];
            if (timer.callback == callback and timer.user_data == user_data) {
                _ = self.timers.swapRemove(i);
                return true;
            }
            i += 1;
        }
        return false;
    }

    /// Process expired timers, returns time until next timer (ms)
    pub fn tick(self: *Self) i64 {
        var min_wait: i64 = 1000; // Default 1 second

        var i: usize = 0;
        while (i < self.timers.items.len) {
            var timer = &self.timers.items[i];
            if (timer.isExpired()) {
                timer.fire();
                if (!timer.repeating) {
                    _ = self.timers.swapRemove(i);
                    continue;
                }
            }

            const wait = timer.timeUntilDeadline();
            if (wait < min_wait) {
                min_wait = wait;
            }
            i += 1;
        }

        return min_wait;
    }
};

test "event loop initialization" {
    var loop = EventLoop.init(std.testing.allocator);
    defer loop.deinit();

    try std.testing.expect(!loop.running);
}

test "timer expiration" {
    var fired = false;
    const callback = struct {
        fn cb(data: ?*anyopaque) void {
            const ptr: *bool = @ptrCast(@alignCast(data));
            ptr.* = true;
        }
    }.cb;

    var timer = Timer.init(0, callback, @ptrCast(&fired)); // 0ms = immediate
    try std.testing.expect(timer.isExpired());
    timer.fire();
    try std.testing.expect(fired);
}

test "timer wheel" {
    var wheel = TimerWheel.init(std.testing.allocator);
    defer wheel.deinit();

    var count: u32 = 0;
    const callback = struct {
        fn cb(data: ?*anyopaque) void {
            const ptr: *u32 = @ptrCast(@alignCast(data));
            ptr.* += 1;
        }
    }.cb;

    try wheel.addTimer(Timer.init(0, callback, @ptrCast(&count)));
    _ = wheel.tick();
    try std.testing.expect(count == 1);
}

test "timer wheel cancellation prevents callback" {
    var wheel = TimerWheel.init(std.testing.allocator);
    defer wheel.deinit();

    var count: u32 = 0;
    const callback = struct {
        fn cb(data: ?*anyopaque) void {
            const ptr: *u32 = @ptrCast(@alignCast(data));
            ptr.* += 1;
        }
    }.cb;

    try wheel.addTimer(Timer.init(0, callback, @ptrCast(&count)));
    try std.testing.expect(wheel.cancelTimer(callback, @ptrCast(&count)));
    try std.testing.expect(!wheel.cancelTimer(callback, @ptrCast(&count)));

    _ = wheel.tick();
    try std.testing.expectEqual(@as(u32, 0), count);
}
