//! Synchronization helpers used by synchronous zquic internals.

const std = @import("std");

pub const SpinMutex = struct {
    state: std.atomic.Mutex = .unlocked,

    pub fn lock(self: *@This()) void {
        while (!self.state.tryLock()) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *@This()) void {
        self.state.unlock();
    }
};

test "spin mutex serializes a critical section" {
    var mutex = SpinMutex{};
    var value: u32 = 0;

    mutex.lock();
    value += 1;
    mutex.unlock();

    try std.testing.expectEqual(@as(u32, 1), value);
    try std.testing.expect(mutex.state.tryLock());
    mutex.unlock();
}
