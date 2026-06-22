//! Performance-oriented helpers for pooling and zero-copy packet processing.

const build_options = @import("build_options");

pub const ConnectionPool = @import("performance/connection_pool.zig");
pub const ZeroCopy = @import("performance/zero_copy.zig");

pub const CryptoConnectionMultiplexer = if (build_options.enable_post_quantum)
    @import("performance/crypto_connection_multiplexer.zig")
else
    struct {};

test {
    _ = ConnectionPool;
    _ = ZeroCopy;
    _ = CryptoConnectionMultiplexer;
}
