pub const packages = struct {
    pub const @"zcrypto-0.8.6-rgQAI9g9DQDTxLJBz5QS6eF5rDIYloue7jV5YZysZCYl" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zcrypto-0.8.6-rgQAI9g9DQDTxLJBz5QS6eF5rDIYloue7jV5YZysZCYl";
        pub const build_zig = @import("zcrypto-0.8.6-rgQAI9g9DQDTxLJBz5QS6eF5rDIYloue7jV5YZysZCYl");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zsync", "zsync-0.5.4-KAuheV0SHQBxubuzXagj1oq5B2KE4VhMWTAAAaInwB2_" },
        };
    };
    pub const @"zsync-0.5.4-KAuheV0SHQBxubuzXagj1oq5B2KE4VhMWTAAAaInwB2_" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zsync-0.5.4-KAuheV0SHQBxubuzXagj1oq5B2KE4VhMWTAAAaInwB2_";
        pub const build_zig = @import("zsync-0.5.4-KAuheV0SHQBxubuzXagj1oq5B2KE4VhMWTAAAaInwB2_");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "zcrypto", "zcrypto-0.8.6-rgQAI9g9DQDTxLJBz5QS6eF5rDIYloue7jV5YZysZCYl" },
    .{ "zsync", "zsync-0.5.4-KAuheV0SHQBxubuzXagj1oq5B2KE4VhMWTAAAaInwB2_" },
};
