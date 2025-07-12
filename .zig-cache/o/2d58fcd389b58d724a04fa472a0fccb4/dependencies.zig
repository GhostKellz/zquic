pub const packages = struct {
    pub const @"tokioZ-1.0.1-P0qt07Z-AwDM-WcpwjDbb0cIN4qQaTHpDuuszJ4bus5D" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/tokioZ-1.0.1-P0qt07Z-AwDM-WcpwjDbb0cIN4qQaTHpDuuszJ4bus5D";
        pub const build_zig = @import("tokioZ-1.0.1-P0qt07Z-AwDM-WcpwjDbb0cIN4qQaTHpDuuszJ4bus5D");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"zcrypto-0.8.0-rgQAI_VdDACh_Pg5kR_69RAOSaAQ5KmbLmOL0_rstGMH" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zcrypto-0.8.0-rgQAI_VdDACh_Pg5kR_69RAOSaAQ5KmbLmOL0_rstGMH";
        pub const build_zig = @import("zcrypto-0.8.0-rgQAI_VdDACh_Pg5kR_69RAOSaAQ5KmbLmOL0_rstGMH");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "tokioZ", "tokioZ-1.0.1-P0qt07Z-AwDM-WcpwjDbb0cIN4qQaTHpDuuszJ4bus5D" },
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "zcrypto", "zcrypto-0.8.0-rgQAI_VdDACh_Pg5kR_69RAOSaAQ5KmbLmOL0_rstGMH" },
    .{ "tokioZ", "tokioZ-1.0.1-P0qt07Z-AwDM-WcpwjDbb0cIN4qQaTHpDuuszJ4bus5D" },
};
