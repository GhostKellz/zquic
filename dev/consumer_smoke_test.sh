#!/bin/bash
# Package Consumer Smoke Test
# Verifies that zquic can be imported as a dependency
# Run from project root: ./dev/consumer_smoke_test.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== ZQUIC Package Consumer Smoke Test ==="
echo ""

# Create temporary directory
TMPDIR=$(mktemp -d)
trap "rm -rf '$TMPDIR'" EXIT

echo "[1/5] Creating test project in $TMPDIR..."

# Create symlink to zquic (Zig requires relative paths in build.zig.zon)
ln -s "$PROJECT_ROOT" "$TMPDIR/zquic_local"

# Create initial build.zig.zon without fingerprint (Zig will compute it)
cat > "$TMPDIR/build.zig.zon" << 'EOF'
.{
    .name = .zquic_consumer_test,
    .version = "0.0.1",
    .fingerprint = 0x1,
    .dependencies = .{
        .zquic = .{
            .path = "zquic_local",
        },
    },
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
    },
}
EOF

# Create a minimal build.zig (Zig 0.16.0-dev API)
cat > "$TMPDIR/build.zig" << 'EOF'
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zquic_dep = b.dependency("zquic", .{
        .target = target,
        .optimize = optimize,
        .http3 = true,
        .doq = true,
        .services = false,
        .vpn = false,
        .@"post-quantum" = false,
        .monitoring = false,
    });

    const exe = b.addExecutable(.{
        .name = "smoke_test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    exe.root_module.addImport("zquic", zquic_dep.module("zquic"));
    b.installArtifact(exe);
}
EOF

# Create test source
mkdir -p "$TMPDIR/src"
cat > "$TMPDIR/src/main.zig" << 'EOF'
const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    // Verify core types are accessible
    _ = zquic.Connection;
    _ = zquic.Stream;
    _ = zquic.Packet;
    _ = zquic.Crypto;

    // Verify HTTP/3 types (empty struct when disabled)
    _ = zquic.Http3;

    // Verify DoQ types (empty struct when disabled)
    _ = zquic.DoQ;

    // Verify build config and version
    const features = zquic.getEnabledFeatures();
    std.debug.print("ZQUIC v{s} - {d} features enabled\n", .{ zquic.version, features.len });

    std.debug.print("Consumer smoke test: PASS\n", .{});
}
EOF

echo "[2/5] Getting package fingerprint from Zig..."
cd "$TMPDIR"

# Run zig build once to get the correct fingerprint
# Zig will fail but tell us what fingerprint to use
BUILD_OUTPUT=$(zig build 2>&1 || true)

# Extract the suggested fingerprint from Zig's error message
FINGERPRINT=$(echo "$BUILD_OUTPUT" | grep -o 'use this value: 0x[a-f0-9]*' | head -1 | sed 's/use this value: //')

if [ -z "$FINGERPRINT" ]; then
    echo "ERROR: Could not extract fingerprint from Zig output"
    echo "Build output was:"
    echo "$BUILD_OUTPUT"
    exit 1
fi

echo "  Computed fingerprint: $FINGERPRINT"

# Update build.zig.zon with correct fingerprint
echo "[3/5] Updating package with correct fingerprint..."
cat > "$TMPDIR/build.zig.zon" << EOF
.{
    .name = .zquic_consumer_test,
    .version = "0.0.1",
    .fingerprint = $FINGERPRINT,
    .dependencies = .{
        .zquic = .{
            .path = "zquic_local",
        },
    },
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
    },
}
EOF

echo "[4/5] Building consumer test..."
zig build 2>&1

echo "[5/5] Running consumer test..."
./zig-out/bin/smoke_test

echo ""
echo "=== Consumer Smoke Test: PASS ==="
