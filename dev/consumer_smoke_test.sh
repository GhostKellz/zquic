#!/bin/bash
# Package Consumer Smoke Test
# Verifies that zquic can be imported as a dependency
# Local/pre-tag check from the project root:
#   ./dev/consumer_smoke_test.sh
#
# Post-tag/archive check:
#   ZQUIC_URL=https://github.com/ghostkellz/zquic/archive/refs/tags/v0.9.15.tar.gz ./dev/consumer_smoke_test.sh

set -e
ZIG="${ZIG:-/opt/zig-dev/zig}"
ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-/tmp/zig-global-cache}"
ZIG_LOCAL_CACHE_DIR="${ZIG_LOCAL_CACHE_DIR:-/tmp/zquic-consumer-smoke-cache}"
REPO_ROOT="$(pwd)"
ZQUIC_URL="${ZQUIC_URL:-}"

echo "=== ZQUIC Package Consumer Smoke Test ==="
echo ""

# Create temporary directory
TMPDIR=$(mktemp -d)
trap "rm -rf '$TMPDIR'" EXIT

echo "[1/5] Creating test project in $TMPDIR..."
if [ -z "$ZQUIC_URL" ]; then
    LOCAL_ARCHIVE="$TMPDIR/zquic-v0.9.15.tar.gz"
    PACKAGE_DIR="$TMPDIR/zquic"
    echo "  packaging current checkout: $LOCAL_ARCHIVE"
    tar \
        --exclude=.git \
        --exclude=.zig-cache \
        --exclude=zig-out \
        -czf "$LOCAL_ARCHIVE" \
        -C "$(dirname "$REPO_ROOT")" \
        "$(basename "$REPO_ROOT")"
    tar -xzf "$LOCAL_ARCHIVE" -C "$TMPDIR"
    FETCH_SOURCE="$LOCAL_ARCHIVE"
    DEPENDENCY_SPEC=".path = \"zquic\","
    echo "  zquic package path: $PACKAGE_DIR"
else
    FETCH_SOURCE="$ZQUIC_URL"
    echo "  zquic URL: $ZQUIC_URL"
fi

echo "[2/5] Getting dependency hash from Zig..."
FETCH_OUTPUT=$(ZIG_GLOBAL_CACHE_DIR="$ZIG_GLOBAL_CACHE_DIR" ZIG_LOCAL_CACHE_DIR="$ZIG_LOCAL_CACHE_DIR" "$ZIG" fetch "$FETCH_SOURCE" 2>&1)
ZQUIC_HASH=$(echo "$FETCH_OUTPUT" | grep -E '^zquic-[A-Za-z0-9._-]+-[A-Za-z0-9_-]+$' | tail -1)

if [ -z "$ZQUIC_HASH" ]; then
    echo "ERROR: Could not extract zquic hash from Zig fetch output"
    echo "Fetch output was:"
    echo "$FETCH_OUTPUT"
    exit 1
fi

echo "  Computed zquic hash: $ZQUIC_HASH"
if [ -n "$ZQUIC_URL" ]; then
    DEPENDENCY_SPEC=".url = \"$ZQUIC_URL\",
            .hash = \"$ZQUIC_HASH\","
fi

# Create initial build.zig.zon without fingerprint (Zig will compute it)
cat > "$TMPDIR/build.zig.zon" << EOF
.{
    .name = .zquic_consumer_test,
    .version = "0.0.1",
    .fingerprint = 0x1,
    .dependencies = .{
        .zquic = .{
            $DEPENDENCY_SPEC
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

echo "[3/5] Getting package fingerprint from Zig..."
cd "$TMPDIR"

# Run zig build once to get the correct fingerprint
# Zig will fail but tell us what fingerprint to use
BUILD_OUTPUT=$(ZIG_GLOBAL_CACHE_DIR="$ZIG_GLOBAL_CACHE_DIR" ZIG_LOCAL_CACHE_DIR="$ZIG_LOCAL_CACHE_DIR" "$ZIG" build 2>&1 || true)

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
echo "[4/5] Updating package with correct fingerprint..."
cat > "$TMPDIR/build.zig.zon" << EOF
.{
    .name = .zquic_consumer_test,
    .version = "0.0.1",
    .fingerprint = $FINGERPRINT,
    .dependencies = .{
        .zquic = .{
            $DEPENDENCY_SPEC
        },
    },
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
    },
}
EOF

echo "[5/6] Building consumer test..."
BUILD_OUTPUT=$(ZIG_GLOBAL_CACHE_DIR="$ZIG_GLOBAL_CACHE_DIR" ZIG_LOCAL_CACHE_DIR="$ZIG_LOCAL_CACHE_DIR" "$ZIG" build 2>&1) || {
    ACTUAL_HASH=$(echo "$BUILD_OUTPUT" | grep -o 'fetched package has [A-Za-z0-9._-]*' | head -1 | sed 's/fetched package has //')
    if [ -z "$ACTUAL_HASH" ]; then
        echo "$BUILD_OUTPUT"
        exit 1
    fi

    echo "  Zig reported canonical package hash: $ACTUAL_HASH"
    ZQUIC_HASH="$ACTUAL_HASH"
    cat > "$TMPDIR/build.zig.zon" << EOF
.{
    .name = .zquic_consumer_test,
    .version = "0.0.1",
    .fingerprint = $FINGERPRINT,
    .dependencies = .{
        .zquic = .{
            .url = "$ZQUIC_URL",
            .hash = "$ZQUIC_HASH",
        },
    },
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
    },
}
EOF
    ZIG_GLOBAL_CACHE_DIR="$ZIG_GLOBAL_CACHE_DIR" ZIG_LOCAL_CACHE_DIR="$ZIG_LOCAL_CACHE_DIR" "$ZIG" build 2>&1
}

echo "[6/6] Running consumer test..."
./zig-out/bin/smoke_test

echo ""
echo "=== Consumer Smoke Test: PASS ==="
