#!/bin/bash
# Package Consumer Smoke Test
# Verifies that zquic can be imported as a dependency
# Local/pre-tag check from the project root:
#   ./dev/consumer_smoke_test.sh
#
# Post-tag/archive check:
#   ZQUIC_URL=https://github.com/ghostkellz/zquic/archive/refs/tags/vX.Y.Z.tar.gz ./dev/consumer_smoke_test.sh

set -e
ZIG="${ZIG:-/opt/zig-dev/zig}"
REPO_ROOT="$(pwd)"
ZQUIC_URL="${ZQUIC_URL:-}"

echo "=== ZQUIC Package Consumer Smoke Test ==="
echo ""

# Create a repo-local temporary consumer project.
WORK_ROOT="$REPO_ROOT/zig-out/consumer-smoke"
WORK_DIR="$WORK_ROOT/work"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cleanup() {
    rm -rf "$WORK_ROOT"
}
trap cleanup EXIT

echo "[1/5] Creating test project in $WORK_DIR..."
if [ -z "$ZQUIC_URL" ]; then
    LOCAL_ARCHIVE="$WORK_DIR/zquic-local.tar.gz"
    PACKAGE_DIR="$WORK_DIR/zquic"
    echo "  packaging current checkout: $LOCAL_ARCHIVE"
    tar \
        --exclude=.git \
        --exclude=.zig-cache \
        --exclude=zig-out \
        -czf "$LOCAL_ARCHIVE" \
        -C "$(dirname "$REPO_ROOT")" \
        "$(basename "$REPO_ROOT")"
    tar -xzf "$LOCAL_ARCHIVE" -C "$WORK_DIR"
    FETCH_SOURCE="$LOCAL_ARCHIVE"
    DEPENDENCY_SPEC=".path = \"zquic\","
    echo "  zquic package path: $PACKAGE_DIR"
else
    FETCH_SOURCE="$ZQUIC_URL"
    echo "  zquic URL: $ZQUIC_URL"
fi

echo "[2/5] Preparing dependency metadata..."
if [ -z "$ZQUIC_URL" ]; then
    FETCH_OUTPUT=$("$ZIG" fetch "$FETCH_SOURCE" 2>&1)
    ZQUIC_HASH=$(echo "$FETCH_OUTPUT" | grep -E '^zquic-[A-Za-z0-9._-]+-[A-Za-z0-9_-]+$' | tail -1)

    if [ -z "$ZQUIC_HASH" ]; then
        echo "ERROR: Could not extract zquic hash from Zig fetch output"
        echo "Fetch output was:"
        echo "$FETCH_OUTPUT"
        exit 1
    fi

    echo "  Computed zquic hash: $ZQUIC_HASH"
else
    echo "  will run zig fetch --save=zquic after consumer fingerprint bootstrap"
fi

# Create initial build.zig.zon without fingerprint (Zig will compute it)
if [ -z "$ZQUIC_URL" ]; then
    cat > "$WORK_DIR/build.zig.zon" << EOF
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
else
    cat > "$WORK_DIR/build.zig.zon" << EOF
.{
    .name = .zquic_consumer_test,
    .version = "0.0.1",
    .fingerprint = 0x1,
    .dependencies = .{},
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
    },
}
EOF
fi

# Create a minimal build.zig (Zig 0.16.0-dev API)
cat > "$WORK_DIR/build.zig" << 'EOF'
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
mkdir -p "$WORK_DIR/src"
cat > "$WORK_DIR/src/main.zig" << 'EOF'
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
cd "$WORK_DIR"

# Run zig build once to get the correct fingerprint
# Zig will fail but tell us what fingerprint to use
BUILD_OUTPUT=$("$ZIG" build 2>&1 || true)

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
if [ -z "$ZQUIC_URL" ]; then
    cat > "$WORK_DIR/build.zig.zon" << EOF
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
else
    cat > "$WORK_DIR/build.zig.zon" << EOF
.{
    .name = .zquic_consumer_test,
    .version = "0.0.1",
    .fingerprint = $FINGERPRINT,
    .dependencies = .{},
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
    },
}
EOF
    echo "  Saving zquic dependency with Zig package manager..."
    "$ZIG" fetch --save=zquic "$ZQUIC_URL"
fi

echo "[5/6] Building consumer test..."
BUILD_OUTPUT=$("$ZIG" build 2>&1) || {
    echo "$BUILD_OUTPUT"
    exit 1
}

echo "[6/6] Running consumer test..."
./zig-out/bin/smoke_test

echo ""
echo "=== Consumer Smoke Test: PASS ==="
