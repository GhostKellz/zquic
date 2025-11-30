#!/bin/bash
# Run ZQUIC server for local testing
# Run from project root: ./dev/run_server.sh [port]

PORT=${1:-4433}

echo "=== Starting ZQUIC Server ==="
echo "Port: $PORT"
echo "Press Ctrl+C to stop"
echo ""

# Build first if needed
if [ ! -f "zig-out/bin/zquic-server" ]; then
    echo "Building..."
    zig build
fi

./zig-out/bin/zquic-server --port "$PORT"
