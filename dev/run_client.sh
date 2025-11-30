#!/bin/bash
# Run ZQUIC client for local testing
# Run from project root: ./dev/run_client.sh [host] [port]

HOST=${1:-localhost}
PORT=${2:-4433}

echo "=== Starting ZQUIC Client ==="
echo "Connecting to: $HOST:$PORT"
echo ""

# Build first if needed
if [ ! -f "zig-out/bin/zquic-client" ]; then
    echo "Building..."
    zig build
fi

./zig-out/bin/zquic-client --host "$HOST" --port "$PORT"
