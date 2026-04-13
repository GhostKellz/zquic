#!/usr/bin/env bash
set -euo pipefail

echo "Using Zig: $(zig version)"
exec "$@"
