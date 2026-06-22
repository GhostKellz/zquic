#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ZIG="${ZIG:-/opt/zig-dev/zig}"

printf 'Building QUIC VPN demo (requires -Dvpn=true -Dmonitoring=true)...\n'
"$ZIG" build -Dvpn=true -Dmonitoring=true >/dev/null

printf 'Running QUIC VPN smoke demo...\n'
"$ROOT_DIR/zig-out/bin/quic-vpn-server-demo" --smoke
printf '\nDone. Inspect Prometheus output above for sanity.\n'
