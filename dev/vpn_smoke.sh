#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

printf 'Building QUIC VPN demo (requires -Dvpn=true -Dmonitoring=true)...\n'
zig build -Dvpn=true -Dmonitoring=true >/dev/null

printf 'Running QUIC VPN smoke demo...\n'
"$ROOT_DIR/zig-out/bin/quic-vpn-server-demo" --smoke
printf '\nDone. Inspect Prometheus output above for sanity.\n'
