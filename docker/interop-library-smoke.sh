#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="$ROOT/.scratch/docker-interop-libs"

cleanup() {
    rm -rf "$SCRATCH"
}

trap cleanup EXIT

mkdir -p "$SCRATCH"

compile_probe() {
    local name="$1"
    local cflags="$2"
    local libs="$3"
    local source="$SCRATCH/$name.c"
    local binary="$SCRATCH/$name"

    cat >"$source"
    cc $cflags "$source" $libs -o "$binary"
    "$binary"
    printf 'PASS %-24s\n' "$name"
}

echo "=== zquic interop library smoke ==="

compile_probe "ngtcp2-link" "$(pkg-config --cflags libngtcp2)" "$(pkg-config --libs libngtcp2)" <<'C'
#include <ngtcp2/ngtcp2.h>
#include <stdio.h>

int main(void) {
    const ngtcp2_info *info = ngtcp2_version(NGTCP2_VERSION_NUM);
    if (info == 0 || info->version_str == 0) return 1;
    printf("ngtcp2: %s\n", info->version_str);
    return 0;
}
C

compile_probe "ngtcp2-gnutls-link" "$(pkg-config --cflags libngtcp2_crypto_gnutls)" "$(pkg-config --libs libngtcp2_crypto_gnutls)" <<'C'
#include <ngtcp2/ngtcp2_crypto.h>

int main(void) {
    return ngtcp2_crypto_hkdf_expand == 0;
}
C

compile_probe "nghttp3-link" "$(pkg-config --cflags libnghttp3)" "$(pkg-config --libs libnghttp3)" <<'C'
#include <nghttp3/nghttp3.h>
#include <stdio.h>

int main(void) {
    const nghttp3_info *info = nghttp3_version(NGHTTP3_VERSION_NUM);
    if (info == 0 || info->version_str == 0) return 1;
    printf("nghttp3: %s\n", info->version_str);
    return 0;
}
C

compile_probe "msquic-link" "" "-lmsquic" <<'C'
#include <msquic.h>

int main(void) {
    const QUIC_API_TABLE *api = 0;
    if (MsQuicOpen2(&api) != QUIC_STATUS_SUCCESS) return 1;
    if (api == 0) return 1;
    MsQuicClose(api);
    return 0;
}
C

cleanup
echo "PASS interop library probes"
