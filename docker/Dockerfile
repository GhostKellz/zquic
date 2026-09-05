FROM alpine:3.24.1

ENV HOME=/home/zquic
ENV PATH=/workspace/docker/bin:/opt/zig:${PATH}

RUN apk add --no-cache \
    bash \
    ca-certificates \
    curl \
    git \
    build-base \
    valgrind \
    file \
    pkgconf \
    python3 \
    py3-aioquic \
    ngtcp2 \
    ngtcp2-dev \
    ngtcp2-gnutls \
    nghttp3 \
    nghttp3-dev \
    libmsquic \
    libmsquic-dev

# Compose runs as the invoking host UID/GID so bind-mounted Zig outputs remain
# host-owned. Give that numeric user a normal writable home for Zig's default
# global cache without redirecting any cache path.
RUN install -d -m 0777 /home/zquic

WORKDIR /workspace

CMD ["bash"]
