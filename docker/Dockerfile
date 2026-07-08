FROM alpine:3.24.1

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

WORKDIR /workspace

CMD ["bash"]
