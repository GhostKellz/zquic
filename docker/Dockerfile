FROM alpine:3.21

ENV PATH=/opt/zig:${PATH}

RUN apk add --no-cache \
    bash \
    ca-certificates \
    curl \
    git \
    build-base \
    valgrind \
    file

WORKDIR /workspace

CMD ["bash"]
