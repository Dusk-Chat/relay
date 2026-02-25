# build stage
FROM rust:1.85-slim as builder

# install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# set working directory
WORKDIR /app

# copy cargo files first for better caching
COPY Cargo.toml Cargo.lock ./

# create a dummy main.rs to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# copy actual source code
COPY src ./src

# build the release binary
RUN touch src/main.rs && \
    cargo build --release

# runtime stage
FROM debian:bookworm-slim

# install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# create non-root user for security
RUN useradd -m -u 1000 dusk && \
    mkdir -p /data && \
    chown -R dusk:dusk /data

# copy binary from builder
COPY --from=builder /app/target/release/dusk-relay /usr/local/bin/dusk-relay

# switch to non-root user
USER dusk

# set working directory
WORKDIR /data

# expose the default relay port (libp2p)
EXPOSE 4001

# expose TURN server ports (UDP + TCP signaling)
EXPOSE 3478/udp
EXPOSE 3478/tcp

# expose TURN relay allocation port range (UDP)
EXPOSE 49152-65535/udp

# persist keypair and data to the volume-mounted /data directory
# XDG_DATA_HOME tells the directories crate to resolve paths under /data
# so the keypair ends up at /data/dusk-relay/keypair instead of ~/.local/share
ENV XDG_DATA_HOME=/data
VOLUME /data

# set environment variables
ENV RUST_LOG=info
ENV DUSK_RELAY_PORT=4001

# TURN server environment variables
ENV DUSK_TURN_ENABLED=true
ENV DUSK_TURN_PUBLIC_IP=""
ENV DUSK_TURN_SECRET=""
ENV DUSK_TURN_UDP_PORT=3478
ENV DUSK_TURN_TCP_PORT=3478
ENV DUSK_TURN_REALM=duskchat.app
ENV DUSK_TURN_PORT_RANGE_START=49152
ENV DUSK_TURN_PORT_RANGE_END=65535
ENV DUSK_TURN_MAX_ALLOCATIONS=1000
ENV DUSK_TURN_MAX_PER_USER=10
ENV DUSK_TURN_PUBLIC_HOST=""

# health check to verify the relay is listening
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD timeout 5 bash -c 'cat < /dev/null > /dev/tcp/0.0.0.0/${DUSK_RELAY_PORT:-4001}' || exit 1

# run the relay server
ENTRYPOINT ["dusk-relay"]
