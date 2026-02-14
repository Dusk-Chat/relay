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

# expose the default relay port
EXPOSE 4001

# set environment variables
ENV RUST_LOG=info
ENV DUSK_RELAY_PORT=4001

# health check to verify the relay is listening
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD timeout 5 bash -c 'cat < /dev/null > /dev/tcp/0.0.0.0/${DUSK_RELAY_PORT:-4001}' || exit 1

# run the relay server
ENTRYPOINT ["dusk-relay"]
