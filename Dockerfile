# --- STAGE 1: Build ---
FROM rust:1.82-slim-bookworm AS builder

# Install build dependencies (needed for SQLite + OpenSSL)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/riskora

# Cache dependencies first (only re-runs when Cargo.toml/Cargo.lock change)
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/compiler.rs && \
    cargo build --release --bin api --bin compiler && \
    rm -f target/release/deps/backend*

# Copy the actual source code
COPY src ./src

# Build the final release binaries
RUN cargo build --release --bin api --bin compiler

# --- STAGE 2: Runtime ---
FROM debian:bookworm-slim

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1001 riskora

WORKDIR /app

# Copy the binaries from the builder stage
COPY --from=builder /usr/src/riskora/target/release/api /app/api
COPY --from=builder /usr/src/riskora/target/release/compiler /app/compiler

# Create data directory and set permissions
RUN mkdir -p /app/data && chown -R riskora:riskora /app

USER riskora

# Expose API port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Default command runs the API
CMD ["./api"]
