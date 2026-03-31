# --- STAGE 1: Build ---
FROM rust:1.76-slim-bullseye as builder

WORKDIR /usr/src/riskora

# Copy the source code
COPY . .

# Build for release (optimized)
RUN cargo build --release --bin api --bin compiler

# --- STAGE 2: Runtime ---
FROM debian:bullseye-slim

# Install system dependencies (needed for SQLite & SSL)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binaries from the builder stage
COPY --from=builder /usr/src/riskora/target/release/api /app/api
COPY --from=builder /usr/src/riskora/target/release/compiler /app/compiler

# Create a data directory for GeoIP and Threats
RUN mkdir -p /app/data

# Exposure Port
EXPOSE 3000

# Default command runs the API
CMD ["./api"]
