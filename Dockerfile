FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    libudev-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Solana
RUN sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)" \
    && export PATH="/root/.local/share/solana/install/active_release/bin:$PATH" \
    && solana --version

# Install Anchor
RUN cargo install --git https://github.com/solana-foundation/anchor avm --force \
    && avm install latest \
    && avm use latest

# Install Bitcoin Core
RUN apt-get update && apt-get install -y software-properties-common \
    && add-apt-repository ppa:bitcoin/bitcoin \
    && apt-get update \
    && apt-get install -y bitcoind

# Install jq
RUN apt-get update && apt-get install -y jq

WORKDIR /app

# Copy package files first for better caching
COPY agent/eth/package.json agent/eth/package-lock.json* ./agent/eth/
COPY agent/sol/package.json agent/sol/package-lock.json* ./agent/sol/

RUN cd agent/eth && npm install --silent
RUN cd agent/sol && npm install --silent

# Copy Rust manifests for dependency resolution
COPY Cargo.toml .
COPY agent/btc/Cargo.toml agent/btc/
COPY agent/sol/Cargo.toml agent/sol/
COPY agent/sol/programs/sol-htlc/Cargo.toml agent/sol/programs/sol-htlc/
COPY client/Cargo.toml client/

# Create dummy source files for initial build caching
RUN mkdir -p \
    agent/btc/src \
    agent/sol/programs/sol-htlc/src \
    client/src \
    client/src/bin \
    && echo 'fn main() {}' > client/src/main.rs \
    && echo 'fn main() {}' > client/src/bin/derive_privkey.rs \
    && echo '' > agent/btc/src/lib.rs \
    && echo '' > agent/sol/programs/sol-htlc/src/lib.rs

# Build dependencies only (caching layer)
RUN cargo build --release --workspace

# Copy the rest of the application
COPY . .

# Build the actual application
RUN cargo build --release --workspace

# Make scripts executable
RUN chmod +x scripts/*.sh && chmod +x setup.sh

# Expose ports
EXPOSE 18443 18444 8545 8899 8900

# Default command
CMD ["./setup.sh"]