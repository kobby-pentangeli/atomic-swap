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
    netcat-openbsd \
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
RUN BITCOIN_VERSION=25.0 && \
    cd /tmp && \
    wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS && \
    grep bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz SHA256SUMS | sha256sum -c - && \
    tar -xzf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    install -m 0755 -o root -g root -t /usr/local/bin bitcoin-${BITCOIN_VERSION}/bin/* && \
    rm -rf bitcoin-${BITCOIN_VERSION}* SHA256SUMS* && \
    bitcoind --version

# Install jq
RUN apt-get update && apt-get install -y jq

WORKDIR /app

# Copy package files first for better caching
COPY agent/eth/package.json agent/eth/package-lock.json* ./agent/eth/
COPY agent/sol/package.json agent/sol/package-lock.json* ./agent/sol/

# Add esbuild Linux binary explicitly
RUN npm install --global esbuild@0.25.9

RUN cd agent/eth && rm -rf node_modules && npm install --silent
RUN cd agent/sol && rm -rf node_modules && npm install --silent

# Copy Rust manifests for dependency resolution
COPY Cargo.toml .
COPY agent/btc/Cargo.toml agent/btc/
COPY agent/sol/Cargo.toml agent/sol/
COPY agent/sol/programs/sol-htlc/Cargo.toml agent/sol/programs/sol-htlc/
COPY agent/sol/tests/Cargo.toml agent/sol/tests/
COPY client/Cargo.toml client/

# Create dummy source files for initial build caching
RUN mkdir -p \
    agent/btc/src \
    agent/sol/programs/sol-htlc/src \
    agent/sol/tests/src \
    client/src \
    client/src/bin \
    && echo 'fn main() {}' > client/src/main.rs \
    && echo 'fn main() {}' > client/src/bin/derive_privkey.rs \
    && echo '' > agent/btc/src/lib.rs \
    && echo '' > agent/sol/programs/sol-htlc/src/lib.rs \
    && echo '' > agent/sol/tests/src/lib.rs

# Build dependencies only (caching layer)
RUN cargo build --release --workspace

# Copy the rest of the application
COPY . .

# Compile Ethereum contracts to generate artifacts
WORKDIR /app/agent/eth
RUN npx hardhat compile
WORKDIR /app

# Build the actual application
RUN cargo build --release --workspace

# Make script executable
RUN chmod +x docker-setup.sh

# Expose ports
EXPOSE 18443 18444 8545 8899 8900

# Default command
CMD ["./docker-setup.sh"]