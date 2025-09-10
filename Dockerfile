FROM ubuntu:22.04

ARG TARGETARCH

# Install system dependencies
RUN apt-get update && apt-get install -y \
    bzip2 \
    cmake \
    clang \
    llvm \
    libclang-dev \
    llvm-dev \
    libstdc++-12-dev \
    protobuf-compiler \
    curl \
    wget \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    libudev-dev \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables for clang
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib
ENV LLVM_CONFIG_PATH=/usr/bin/llvm-config

# Install Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build Solana from source with AVX disabled
RUN git clone --branch v3.0.0 https://github.com/anza-xyz/agave.git
RUN cd agave && ./scripts/cargo-install-all.sh /root/.local/share/solana/install/active_release
ENV PATH="/root/.local/share/solana/install/active_release/bin:${PATH}"
RUN solana --version

# Install Anchor
RUN if [ "$TARGETARCH" = "amd64" ]; then \
    cargo install --git https://github.com/solana-foundation/anchor avm --force && \
    avm install latest && avm use latest; \
    else \
    cargo install --git https://github.com/solana-foundation/anchor anchor-cli --tag v0.31.1 --force; \
    fi
RUN anchor --version || echo "Anchor installation verification failed"

# Install Bitcoin Core
RUN BITCOIN_VERSION=25.0 && \
    cd /tmp && \
    if [ "$TARGETARCH" = "arm64" ]; then \
    BITCOIN_ARCH="aarch64-linux-gnu"; \
    else \
    BITCOIN_ARCH="x86_64-linux-gnu"; \
    fi && \
    wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-${BITCOIN_ARCH}.tar.gz && \
    wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS && \
    grep bitcoin-${BITCOIN_VERSION}-${BITCOIN_ARCH}.tar.gz SHA256SUMS | sha256sum -c - && \
    tar -xzf bitcoin-${BITCOIN_VERSION}-${BITCOIN_ARCH}.tar.gz && \
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

# Create minimal dummy source files for dependency caching
RUN mkdir -p \
    agent/btc/src \
    agent/sol/programs/sol-htlc/src \
    agent/sol/tests/src \
    client/src/bin \
    && echo 'fn main() {}' > client/src/main.rs \
    && echo 'fn main() {}' > client/src/bin/derive_privkey.rs \
    && echo '' > agent/btc/src/lib.rs \
    && echo '' > agent/sol/programs/sol-htlc/src/lib.rs \
    && echo '' > agent/sol/tests/src/lib.rs

# Build dependencies only (caching layer)
RUN cargo build --release --workspace

# Remove dummy files to avoid conflicts
RUN rm -rf client/src agent/btc/src agent/sol/programs/sol-htlc/src agent/sol/tests/src

# Copy starter script for Solana test validator
COPY scripts/start-solana.sh .
RUN chmod +x start-solana.sh

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