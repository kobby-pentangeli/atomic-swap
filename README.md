# Crosschain Secret Mint

A cross-chain atomic swap system where Bitcoin payment unlocks NFT minting on Ethereum or Solana through shared secrets using Hash Time Locked Contracts (HTLC).

**⚠️ Warning:** This is experimental software. Please do not use with real funds without thorough testing and security audit.

## Overview

This system enables trustless atomic swaps between Bitcoin and Ethereum/Solana NFTs:

1. **Buyer locks Bitcoin** in an HTLC using a secret hash
2. **Seller commits NFT** on Ethereum or Solana using the same secret hash  
3. **Buyer reveals secret** to mint the NFT on Ethereum or Solana
4. **Seller claims Bitcoin** using the revealed secret from Ethereum or Solana

## Status

### DONE

- [x] Bitcoin HTLC (script locking mechanism)
- [x] Ethereum NFT (standard ERC721) contract
- [x] Bitcoin client
- [x] Ethereum client
- [x] End-to-end demo for BTC<=>ETH swap

### TODO

- [ ] Solana HTLC program
- [ ] Solana client
- [ ] Architectural diagram

## End-to-end Demo

## Prerequisites

### System Requirements

- **Rust** 1.75+ with Cargo
- **Node.js** 18+ with npm/yarn
- **Bitcoin Core** (for regtest mode)
- **Hardhat** development environment

### Development Tools

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Node.js (via nvm recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install --lts
nvm use --lts

# Install Bitcoin Core (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install bitcoind

# Or via Homebrew (macOS)
brew install bitcoin
```

## Quick Start

### 1. Setup

```bash
# Clone repo
git clone https://github.com/kobby-pentangeli/crosschain-secret-mint.git
cd crosschain-secret-mint

# Set up the demo paramters and env variables
./setup.sh
```

The setup script automatically:

- Installs missing prerequisites (Bitcoin Core, dependencies)
- Configures and starts Bitcoin regtest node
- Deploys Ethereum NFT contract on local Hardhat network
- Generates funded test accounts for both networks
- Creates ready-to-use demo configuration

### 2. Run Demo

```bash
source ./demo_config.sh && run_demo
```

The above command will run through the complete cross-chain atomic swap.

### What You'll See

When you run `run_demo`, you'll see the complete atomic swap process:

```bash
[INFO] Initializing cross-chain atomic swap
[INFO] Generated secret pair for atomic swap
[INFO] Created HTLC contract
[INFO] Connected to blockchain networks
[INFO] Initiating Bitcoin lock transaction
[INFO] Bitcoin funds locked successfully
[INFO] === SELLER INSTRUCTIONS ===
[INFO] Bitcoin has been locked in HTLC: bc1q...
[INFO] To commit the NFT for minting, run: seller_commit abc123...
[INFO] Waiting for seller NFT commitment on Ethereum
[INFO] Seller commitment verified successfully
[INFO] Executing NFT mint with secret reveal
[INFO] NFT minted successfully, secret revealed on Ethereum
[INFO] === SELLER CLAIM INSTRUCTIONS ===
[INFO] The secret has been revealed: def456...
[INFO] To claim Bitcoin, run: seller_claim_btc def456... abc123... txid...
[INFO] Cross-chain atomic swap completed successfully
```

## Advanced Usage

### Step-by-Step Manual Run

If you'd rather see each step individually:

```bash
# Load configuration, after the running `./setup.sh` above
source ./demo_config.sh

# Terminal 1: Monitor events (optional)
RUST_LOG=info cargo run --release -- monitor \
    --eth-key $BUYER_ETH_PRIVKEY --nft-contract $NFT_CONTRACT_ADDRESS

# Terminal 2: Start buyer side (this will pause, waiting for seller)
run_demo

# Terminal 3: When buyer shows instructions, seller commits:
seller_commit <SECRET_HASH_FROM_BUYER_OUTPUT>

# Terminal 4: After NFT is minted, seller claims Bitcoin:
seller_claim_btc <SECRET> <SECRET_HASH> <LOCK_TXID>
```

### Custom Parameters

Modify `demo_config.sh` to customize:

```bash
# Edit amounts, token IDs, metadata, etc.
export BTC_AMOUNT="2000000"      # 0.02 BTC
export NFT_PRICE="2000000000000000000"  # 2 ETH
export TOKEN_ID="42"
export METADATA_URI="https://your-nft-metadata.json"
```

## Configuration Parameters

### Bitcoin Parameters

- `--btc-rpc`: Bitcoin RPC URL (default: <http://localhost:18443>)
- `--btc-user`: RPC username (default: user)  
- `--btc-pass`: RPC password (default: password)
- `--btc-network`: Network type (regtest/testnet/mainnet)
- `--btc-amount`: Amount in satoshis (default: 1000000 = 0.01 BTC)
- `--timeout`: HTLC timeout in blocks (default: 144 ≈ 24 hours)

### Ethereum Parameters

- `--eth-rpc`: Ethereum RPC URL (default: <http://localhost:8545>)
- `--nft-contract`: Deployed NFT contract address
- `--nft-price`: NFT price in wei (default: 1 ETH)
- `--token-id`: NFT token ID to mint
- `--metadata-uri`: NFT metadata URL

### Key Formats

- **Bitcoin Private Keys**: WIF format (e.g., `cQJ9R...`)
- **Bitcoin Public Keys**: Hex format (66 chars, e.g., `03a1b2c3...`)  
- **Ethereum Private Keys**: Hex format (64 chars, e.g., `0x123abc...`)
- **Ethereum Addresses**: Checksummed format (e.g., `0x742d3...`)
