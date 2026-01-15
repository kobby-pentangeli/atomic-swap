# Atomic Swap

A cross-chain atomic swap system where Bitcoin payment unlocks NFT minting on Ethereum or Solana through shared secrets using Hash Time Locked Contracts (HTLC).

**Warning:** This is experimental software. Please do not use with real funds without thorough testing and security audit.

## Overview

This system enables trustless atomic swaps between Bitcoin and Ethereum/Solana NFTs:

1. **Buyer locks Bitcoin** in an HTLC using a secret hash
2. **Seller commits NFT** on Ethereum or Solana using the same secret hash
3. **Buyer reveals secret** to mint the NFT on Ethereum or Solana
4. **Seller claims Bitcoin** using the revealed secret from Ethereum or Solana

## End-to-end Demo

You can run the demo either locally or in a dockerized environment:

- **Docker Setup** (Recommended): No local dependencies needed; everything runs in containers
- **Local Setup**: Full control and debugging capabilities

### Docker Setup (Recommended)

Prerequisites: **Docker** 20.10+ and **Docker Compose** 2.0+
Installing Docker Desktop automatically gives Docker Compose as well. [Install here](https://www.docker.com/).

```bash
# Clone repo
git clone https://github.com/kobby-pentangeli/atomic-swap.git
cd atomic-swap

# Start all services (Bitcoin, Ethereum, Solana, and app)
docker-compose up --build
```

This will:

- Build all blockchain services in containers
- Start Bitcoin regtest, Ethereum (Hardhat), and Solana test validator
- Build the Rust client and deploy all contracts
- Generate funded test accounts and demo configuration
- Display ready-to-use commands when setup completes

### Run Dockerized Demo

After `docker-compose up` shows "Setup complete! Container ready for demo.", open a new terminal and run:

```bash
# Enter the demo container
docker exec -it xchain-app bash

# Load the generated configuration
source .swap/atomic_swap.sh
```

> **Tip:** The setup container stays running after initialization, so you can access it anytime with `docker exec -it xchain-app bash` in a separate terminal

#### Lock BTC

```bash
# 1. (BUYER): Lock Bitcoin in HTLC
lock_btc
```

The above command will execute the first step of the swap. Upon success, the **SECRET**, **SECRET_HASH**, and **LOCK_TXID** are automatically saved to `.swap/secrets/swap.secret`. You can also view them in stdout.

#### Commit the NFT

```bash
# 2. (SELLER): Commit to mint NFT with secret hash
commit_for_mint --chain <eth|sol> <SECRET_HASH>

# Example commands:
#   commit_for_mint --chain eth <SECRET_HASH>
#   commit_for_mint --chain sol <SECRET_HASH>
```

#### Mint with Secret

```bash
# 3. (BUYER): Mint NFT by revealing the secret
mint_with_secret --chain <eth|sol> <SECRET>

# Or use the secret file directly:
mint_with_secret --chain <eth|sol> --secret-file .swap/secrets/swap.secret

# Example commands:
#   mint_with_secret --chain eth --secret-file .swap/secrets/swap.secret
#   mint_with_secret --chain sol <SECRET>
```

#### Claim Bitcoin

```bash
# 4. (SELLER): Claim Bitcoin using the revealed secret
claim_btc <SECRET> <SECRET_HASH> <LOCK_TXID>

# Or use the secret file directly:
claim_btc --secret-file .swap/secrets/swap.secret
```

#### Cancel Commitment (Recovery)

If the swap doesn't complete, the seller can cancel an expired commitment:

```bash
# Cancel an expired commitment (seller only)
cancel_commit --chain <eth|sol>

# With specific token ID:
cancel_commit --chain eth --token-id 5
```

**NOTE**: The above commands `lock_btc`, `commit_for_mint`, `mint_with_secret`, `claim_btc`, and `cancel_commit` work the same in the local setup case as in the Dockerized case.

### Local Setup & Demo

Prerequisites:

- **Rust** 1.75+ with Cargo
- **Node.js** 18+ with npm/yarn
- **Bitcoin Core** (for regtest mode)
- **Hardhat** development environment

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

# Clone repo
git clone https://github.com/kobby-pentangeli/atomic-swap.git
cd atomic-swap

# Set up the demo parameters and runners
./setup.sh
```

The setup script automatically:

- Installs missing prerequisites (Bitcoin Core, dependencies)
- Builds the Rust `client`
- Configures and starts Bitcoin regtest node
- Deploys Ethereum NFT contract on local Hardhat network
- Generates funded test accounts for both networks
- Creates ready-to-use demo configuration in `.swap/`

**NOTE**: The setup script prefunds the buyer's BTC wallet ("testwallet"), but to ensure sufficient funds and avoid potential errors, you may need to mine additional blocks:

```bash
# In project root directory
bitcoin-cli -regtest -datadir=.bitcoin generatetoaddress 101 <BUYER_BTC_ADDRESS>
```

Copy-paste the `<BUYER_BTC_ADDRESS>` from the `.swap/atomic_swap.sh` demo config file. Once you have enough BTC, proceed with the swap:

```bash
# 0. Load the config
source .swap/atomic_swap.sh
```

The above command will load the demo config. You can then proceed to execute the `lock_btc`, `commit_for_mint`, etc. commands as specified in the Dockerized demo section.
To stop all services, run the `stop_services` command.

## Directory Structure

After setup, the `.swap/` directory contains all runtime-generated files:

```sh
.swap/
├── atomic_swap.sh        # Demo configuration (source this file)
├── contract_address.txt  # Ethereum NFT contract address
├── program_id.txt        # Solana program ID
├── keypairs/
│   ├── buyer.json        # Solana buyer keypair
│   └── seller.json       # Solana seller keypair
└── secrets/
    └── swap.secret       # Secret, hash, and txid from lock_btc
```

## Customizing Demo Parameters

You can modify the generated `.swap/atomic_swap.sh` to customize the demo run:

```bash
# Edit amounts, token IDs, metadata, etc.
export BTC_AMOUNT="2000000"      # 0.02 BTC
export ETH_NFT_PRICE="2000000000000000000"  # 2 ETH
export TOKEN_ID="42"
export METADATA_URI="https://your-nft-metadata.json"
```

## Managing Docker Services

### Basics

```bash
# Start all services
docker-compose up --build

# Stop all services
docker-compose down

# View logs
docker-compose logs -f

# Check service status
docker-compose ps

# Access individual services
docker exec -it xchain-btc bash      # Bitcoin node
docker exec -it xchain-eth bash      # Ethereum node
docker exec -it xchain-sol bash      # Solana validator
docker exec -it xchain-app bash      # Demo environment
```

### Service Health Checks

```bash
# Bitcoin regtest status
docker exec -it xchain-btc bitcoin-cli -regtest -rpcport=18443 -rpcuser=user -rpcpassword=password getblockchaininfo

# Ethereum network status
docker exec -it xchain-eth curl -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' http://localhost:8545

# Solana cluster status
docker exec -it xchain-sol solana cluster-version --url http://localhost:8899
```

## Contributing

Thank you for considering contributing to this project! All contributions large and small are actively accepted.

- To get started, please read the [contribution guidelines](https://github.com/kobby-pentangeli/atomic-swap/blob/main/CONTRIBUTING.md).

- Browse [Good First Issues](https://github.com/kobby-pentangeli/atomic-swap/labels/good%20first%20issue).

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or [MIT license](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this codebase by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
