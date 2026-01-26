# Atomic Swap

A cross-chain atomic swap system enabling trustless exchange of Bitcoin for NFTs on Ethereum or Solana using Hash Time Locked Contracts (HTLC).

**Warning:** This is experimental software. Do not use with real funds without thorough testing and security audit.

## How It Works

1. **Buyer locks Bitcoin** in an HTLC using a secret hash
2. **Seller commits NFT** on Ethereum or Solana using the same hash
3. **Buyer reveals secret** to mint the NFT
4. **Seller claims Bitcoin** using the revealed secret

## Local Demo

Test the full swap flow on your local machine using either Docker (recommended) or native setup.

### Option A: Docker (Recommended)

**Requirements:** Docker 20.10+ and Docker Compose 2.0+

```bash
# Clone and start all services
git clone https://github.com/kobby-pentangeli/atomic-swap.git
cd atomic-swap
docker-compose up --build

# In a new terminal, enter the container
docker exec -it xchain-app bash
source .swap/atomic_swap.sh
```

### Option B: Native Setup

**Requirements:** Rust 1.75+, Node.js 18+, Bitcoin Core

```bash
# Clone and run setup
git clone https://github.com/kobby-pentangeli/atomic-swap.git
cd atomic-swap
./setup.sh

# Load configuration
source .swap/atomic_swap.sh
```

> **Note:** For native setup, you may need to mine additional blocks:
>
> ```bash
> bitcoin-cli -regtest -datadir=.bitcoin generatetoaddress 101 <BUYER_BTC_ADDRESS>
> ```

### Running the Swap

Once setup is complete (Docker or native), run these commands:

```bash
# 1. Buyer locks Bitcoin
lock_btc

# 2. Seller commits NFT (choose chain)
commit_for_mint --chain eth <SECRET_HASH>  # Ethereum
# OR
commit_for_mint --chain sol <SECRET_HASH>  # Solana

# 3. Buyer mints NFT by revealing secret
mint_with_secret --chain eth --secret-file .swap/secrets/swap.secret
# OR
mint_with_secret --chain sol --secret-file .swap/secrets/swap.secret

# 4. Seller claims Bitcoin
claim_btc --secret-file .swap/secrets/swap.secret
```

### Recovery Commands

If the swap fails or times out:

```bash
# Seller cancels commitment
cancel_commit --chain eth --token-id 1

# Buyer reclaims Bitcoin after timeout
refund_btc --secret-file .swap/secrets/swap.secret
```

## Devnet Deployment

Deploy to Bitcoin testnet/signet, Ethereum Sepolia, or Solana Devnet.

### Prerequisites

1. **Bitcoin**: Testnet/Signet RPC access ([public nodes](https://mempool.space/testnet) or run your own)
2. **Ethereum**: Sepolia RPC ([Infura](https://infura.io), [Alchemy](https://alchemy.com), or public endpoint)
3. **Solana**: Devnet RPC access (public endpoint: `https://api.devnet.solana.com`)
4. **Wallets**: Funded accounts on each network

### Configuration

```bash
# Copy template and fill in values
cp .env.template .env
```

**Edit `.env` with your testnet/devnet details:**

```bash
# Bitcoin Testnet
BTC_RPC_URL=https://your-testnet-node:18332
BTC_NETWORK=testnet
BUYER_BTC_PRIVKEY=<your_hex_key>
SELLER_BTC_PUBKEY=<seller_hex_pubkey>

# Ethereum Sepolia
ETH_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
NFT_CONTRACT_ADDRESS=<deployed_contract_address>
BUYER_ETH_PRIVKEY=0x...
SELLER_ETH_PRIVKEY=0x...

# Solana Devnet
SOL_RPC_URL=https://api.devnet.solana.com
SOL_PROGRAM_ID=<deployed_program_id>
BUYER_SOL_KEYPAIR=./path/to/buyer-keypair.json
SELLER_SOL_KEYPAIR=./path/to/seller-keypair.json
```

For complete list of variables, see [.env.template](.env.template).

### Deploy Contracts

#### Ethereum Sepolia

```bash
cd agent/eth

# Set environment variables
export SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
export SEPOLIA_PRIVATE_KEY=0x...

# Deploy
npm run deploy:sepolia

# Copy deployed address to .env
# NFT_CONTRACT_ADDRESS=<address_from_output>
```

#### Solana Devnet

```bash
cd agent/sol

# Configure Solana CLI for devnet
solana config set --url https://api.devnet.solana.com

# Airdrop SOL for deployment (if needed)
solana airdrop 2

# Deploy
anchor build
anchor deploy --provider.cluster devnet

# Copy program ID to .env
# SOL_PROGRAM_ID=<program_id_from_output>
```

### Running on Devnet

With `.env` configured, the CLI requires minimal arguments:

```bash
# Lock Bitcoin on testnet
cargo run --release -- lock-btc --amount 100000

# Commit NFT on Sepolia
cargo run --release -- commit-for-mint \
  --chain eth \
  --secret-hash <hash_from_lock_output> \
  --price 1000000000000000000 \
  --token-id 1 \
  --metadata-uri https://example.com/nft/1.json

# Mint NFT on Sepolia
cargo run --release -- mint-with-secret \
  --chain eth \
  --secret-file .swap/secrets/swap.secret

# Claim Bitcoin on testnet
cargo run --release -- claim-btc --secret-file .swap/secrets/swap.secret
```

> **Tip:** Use `--no-env` flag to bypass `.env` loading and use system environment variables instead.

## Project Structure

```bash
atomic-swap/
├── agent/
│   ├── btc/              # Bitcoin HTLC library
│   ├── eth/              # Ethereum NFTSecretMint contract
│   └── sol/              # Solana sol-htlc program
├── client/               # Rust CLI orchestration tool
├── scripts/              # Setup and deployment scripts
└── .swap/                # Runtime-generated files (gitignored)
    ├── atomic_swap.sh    # Shell wrapper functions
    ├── keypairs/         # Solana keypairs
    └── secrets/          # Swap secrets
```

## Advanced Usage

### Customizing Parameters

Modify `.swap/atomic_swap.sh` or `.env` to customize amounts, token IDs, and metadata:

```bash
BTC_AMOUNT=2000000                        # 0.02 BTC
ETH_NFT_PRICE=2000000000000000000         # 2 ETH
SOL_NFT_PRICE=2000000000                  # 2 SOL
TOKEN_ID=42
METADATA_URI=https://your-nft-metadata.json
```

### Docker Management

```bash
# Start services
docker-compose up --build

# Stop services
docker-compose down

# View logs
docker-compose logs -f

# Access containers
docker exec -it xchain-app bash  # Demo environment
docker exec -it xchain-btc bash  # Bitcoin node
docker exec -it xchain-eth bash  # Ethereum node
docker exec -it xchain-sol bash  # Solana validator
```

### Health Checks

```bash
# Bitcoin regtest
docker exec -it xchain-btc bitcoin-cli -regtest getblockchaininfo

# Ethereum
docker exec -it xchain-eth curl -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  http://localhost:8545

# Solana
docker exec -it xchain-sol solana cluster-version --url http://localhost:8899
```

## Contributing

Contributions are welcome! Please read the [contribution guidelines](https://github.com/kobby-pentangeli/atomic-swap/blob/main/CONTRIBUTING.md) and browse [Good First Issues](https://github.com/kobby-pentangeli/atomic-swap/labels/good%20first%20issue).

## License

Licensed under either [Apache License 2.0](./LICENSE-APACHE) or [MIT license](./LICENSE-MIT) at your option.
