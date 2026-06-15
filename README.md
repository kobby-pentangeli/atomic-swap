# Atomic Swap

A cross-chain atomic swap system enabling trustless exchange of Bitcoin for NFTs on Ethereum or Solana using Hash Time Locked Contracts (HTLC).

**Warning:** This is experimental software. Do not use with real funds without thorough testing and security audit.

## How It Works

1. **Buyer locks Bitcoin** in an HTLC using a secret hash
2. **Seller commits NFT** on Ethereum or Solana using the same hash
3. **Buyer reveals secret** to mint the NFT
4. **Seller claims Bitcoin** using the revealed secret

The swap is atomic because the timelocks are ordered so that, once the buyer reveals the secret to mint the NFT, the seller can always claim the Bitcoin before the buyer's refund window opens. If the buyer never reveals, the seller cancels the commitment and the buyer refunds the Bitcoin after the timeout. No party can take both assets.

## Quick Start

Install the pinned toolchains, then watch the full swap run end to end on local chains.

```bash
git clone https://github.com/kobby-pentangeli/atomic-swap.git
cd atomic-swap

# Install (or verify) the toolchains the project builds against:
# Rust, Foundry, the Agave/Solana CLI, Anchor, and Bitcoin Core.
./scripts/setup.sh            # add --verify to only report what is installed

# Walk through the whole lifecycle interactively on ephemeral local chains.
cargo run -p e2e --bin demo -- --chain eth     # or: --chain sol
```

The demo stands up a Bitcoin regtest node and the chosen NFT chain (an Anvil node or a Solana test validator), deploys the contract / loads the program, and steps through buyer-locks-BTC → seller-commits-NFT → buyer-reveals-and-mints → seller-claims-BTC, pausing between steps. Add `--bound` to restrict the mint to the authorized buyer, or `--yes` to run without pausing.

## End-to-End Tests

The same flows back the release gate. The tests stand up real local chains and drive the real client, so they are ignored by default and run on demand:

```bash
cargo test -p e2e -- --ignored
```

They cover the happy path on both NFT chains (open and bound mints), the refund and cancel recovery paths, and the defection paths (unsafe timelock, premature refund, wrong secret, unauthorized mint, replay).

## Manual Runs and Deployment

To run against a testnet/devnet (or your own local nodes), configure `.env` and drive the `client` binary directly.

### Configuration

```bash
cp .env.template .env
# Edit .env with your RPC endpoints, keys, and the deployed contract/program addresses.
```

See [.env.template](.env.template) for the full list of variables.

### Deploy the Ethereum contract

```bash
cd agent/eth
forge soldeer install
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$ETH_RPC_URL" --broadcast --account <keystore-account>
# Copy the deployed address into NFT_CONTRACT_ADDRESS in your .env.
```

The signing key is supplied by the `forge` CLI (`--account` for a `cast wallet` keystore, `--ledger` for a hardware wallet, or `--private-key` for local/testnet use); it is never read from source.

### Deploy the Solana program

```bash
cd agent/sol
solana config set --url https://api.devnet.solana.com
solana airdrop 2
anchor build
anchor deploy --provider.cluster devnet
# Copy the program id into SOL_PROGRAM_ID in your .env.
```

### Run the swap

```bash
# 1. Buyer locks Bitcoin
cargo run --release -p client -- lock-btc --btc-amount 100000

# 2. Seller commits the NFT (Ethereum shown; use --chain sol for Solana)
cargo run --release -p client -- commit-for-mint \
  --chain eth \
  --secret-hash <hash_from_lock_output> \
  --nft-price 1000000000000000000 \
  --token-id 1 \
  --metadata-uri https://example.com/nft/1.json

# 3. Buyer reveals the secret to mint the NFT
cargo run --release -p client -- mint-with-secret \
  --chain eth --secret-file .swap/secrets/swap.secret

# 4. Seller claims the Bitcoin
cargo run --release -p client -- claim-btc --secret-file .swap/secrets/swap.secret
```

Recovery, if the swap is abandoned:

```bash
# Seller cancels the commitment
cargo run --release -p client -- cancel-commit --chain eth --token-id 1

# Buyer reclaims the Bitcoin after the timeout
cargo run --release -p client -- refund-btc --secret-file .swap/secrets/swap.secret
```

> Use the `--no-env` flag to bypass `.env` loading and read configuration from system environment variables instead.

## Project Structure

```bash
atomic-swap/
├── agent/
│   ├── btc/     # Bitcoin HTLC library
│   ├── eth/     # Ethereum NFTSecretMint contract (Foundry)
│   └── sol/     # Solana sol-htlc program (Anchor) + litesvm harness
├── client/      # Rust CLI orchestration tool
├── e2e/         # End-to-end harness and interactive demo binary
└── scripts/     # Pinned toolchain installer (setup.sh)
```

## Contributing

Contributions are welcome! Please read the [contribution guidelines](https://github.com/kobby-pentangeli/atomic-swap/blob/main/CONTRIBUTING.md) and browse [Good First Issues](https://github.com/kobby-pentangeli/atomic-swap/labels/good%20first%20issue).

## License

Licensed under either [Apache License 2.0](./LICENSE-APACHE) or [MIT license](./LICENSE-MIT) at your option.
