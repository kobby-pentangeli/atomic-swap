# Atomic Swap

[![CI](https://github.com/kobby-pentangeli/atomic-swap/workflows/CI/badge.svg)](https://github.com/kobby-pentangeli/atomic-swap/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Releases](https://img.shields.io/github/v/release/kobby-pentangeli/atomic-swap)](https://github.com/kobby-pentangeli/atomic-swap/releases)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg?style=flat-square)](https://github.com/kobby-pentangeli/atomic-swap/blob/main/CONTRIBUTING.md)

A cross-chain atomic swap system enabling trustless exchange of Bitcoin for NFTs on Ethereum or Solana using Hash Time Locked Contracts (HTLC).

> [!WARNING]
> This is experimental software. It is not audited; please do not use it with real funds without thorough testing and an independent security audit. See [SECURITY.md](SECURITY.md) for the threat model and trust assumptions.

## Project Structure

```text
atomic-swap/
├── agent/
│   ├── btc/     # Bitcoin HTLC library (btc-htlc)
│   ├── eth/     # Ethereum NFTSecretMint contract (Foundry)
│   └── sol/     # Solana sol-htlc program (Anchor) + litesvm harness
├── client/      # Rust CLI orchestration tool
├── e2e/         # End-to-end harness and interactive demo binary
├── docs/        # Developer documentation
└── scripts/     # Pinned toolchain installer (setup.sh)
```

## How It Works

The swap binds a Bitcoin payment and an NFT mint to one shared secret `s`. The buyer locks Bitcoin behind the hash `H = SHA256(s)`; the seller commits the NFT behind the same `H`; the buyer mints the NFT by revealing `s`, which makes `s` public; the seller then reuses that public `s` to claim the Bitcoin. The same preimage satisfies `OP_SHA256` in the Bitcoin script and the `sha256` check on the NFT chain, so the two legs settle together or not at all.

```text
   ┌─────────┐                                                  ┌──────────┐
   │  Buyer  │                                                  │  Seller  │
   └────┬────┘                                                  └────┬─────┘
        │  (1) lock-btc                          (2) commit-for-mint │
        ▼      via client                               via client   ▼
══════════════  BITCOIN  ·  HTLC output (P2WSH)  ═══════════════════════════════
   ┌──────────────────────────────────────────────────────────────────────────┐
   │  hashlock H = SHA256(s)         refund to Buyer after block height T_btc │
   │  spend paths:   reveal s ─→ Seller (4)    ·    after T_btc ─→ Buyer (R1) │
   └──────────────────────────────────────────────────────────────────────────┘
        ▲                                                              │
        │  (4) claim-btc                                               │
        │      Seller reuses the public s                              │
        │                                                              │
════════|═════  the secret s is the only thing that crosses  ══════════|═════
        │              (revealed to mint, then reused to claim)        │
        │                                                              │
   ┌────┴───────────────────────────────────────────────────────────┐  │
   │  NFT commitment      token bound to H      reveal deadline T_nft  │
   │  spend paths:   reveal s ─→ mint to Buyer (3)  ·  cancel ─→ Seller (R2)
   └────────────────────────────────────────────────────────────────┘  │
        ▲                                                              │
        │  (3) mint-with-secret                                        │
        │      Buyer reveals s, pays the price, receives the NFT ◀─────┘
        │      (Ethereum contract / Solana program)
```

| Step                     | What happens                                                                                                        | Path                        |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| **(1) lock-btc**         | Buyer locks the Bitcoin in a P2WSH HTLC behind `H = SHA256(s)`, refundable to the buyer after block height `T_btc`. | Buyer → client → Bitcoin    |
| **(2) commit-for-mint**  | Seller commits the token behind the same hash `H`, with an on-chain reveal deadline `T_nft` (24h).                  | Seller → client → NFT chain |
| **(3) mint-with-secret** | Buyer reveals `s` to mint the NFT and pays the price; `s` is now public on the NFT chain.                           | Buyer → client → NFT chain  |
| **(4) claim-btc**        | Seller reads the now-public `s` from the NFT chain and spends the HTLC's reveal path to take the Bitcoin.           | Seller → client → Bitcoin   |
| **(R1) refund-btc**      | If the buyer never reveals, the buyer reclaims the Bitcoin after block height `T_btc`.                              | Buyer → client → Bitcoin    |
| **(R2) cancel-commit**   | The seller cancels an unminted commitment, freeing the token and reclaiming rent.                                   | Seller → client → NFT chain |

A few details worth calling out:

- **Only the secret crosses the boundary.** Nothing else moves between chains; the swap is atomic precisely because the single preimage `s` that mints the NFT is the same preimage that unlocks the Bitcoin. Reveal it on one side and the other side becomes claimable.
- **The two timelocks are ordered, and the client enforces the ordering.** The Bitcoin refund window `T_btc` must be at least twice the NFT reveal window `T_nft`, so that once the buyer reveals `s` to mint, the seller can always claim the Bitcoin before the buyer's refund opens. The client refuses any lock whose window is below this safe minimum (288 blocks) rather than trusting the operator. See [SECURITY.md](SECURITY.md).
- **No party can take both assets, and no funds are stranded.** If the buyer reveals, the seller claims the Bitcoin within the safe margin; if the buyer never reveals, the seller cancels the commitment and the buyer refunds the Bitcoin after `T_btc`. Every lock carries a reachable refund and every commitment a reachable cancel.
- **One client, two NFT chains.** Only the NFT leg is chain-specific---an Ethereum contract (`NFTSecretMint`) or a Solana program (`sol-htlc`). The Bitcoin HTLC, the secret, and the client flow are identical for both.

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

The demo spins up a Bitcoin regtest node and the chosen NFT chain (an Anvil node or a Solana test validator), deploys the contract / loads the program, and steps through buyer-locks-BTC → seller-commits-NFT → buyer-reveals-and-mints → seller-claims-BTC, pausing between steps. Add `--bound` to restrict the mint to the authorized buyer, or `--yes` to run without pausing.

## End-to-End Tests

The same flows back the end-to-end tests. The tests spin up real local chains and drive the real client, so they are ignored by default and run on demand:

```bash
cargo test -p e2e -- --ignored
```

They cover the happy path on both NFT chains (open and bound mints), the refund and cancel recovery paths, and the defection paths (unsafe timelock, premature refund, wrong secret, unauthorized mint, replay). See the [Development Guide](docs/development.md) for the toolchains they expect on `PATH`.

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

## Development

Please run the following from the repository root before opening a pull request:

```bash
cargo +nightly fmt
cargo clippy --all-features --all-targets --workspace -- -D warnings
cargo build --release --all-features --all-targets
cargo doc --all-features --no-deps --document-private-items --workspace
cargo test --all-features --all-targets --workspace
```

The Solana program and the Ethereum contract have their own suites. See the [Development Guide](docs/development.md) for the workspace layout, toolchain pins, and how to run the end-to-end matrix locally.

## Security

This project is **not audited** and is experimental. [SECURITY.md](SECURITY.md) documents the two-timelock safety invariant, what the revealed secret does and does not expose, the front-running exposure on open mints, the residual HTLC griefing properties, contract-address / program-id pinning, and the explicit out-of-scope list. Please report vulnerabilities privately, as described there.

## Contributing

Contributions are welcome. Please read the [Contributing Guidelines](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md), and browse [Good First Issues](https://github.com/kobby-pentangeli/atomic-swap/labels/good%20first%20issue).

## License

Licensed under either [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
