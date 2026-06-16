# client

The orchestration CLI for the [Atomic Swap](../README.md). It drives the full cross-chain lifecycle---lock Bitcoin, commit the NFT, reveal-and-mint, claim Bitcoin---against either NFT chain through one binary, and enforces the two-timelock safety invariant so unsafe parameter combinations are refused rather than trusted.

It talks to Bitcoin Core over JSON-RPC, to Ethereum via [`alloy`](https://github.com/alloy-rs/alloy) (the contract is bound from the Foundry ABI with the `sol!` macro), and to Solana via the Anchor client.

## Commands

```bash
# Buyer locks Bitcoin in the HTLC and writes the secret to a file.
client lock-btc --btc-amount 100000

# Seller commits the NFT behind the buyer's secret hash (Ethereum shown).
client commit-for-mint --chain eth \
  --secret-hash <hash> --nft-price <wei> --token-id 1 \
  --metadata-uri <uri> [--buyer-address <addr>]

# Buyer reveals the secret to mint the NFT and pay the price.
client mint-with-secret --chain eth --secret-file <path>

# Seller reuses the now-public secret to claim the Bitcoin.
client claim-btc --secret-file <path>

# Recovery paths.
client cancel-commit --chain eth --token-id 1     # seller cancels an unminted commitment
client refund-btc --secret-file <path>            # buyer reclaims BTC after the timeout height
```

Use `--chain sol` for the Solana leg (with `--sol-buyer` to bind a buyer instead of `--buyer-address`). `lock-btc`'s `--timeout` is a relative window in blocks; it is rejected below the safe minimum that keeps the swap atomic.

## Configuration

Every argument has an environment-variable fallback, so configuration can live in a `.env` file (see [`.env.template`](../.env.template)). Pass `--no-env` to ignore `.env` and read from the process environment only. `-o json` prints structured, machine-readable output for each step; set `RUST_LOG=info` for progress logs. No private key or pre-reveal secret is ever logged.

## As a library

The crate is primarily a binary, but its chain modules are reusable from a checkout. It also ships a second binary, `derive_privkey`, which turns a wallet xpriv into the raw swap key for real-network deployments.

## Building and running

```bash
cargo run --release -p client -- <command> [flags]
```

See the [Development Guide](../docs/development.md) for the workspace layout and the end-to-end harness, and [SECURITY.md](../SECURITY.md) for the threat model.

## License

Licensed under either [Apache-2.0](../LICENSE-APACHE) or [MIT](../LICENSE-MIT) at your option.
