# client

The orchestration CLI for the [Atomic Swap](../README.md). It drives the full cross-chain lifecycle---lock Bitcoin, commit the NFT, reveal-and-mint, claim Bitcoin---against either NFT chain through one binary, and enforces the two-timelock safety invariant so unsafe parameter combinations are refused rather than trusted.

It talks to Bitcoin Core over JSON-RPC, to Ethereum via [`alloy`](https://github.com/alloy-rs/alloy) (the contract is bound from the Foundry ABI with the `sol!` macro), and to Solana via the Anchor client.

## Installation

Install the CLI (this also installs the `derive_privkey` helper) with:

```bash
cargo install --git https://github.com/kobby-pentangeli/atomic-swap client
```

Or build it from a checkout of the workspace:

```bash
cargo build --release -p client               # binary at target/release/client
cargo run   --release -p client -- <command>  # run from the checkout without installing
```

The examples below invoke the installed `client` binary; from a checkout, substitute `cargo run --release -p client --` for `client`.

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

## Deriving a Bitcoin key (`derive_privkey`)

The `--buyer-btc-key`/`--seller-btc-key` flags (env: `BUYER_BTC_PRIVKEY`/`SELLER_BTC_PRIVKEY`) take a raw 32-byte secret as 64 hex characters. When your key lives in an HD wallet you hold a BIP-32 extended private key (`xpriv`) instead, so the second binary this crate ships, `derive_privkey`, resolves a derivation path against an `xpriv` and prints exactly that hex secret:

```bash
derive_privkey <xpriv> <derivation_path>
```

For example, against the BIP-32 test vector:

```bash
$ derive_privkey xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi "m/0'"
edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
```

Feed the result straight to a swap command so the key never lands in your shell history:

```bash
client lock-btc --btc-amount 100000 \
  --buyer-btc-key "$(derive_privkey "$XPRIV" "m/84'/0'/0'/0/0")"
```

The output is a live private key: prefer command substitution or a `.env` entry over echoing it, and never commit it.

## As a library

The crate is primarily a binary, but its chain modules are reusable from a checkout. See the [Development Guide](../docs/development.md) for the workspace layout and the end-to-end harness, and [SECURITY.md](../SECURITY.md) for the threat model.

## License

Licensed under either [Apache-2.0](../LICENSE-APACHE) or [MIT](../LICENSE-MIT) at your option.
