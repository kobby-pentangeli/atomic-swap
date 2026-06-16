# Development Guide

This guide covers the toolchains, commands, and workspace layout needed to build, test, and run the swap end to end. For the lifecycle and deployment, see the [README](../README.md); for the trust model, see [SECURITY.md](../SECURITY.md).

## Workspace layout

The repository is one Cargo workspace plus two satellites that the root workspace deliberately does not own, because the Solana SBF toolchain cannot parse the host crates' edition-2024 manifests and vice versa:

| Path                                | Workspace / project                                                                                                      |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `./` (`agent/btc`, `client`, `e2e`) | Root Cargo workspace (host crates: the Bitcoin HTLC library, the CLI, and the end-to-end harness).                       |
| `agent/sol`                         | Anchor workspace: the `sol-htlc` program. Excluded from the root workspace; the client consumes it as a path dependency. |
| `agent/sol/harness`                 | `litesvm` test harness for the program. A further crate, excluded from the Anchor workspace.                             |
| `agent/eth`                         | Foundry project: the `NFTSecretMint` contract, its tests, and the deploy script.                                         |

The split means the root `cargo clippy`/`cargo test` cover the host crates, while the program and its harness, and the Foundry contract, are checked through their own commands (below). All crates share `version` through `[workspace.package]`; the `sol-htlc` program sets the same version directly, since it lives across the workspace boundary.

## Toolchains

`scripts/setup.sh` installs and pins every toolchain the project builds against; `scripts/setup.sh --verify` reports what is present without installing anything. It also takes per-component flags (`--rust`, `--foundry`, `--solana`, `--anchor`, `--bitcoin`). The components and the few non-obvious details:

### Rust

Stable plus nightly; the project formats with `cargo +nightly fmt`. The host crates use the 2024 edition and declare an MSRV of 1.88 (`[workspace.package].rust-version`).

### Foundry + Soldeer

Install Foundry (`forge`, `cast`, `anvil`). Solidity dependencies are managed by Soldeer, not git submodules, and `dependencies/` is restored from the lockfile:

```bash
cd agent/eth && forge soldeer install
```

### Agave (Solana) + SBF build tools

The Agave CLI is pinned to `v3.1.10`. Build the program to SBF from the Anchor workspace with:

```bash
cd agent/sol && cargo build-sbf
```

No `--tools-version` override is needed: the Agave 3.1 line's bundled platform-tools compiler parses the Anchor 1.x edition-2024 build dependencies. (Older Agave releases do not, and would require selecting a newer platform-tools with `--tools-version`.) `cargo build-sbf` emits the same `target/deploy/sol_htlc.so` that `anchor build` does, without provisioning `avm`/the Anchor CLI.

### Anchor

Installed via `avm`, pinned to `1.0.2`. Needed for `anchor build`/`anchor deploy`; `cargo build-sbf` alone is enough to produce the program artifact the harness and the end-to-end suite load.

### Bitcoin Core

Pinned to `31.0` (`bitcoind`/`bitcoin-cli`). The end-to-end suite and the demo run a regtest node.

## Dev commands

Run these from the repository root before opening a pull request:

```bash
cargo +nightly fmt
cargo clippy --all-features --all-targets --workspace -- -D warnings
cargo build --release --all-features --all-targets
cargo doc --all-features --no-deps --document-private-items --workspace
cargo test --all-features --all-targets --workspace
```

The program and the contract carry their own suites, since the root workspace excludes them:

```bash
# Solana program: host-side lint/format over the program and harness manifests,
# the SBF build, and the litesvm harness tests.
cargo fmt --manifest-path agent/sol/programs/sol-htlc/Cargo.toml --check
cargo clippy --manifest-path agent/sol/harness/Cargo.toml --all-targets -- -D warnings
( cd agent/sol && cargo build-sbf )
cargo test --manifest-path agent/sol/harness/Cargo.toml

# Ethereum contract (Foundry).
cd agent/eth && forge fmt --check && forge build && forge test
```

> **macOS link note.** A `lto = "fat"` release build can occasionally fail to *link* on macOS, because the Xcode Command-Line-Tools linker's libLTO can lag the LLVM that rustc was built against. The same build links cleanly on CI/Linux, or locally with LTO disabled. This is an environment caveat, not a code defect.

## End-to-end suite

The `e2e` crate drives the real `client` binary against ephemeral local chains---`bitcoind -regtest`, `anvil`, and `solana-test-validator`, each spawned as a child process and torn down on drop. Its live tests are `#[ignore]`d, so `cargo test --workspace` compiles them (catching client/contract API drift) but skips them. Run them explicitly, with the toolchains on `PATH` and the program and contract built first:

```bash
( cd agent/eth && forge soldeer install && forge build )
( cd agent/sol && cargo build-sbf )
cargo build -p client
cargo test -p e2e -- --ignored
```

The suite serializes its worlds with a process-wide lock, so it is independent of `--test-threads`. The same lifecycle primitives back the interactive demo:

```bash
cargo run -p e2e --bin demo -- --chain eth   # or: --chain sol; add --bound or --yes
```

The harness loads the prebuilt program `.so` at its declared id and a vendored Metaplex Token Metadata fixture into the validator at genesis (no `anchor deploy`), and deploys the Foundry contract with `forge create`; the Solana validator runs at `confirmed` commitment to keep runtime bounded.
