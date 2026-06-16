# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-16

The swap is now provably atomic, i.e., the two timelocks are ordered and enforced, and every component is exercised through a real end-to-end harness. The Ethereum toolchain moves to Foundry, the EVM client to `alloy`, and the Solana tests to native Rust.

### Added

#### Cross-chain soundness

- Enforced the two-timelock safety invariant in the client: the Bitcoin refund window must be at least twice the NFT reveal window, so once the buyer reveals the secret the seller can always claim the Bitcoin before the buyer's refund opens. Unsafe parameter combinations are refused at lock time with an actionable error (`client/src/timelock.rs`).
- On-chain reveal deadline on Solana (`COMMITMENT_TIMEOUT_SECS = 24h`), making the Solana leg symmetric with Ethereum's `COMMITMENT_TIMEOUT` so the preimage can only become public within a bounded window.
- `commit-for-mint` accepts the buyer's Bitcoin refund deadline and re-validates the safe ordering in the wall-clock domain.

#### Testing and validation

- `e2e` crate: an end-to-end harness that drives the real client against ephemeral `bitcoind -regtest`, `anvil`, and `solana-test-validator` chains, plus a narrated interactive `demo` binary built on the same lifecycle.
- Full Foundry test suite for the Ethereum contract: unit, fuzz, and invariant tests with access-control and revert coverage.
- Native Rust `litesvm` harness for the Solana program, replacing the TypeScript suite.
- Script-interpreter (`bitcoinconsensus`) tests for both Bitcoin HTLC spend paths and their failure modes.

#### Tooling and supply chain

- `scripts/setup.sh`: a pinned, idempotent toolchain installer with a `--verify` mode (Rust, Foundry, Agave CLI, Anchor, Bitcoin Core).
- `cargo-deny` dependency auditing (`deny.toml`) wired into CI, with fixable advisories upgraded rather than suppressed.
- `Cargo.lock` is now tracked in git for reproducible builds.

#### Documentation

- `SECURITY.md` threat model (two-timelock invariant, revealed-secret exposure, open-mint front-running, residual griefing, address/program-id pinning, out-of-scope list).
- `docs/development.md` developer guide (workspace layout, toolchain pins, canonical commands, running the e2e suite).
- Per-crate `README`s for `btc-htlc`, `client`, and `e2e`, plus an architecture diagram in the root `README`.

### Changed

- **Ethereum toolchain: Hardhat → Foundry.** OpenZeppelin is vendored via Soldeer; the deploy flow uses `forge script` with CLI-supplied signing keys.
- **EVM client: `ethers` → `alloy`.** The contract is bound from the Foundry ABI with the `sol!` macro, removing the runtime ABI parsing and the Node build dependency.
- **Solana tests: TypeScript → Rust.** Anchor `0.32.1 → 1.0.2`, Solana client/SDK to the `3.1` line, with the host harness excluded from the SBF workspace.
- **Workspace modernized.** A single topology with a `[workspace.package]` block, centralized dependencies, and one lockfile; all crates report `0.3.0`.
- Bitcoin client: fee estimation rebuilt on segwit weight units and single-sourced through selection and change.
- Client arguments are chain-typed per command, removing the optional-field `unwrap`s.
- Solana RPC uses `confirmed` commitment for lower-latency settlement.
- CI rewritten into separate cached Rust, Foundry, and Anchor jobs, gated on `master` and pull requests; the Hardhat coupling is gone.
- MSRV raised to 1.88; Agave pinned to `v3.1.10` and Bitcoin Core to `31.0`.
- `lock-btc`'s default timeout raised from 144 to 288 blocks (the safe minimum).

### Fixed

- **Bitcoin locktime is now a real, chain-derived absolute height.** It was previously ambiguous between absolute and relative semantics and could be meaningless on a chain past the value; lock, claim, and refund now agree on one persisted height.
- **Fee overpayment.** Dynamic fee estimation misread `estimatesmartfee` units, a silent ~1000× overpayment on any network with fee history.
- **Ethereum token-ID-zero hash reuse.** A hash-to-token-ID mapping could not distinguish "no commitment" from "a commitment for token ID 0"; replaced with an explicit existence flag.
- **Solana cancel griefing.** A cancelled commitment could permanently brick its `token_id` and strand rent; minting is now deferred so cancel never leaves a dangling PDA.
- **Solana had no reveal deadline,** which broke atomicity (a buyer could refund the Bitcoin and then mint); a bounded on-chain deadline closes it.
- `mint_with_secret`'s `seller_info` is constrained to the committed seller in the account context.
- The pre-reveal secret is no longer emitted in logs.

### Security

- Provably-unique NFTs on Solana via a Metaplex master edition (`max_supply = 0`), which also removes the freeze-authority censorship vector.
- Ethereum ownership uses `Ownable2Step`; the contract is `Pausable`.
- Open-mint front-running is documented, with buyer-binding as the production-safe default and supported on both chains.

### Removed

- Docker apparatus (`Dockerfile`, `docker-compose.yml`, `.dockerignore`, `docker-setup.sh`) and the shell-script demo (`setup.sh` and `scripts/*.sh`), superseded by the `e2e` crate and `scripts/setup.sh`.
- Hardhat, Ignition, `viem`, and the npm scaffolding.
- The TypeScript Solana test toolchain (`ts-mocha`/`chai`/`yarn`).

## [0.2.0] - 2026-01-26

### Added

#### CLI & Configuration

- `.env` file support for all CLI arguments with `--no-env` flag to disable loading
- `.env.template` with comprehensive configuration examples
- `--secret-file` argument as alternative to `--secret` for all secret-requiring commands
- `--secret-output` argument to `lock-btc` for specifying custom secret file path
- Environment variable defaults for all CLI arguments (e.g., `BTC_RPC_URL`, `SELLER_ETH_PRIVKEY`)
- Default values for common arguments (e.g., `--btc-rpc` defaults to `http://localhost:18443`)

#### Client Implementation

- Added a new command: `refund-btc`: Refund Bitcoin after timeout
- `client/src/utils.rs`: Centralized utility functions including:
  - `write_secret_to_file()`: Secure secret file writing with 0600 permissions
  - `read_secret_from_file()`: Parse secret files
  - `resolve_secrets()`: Resolve secrets from CLI args or file
  - `parse_btc_network()`: Bitcoin network string parsing
- `client/src/btc/fee.rs`: Dedicated Bitcoin fee estimation module
  - `get_fee_rate()`: Dynamic fee estimation with fallback
  - `estimate_fee_for_htlc_funding()`: HTLC funding transaction fees
  - `estimate_fee_for_htlc_claim()`: HTLC claim transaction fees
  - `estimate_fee_for_htlc_timeout()`: HTLC timeout transaction fees
- Automatic time advancement in Ethereum demo after `commit-for-mint` to satisfy `MIN_COMMITMENT_TIME`
- `crossterm` dependency for type-safe colored terminal output

#### Testing

- End-to-end tests for Solana HTLC program (`agent/sol/tests/sol-htlc.ts`)
- Witness creation path tests in `btc-htlc` library

#### CI/CD

- npm dependency caching for faster builds
- Hardhat artifact caching
- Cargo registry, index, and build caching

#### Documentation

- Comprehensive devnet deployment guide for Bitcoin testnet/signet, Ethereum Sepolia, and Solana Devnet
- `.env` workflow documentation with variable mapping table
- NFTSecretMint contract ABI now auto-generated to `agent/eth/abi/`
- Enhanced inline documentation across all modules

### Changed

#### CLI Breaking Changes

- **BREAKING**: Most CLI arguments now optional with environment variable defaults
- **BREAKING**: `--secret` and `--secret-hash` now `Option<String>` instead of required `String`
- **BREAKING**: `--token-id` now `Option<u64>` with `TOKEN_ID` env var support
- **BREAKING**: Secret arguments now accept either `--secret <hex>` OR `--secret-file <path>`
- All commands now use environment variables from `.env` file by default

#### Refactoring & Code Quality

- Extracted Bitcoin RPC utilities from `btc.rs` into dedicated modules
- Refactored `BtcTxSigner` for improved witness creation and idiomatic Rust patterns
- Improved error handling with better context messages
- Simplified Ethereum client timing validation and polling

#### Infrastructure

- Improved Docker setup with better directory structure handling
- Enhanced setup scripts
- Better separation of concerns in demo functions
- Restructured README with clear separation between local demo and devnet deployment

### Removed

- `client/src/btc/utils.rs` (moved to `client/src/utils.rs`)
- `agent/sol/tests/Cargo.toml` and associated Rust test infrastructure

## [0.1.0] - 2025-01-14

### Implemented

- Initial release of cross-chain atomic swap system
- Bitcoin HTLC library (`agent/btc`) with P2WSH script generation
- Ethereum NFTSecretMint contract (`agent/eth`) with ERC721 minting
- Solana sol-htlc program (`agent/sol`) with SPL token metadata
- Rust CLI orchestration tool (`client`) with the following commands:
  - `lock-btc`: Lock Bitcoin in HTLC
  - `commit-for-mint`: Commit NFT for minting
  - `mint-with-secret`: Mint NFT by revealing secret
  - `claim-btc`: Claim Bitcoin using revealed secret
  - `cancel-commit`: Cancel commitment
- Docker Compose setup for local development
- Setup scripts (`setup.sh`, `docker-setup.sh`) for automated environment configuration
- Demo environment with Bitcoin regtest, Hardhat, and Solana test validator
- Multi-chain support (Bitcoin ↔ Ethereum/Solana NFT)
- SHA256 hash consistency across all chains
- Dynamic Bitcoin fee estimation
- Comprehensive README with setup and usage instructions

---

## Guidelines for Contributors

When adding entries to this changelog for future releases:

1. **Format**: Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
2. **Categories**: Use Added, Changed, Deprecated, Removed, Fixed, Security
3. **Audience**: Write for users, not developers (focus on impact, not implementation)
4. **Links**: Add comparison links at the bottom: `[0.3.0]: https://github.com/kobby-pentangeli/atomic-swap/compare/v0.2.0...v0.3.0`

[0.3.0]: https://github.com/kobby-pentangeli/atomic-swap/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kobby-pentangeli/atomic-swap/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kobby-pentangeli/atomic-swap/releases/tag/v0.1.0
