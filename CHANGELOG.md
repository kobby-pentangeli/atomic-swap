# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/kobby-pentangeli/atomic-swap/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kobby-pentangeli/atomic-swap/releases/tag/v0.1.0
