//! End-to-end harness for the cross-chain atomic swap.
//!
//! This crate stands up ephemeral local chains---Bitcoin regtest, an Anvil
//! Ethereum node, and a Solana test validator---deploys the NFT contract and
//! loads the HTLC program, and drives the **real** swap client through the full
//! lifecycle against them. It backs two things:
//!
//! - the integration tests in `tests/`, which gate the release on the swap being
//!   genuinely atomic (i.e., the secret revealed on the NFT chain unlocks the
//!   Bitcoin HTLC) and on every defection path being rejected, and
//! - the [`demo`](../demo) binary, an interactive walk through that same
//!   lifecycle so the swap can be observed end to end.
//!
//! Both share [`AtomicSwap`], so what the demo shows is exactly what the tests
//! assert. The live work is heavyweight (real validators, real signing), so the
//! tests are `#[ignore]`d: `cargo test` compiles them, while `--ignored` runs them.

pub mod bitcoin;
pub mod build;
pub mod client;
pub mod ethereum;
pub mod process;
pub mod solana;
pub mod swap_env;

pub use swap_env::{AtomicSwap, NftChain, SAFE_TIMEOUT};
