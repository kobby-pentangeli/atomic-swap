//! An ephemeral `solana-test-validator` preloaded with the HTLC program.
//!
//! The prebuilt program `.so` is loaded at its declared id and the vendored
//! Metaplex Token Metadata program is loaded at its mainnet id, both at genesis
//! via `--bpf-program`. This is why no `anchor deploy` or program-keypair
//! reconciliation is needed: the program is live at `PROGRAM_ID` from the first
//! slot, and the master-edition CPI the mint performs resolves against the
//! loaded Metaplex program.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;

use crate::process::{Process, Scratch, free_port, run, wait_until};

/// Declared id of the HTLC program (`declare_id!` / `Anchor.toml`).
pub const PROGRAM_ID: &str = "2geXhC16Hc9Q9QBP4DQZx2xxUumXHLS5ugYqXwSB4jXo";

/// Mainnet id of the Metaplex Token Metadata program.
pub const METAPLEX_ID: &str = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";

/// A Solana account backed by a keypair file on disk.
pub struct SolAccount {
    /// Path to the keypair file (the `--*-sol-keypair` flags take this).
    pub keypair_path: String,
    /// Base58 public key.
    pub pubkey: String,
}

/// A running test validator with funded buyer and seller accounts.
pub struct SolanaNode {
    _scratch: Scratch,
    _validator: Process,
    rpc_port: u16,
    /// Buyer account: reveals the secret and mints the NFT.
    pub buyer: SolAccount,
    /// Seller account: commits the NFT and receives its price.
    pub seller: SolAccount,
}

impl SolanaNode {
    /// Start the validator with `program_so` loaded at [`PROGRAM_ID`] and
    /// `metaplex_so` at [`METAPLEX_ID`], then fund the buyer and seller.
    pub fn start(program_so: &Path, metaplex_so: &Path) -> Result<Self> {
        let scratch = Scratch::new("sol")?;
        let ledger = scratch.path().join("ledger");
        let rpc_port = free_port()?;
        let faucet_port = free_port()?;

        let mut validator = Process::spawn(
            "solana-test-validator",
            "solana-test-validator",
            &[
                "--reset",
                "--quiet",
                "--rpc-port",
                &rpc_port.to_string(),
                "--faucet-port",
                &faucet_port.to_string(),
                "--ledger",
                &ledger.to_string_lossy(),
                "--bpf-program",
                PROGRAM_ID,
                &program_so.to_string_lossy(),
                "--bpf-program",
                METAPLEX_ID,
                &metaplex_so.to_string_lossy(),
            ],
        )?;

        let url = format!("http://127.0.0.1:{rpc_port}");
        wait_until(
            "solana-test-validator RPC",
            Duration::from_secs(60),
            &mut validator,
            || run("solana", &["cluster-version", "--url", &url]).is_ok(),
        )?;

        let node = Self {
            buyer: keygen(scratch.path(), "buyer")?,
            seller: keygen(scratch.path(), "seller")?,
            rpc_port,
            _validator: validator,
            _scratch: scratch,
        };

        node.airdrop(&node.buyer.pubkey, 10)?;
        node.airdrop(&node.seller.pubkey, 10)?;
        Ok(node)
    }

    /// Solana JSON-RPC URL.
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    /// Solana PubSub (WebSocket) URL, which the validator serves on `rpc + 1`.
    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.rpc_port + 1)
    }

    fn airdrop(&self, pubkey: &str, sol: u32) -> Result<()> {
        run(
            "solana",
            &[
                "airdrop",
                &sol.to_string(),
                pubkey,
                "--url",
                &self.rpc_url(),
            ],
        )?;
        Ok(())
    }
}

fn keygen(dir: &Path, name: &str) -> Result<SolAccount> {
    let path: PathBuf = dir.join(format!("{name}.json"));
    let path_str = path.to_string_lossy().into_owned();
    run(
        "solana-keygen",
        &[
            "new",
            "--no-bip39-passphrase",
            "--silent",
            "--force",
            "--outfile",
            &path_str,
        ],
    )?;
    let pubkey = run("solana-keygen", &["pubkey", &path_str])?;
    Ok(SolAccount {
        keypair_path: path_str,
        pubkey,
    })
}
