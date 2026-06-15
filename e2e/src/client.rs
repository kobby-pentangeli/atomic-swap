//! A thin wrapper around the compiled `client` binary.
//!
//! Every swap step is exercised through the real CLI (`-o json`), so the harness
//! tests the same argument-parsing and boundary validation a user hits. The
//! result of each command is parsed from the structured JSON the client already
//! emits. `.env` loading is disabled and `RUST_LOG` is stripped so the only thing
//! on stdout is the JSON object.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::build::client_binary;

/// Parsed `lock-btc` output (subset used by the harness).
#[derive(Debug, Deserialize)]
pub struct LockBtc {
    /// Funding transaction id.
    pub txid: String,
    /// SHA-256 hash of the secret, hex (passed to `commit-for-mint`).
    pub secret_hash: String,
    /// Path the generated secret was written to (passed to `claim`/`refund`).
    pub secret_file: String,
    /// Absolute block height at which refund becomes possible.
    pub timeout_height: u32,
    /// Buyer's refund deadline as a Unix timestamp.
    pub btc_refund_deadline: i64,
}

/// Parsed `commit-for-mint` output.
#[derive(Debug, Deserialize)]
pub struct Commit {
    /// Commitment transaction id / signature.
    pub tx_id: String,
}

/// Parsed `mint-with-secret` output.
#[derive(Debug, Deserialize)]
pub struct Mint {
    /// Mint transaction id / signature.
    pub tx_id: String,
    /// The 32-byte secret revealed on the NFT chain, hex.
    pub secret_revealed: String,
}

/// Parsed `claim-btc` output.
#[derive(Debug, Deserialize)]
pub struct ClaimBtc {
    /// Claim transaction id.
    pub txid: String,
}

/// Parsed `refund-btc` output.
#[derive(Debug, Deserialize)]
pub struct RefundBtc {
    /// Refund transaction id.
    pub txid: String,
}

/// Wrapper bound to a located `client` executable.
pub struct Client {
    binary: PathBuf,
}

impl Client {
    /// Locate the built `client` binary.
    pub fn new() -> Result<Self> {
        Ok(Self {
            binary: client_binary()?,
        })
    }

    /// Run a subcommand expected to succeed and parse its JSON output.
    pub fn json<T: serde::de::DeserializeOwned>(&self, args: &[&str]) -> Result<T> {
        let output = self.invoke(args)?;
        let stdout =
            String::from_utf8(output.stdout).context("client produced non-UTF-8 stdout")?;
        if !output.status.success() {
            bail!(
                "client {} failed ({}): {}",
                args.first().copied().unwrap_or_default(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        serde_json::from_str(stdout.trim())
            .with_context(|| format!("Failed to parse client JSON output: {}", stdout.trim()))
    }

    /// Run a subcommand expected to fail, returning the combined error text.
    ///
    /// Errors if the command unexpectedly succeeds, which is exactly the
    /// assertion the adversarial tests need.
    pub fn expect_failure(&self, args: &[&str]) -> Result<String> {
        let output = self.invoke(args)?;
        if output.status.success() {
            bail!(
                "client {} unexpectedly succeeded; expected a rejection",
                args.first().copied().unwrap_or_default()
            );
        }
        let mut text = String::from_utf8_lossy(&output.stderr).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stdout));
        Ok(text)
    }

    fn invoke(&self, args: &[&str]) -> Result<std::process::Output> {
        Command::new(&self.binary)
            .args(["-o", "json", "--no-env"])
            .args(args)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .output()
            .context("Failed to invoke the client binary")
    }
}
