//! An ephemeral Anvil node and the Foundry contract deployment.
//!
//! Anvil's default mnemonic yields well-known accounts; the first two are the
//! buyer and seller. The NFT contract is deployed with `forge create` (the same
//! `NFTSecretMint` Foundry builds), and reveal timing is fast-forwarded with the
//! `evm_increaseTime`/`evm_mine` cheatcodes so the commitment's minimum-age
//! window clears without real wall-clock waiting.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::process::{Process, free_port, run, run_in, wait_until};

/// An Anvil account (private key and address).
pub struct EthAccount {
    /// Private key in hex with `0x` prefix.
    pub key: &'static str,
    /// Address in hex with `0x` prefix.
    pub address: &'static str,
}

/// Buyer: Anvil account 0.
pub const BUYER: EthAccount = EthAccount {
    key: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
};

/// Seller: Anvil account 1. Deploys the collection and commits the NFT.
pub const SELLER: EthAccount = EthAccount {
    key: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
};

/// A running Anvil node.
pub struct EthereumNode {
    _node: Process,
    rpc_port: u16,
    eth_dir: PathBuf,
}

impl EthereumNode {
    /// Start `anvil` on a free port.
    pub fn start(eth_dir: PathBuf) -> Result<Self> {
        let rpc_port = free_port()?;
        let mut node = Process::spawn(
            "anvil",
            "anvil",
            &["--port", &rpc_port.to_string(), "--silent"],
        )?;

        let url = format!("http://127.0.0.1:{rpc_port}");
        wait_until("anvil RPC", Duration::from_secs(20), &mut node, || {
            run("cast", &["block-number", "--rpc-url", &url]).is_ok()
        })?;

        Ok(Self {
            _node: node,
            rpc_port,
            eth_dir,
        })
    }

    /// Ethereum RPC URL.
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    /// Deploy `NFTSecretMint(name, symbol, owner)` and return its address.
    ///
    /// The seller deploys, so it owns the collection; `forge create` supplies the
    /// signing key, mirroring the production deployment path (no key in source).
    pub fn deploy(&self, name: &str, symbol: &str) -> Result<String> {
        let url = self.rpc_url();
        let out = run_in(
            &self.eth_dir,
            "forge",
            &[
                "create",
                "src/NFTSecretMint.sol:NFTSecretMint",
                "--rpc-url",
                &url,
                "--private-key",
                SELLER.key,
                "--broadcast",
                "--json",
                "--constructor-args",
                name,
                symbol,
                SELLER.address,
            ],
        )?;

        let parsed: serde_json::Value =
            serde_json::from_str(&out).context("Failed to parse `forge create` JSON output")?;
        parsed
            .get("deployedTo")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .context("`forge create` output had no deployedTo address")
    }

    /// Current owner of `token_id` in the deployed collection (lowercased hex).
    pub fn owner_of(&self, contract: &str, token_id: u64) -> Result<String> {
        let owner = run(
            "cast",
            &[
                "call",
                contract,
                "ownerOf(uint256)(address)",
                &token_id.to_string(),
                "--rpc-url",
                &self.rpc_url(),
            ],
        )?;
        Ok(owner.trim().to_lowercase())
    }

    /// Fast-forward the chain by `secs` seconds and mine a block to apply it.
    pub fn advance_time(&self, secs: u64) -> Result<()> {
        let url = self.rpc_url();
        run(
            "cast",
            &[
                "rpc",
                "evm_increaseTime",
                &secs.to_string(),
                "--rpc-url",
                &url,
            ],
        )?;
        run("cast", &["rpc", "evm_mine", "--rpc-url", &url])?;
        Ok(())
    }
}
