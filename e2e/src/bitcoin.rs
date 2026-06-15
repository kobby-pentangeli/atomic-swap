//! An ephemeral Bitcoin Core regtest node and its funded swap accounts.
//!
//! The node is driven through `bitcoin-cli`. Buyer and seller keys are generated
//! in-process so their WIF/pubkey/address all parse with the same `bitcoin`
//! crate the client uses; the buyer descriptor is imported into the node wallet
//! so the client's `listunspent`-based funding selection can see its UTXOs.

use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey};

use crate::process::{Process, Scratch, free_port, run, wait_until};

const RPC_USER: &str = "user";
const RPC_PASS: &str = "password";
const WALLET: &str = "e2e";

/// A regtest key set covering every form the harness needs: the raw secret in
/// hex (the client's `--*-btc-key` flags), the WIF (the wallet descriptor
/// import), the compressed public key, and the P2WPKH address.
pub struct BtcKey {
    /// Secret key as 64 hex chars (`--buyer-btc-key` / `--seller-btc-key`).
    pub secret_hex: String,
    /// Private key in WIF format (for the `wpkh(...)` wallet descriptor import).
    pub wif: String,
    /// Compressed public key in hex (`--seller-btc-pubkey` / `--buyer-btc-pubkey`).
    pub pubkey: String,
    /// P2WPKH address string.
    pub address: String,
}

impl BtcKey {
    fn generate() -> Result<Self> {
        let secp = Secp256k1::new();
        let (secret, _) = secp.generate_keypair(&mut rand::thread_rng());
        let private = PrivateKey::new(secret, Network::Regtest);
        let compressed = CompressedPublicKey::from_private_key(&secp, &private)
            .context("Failed to derive compressed public key")?;
        Ok(Self {
            secret_hex: secret.display_secret().to_string(),
            wif: private.to_wif(),
            pubkey: compressed.to_string(),
            address: Address::p2wpkh(&compressed, Network::Regtest).to_string(),
        })
    }
}

/// A running regtest node with a funded buyer and a seller key.
pub struct BitcoinNode {
    _scratch: Scratch,
    _daemon: Process,
    rpc_port: u16,
    /// Buyer account: holds the locked Bitcoin's funding UTXO.
    pub buyer: BtcKey,
    /// Seller account: receives the claimed Bitcoin.
    pub seller: BtcKey,
}

impl BitcoinNode {
    /// Start `bitcoind -regtest`, create a wallet, and fund the buyer with 1 BTC.
    pub fn start() -> Result<Self> {
        let scratch = Scratch::new("btc")?;
        let datadir = scratch.path().to_string_lossy().into_owned();
        let rpc_port = free_port()?;
        let p2p_port = free_port()?;

        let mut daemon = Process::spawn(
            "bitcoind",
            "bitcoind",
            &[
                "-regtest",
                &format!("-datadir={datadir}"),
                &format!("-rpcport={rpc_port}"),
                &format!("-rpcuser={RPC_USER}"),
                &format!("-rpcpassword={RPC_PASS}"),
                "-rpcbind=127.0.0.1",
                "-rpcallowip=127.0.0.1",
                &format!("-port={p2p_port}"),
                "-listen=0",
                "-fallbackfee=0.0001",
                "-txindex=1",
                "-server=1",
            ],
        )?;

        wait_until("bitcoind RPC", Duration::from_secs(30), &mut daemon, || {
            run(
                "bitcoin-cli",
                &[
                    "-regtest",
                    &format!("-rpcport={rpc_port}"),
                    &format!("-rpcuser={RPC_USER}"),
                    &format!("-rpcpassword={RPC_PASS}"),
                    "getblockchaininfo",
                ],
            )
            .is_ok()
        })?;

        let node = Self {
            _scratch: scratch,
            _daemon: daemon,
            rpc_port,
            buyer: BtcKey::generate()?,
            seller: BtcKey::generate()?,
        };

        node.fund_buyer()?;
        Ok(node)
    }

    /// Bitcoin RPC URL the client connects to.
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    /// RPC username.
    pub fn rpc_user(&self) -> &str {
        RPC_USER
    }

    /// RPC password.
    pub fn rpc_pass(&self) -> &str {
        RPC_PASS
    }

    /// Mine `count` blocks to a throwaway wallet address (advances the tip).
    pub fn mine(&self, count: u32) -> Result<()> {
        let addr = self.wallet_cli(&["getnewaddress"])?;
        self.cli(&["generatetoaddress", &count.to_string(), &addr])?;
        Ok(())
    }

    /// Current best-block height.
    pub fn height(&self) -> Result<u64> {
        self.cli(&["getblockcount"])?
            .parse()
            .context("Failed to parse block height")
    }

    /// Total confirmed Bitcoin (in satoshis) currently held at `address`.
    ///
    /// Uses `scantxoutset` so any address can be queried without importing it
    /// into the wallet, which is what we need to assert the seller's claimed
    /// output without tracking the seller key.
    pub fn balance_sats(&self, address: &str) -> Result<u64> {
        let out = self.cli(&["scantxoutset", "start", &format!("[\"addr({address})\"]")])?;
        let scan: serde_json::Value =
            serde_json::from_str(&out).context("Failed to parse scantxoutset output")?;
        let btc = scan
            .get("total_amount")
            .and_then(serde_json::Value::as_f64)
            .context("scantxoutset returned no total_amount")?;
        // total_amount is BTC; convert to whole satoshis.
        Ok((btc * 1e8).round() as u64)
    }

    fn fund_buyer(&self) -> Result<()> {
        self.cli(&["createwallet", WALLET])
            .or_else(|_| self.cli(&["loadwallet", WALLET]))?;

        // Mature a coinbase to the wallet so it can fund the buyer.
        self.mine(101)?;

        // Import the buyer descriptor with its private key so its UTXOs appear
        // in `listunspent` as spendable (the client filters out watch-only
        // outputs). `getdescriptorinfo`'s `descriptor` field is the public,
        // watch-only normalization, so the private descriptor is rebuilt from
        // the WIF plus the separately returned `checksum`.
        let descriptor = format!("wpkh({})", self.buyer.wif);
        let info = self.cli(&["getdescriptorinfo", &descriptor])?;
        let info: serde_json::Value =
            serde_json::from_str(&info).context("Failed to parse getdescriptorinfo output")?;
        let checksum = info
            .get("checksum")
            .and_then(serde_json::Value::as_str)
            .context("getdescriptorinfo returned no checksum")?;
        let request = format!("[{{\"desc\":\"{descriptor}#{checksum}\",\"timestamp\":\"now\"}}]");
        self.wallet_cli(&["importdescriptors", &request])?;

        // Send the buyer 1 BTC and confirm it.
        self.wallet_cli(&["sendtoaddress", &self.buyer.address, "1.0"])?;
        self.mine(1)?;
        Ok(())
    }

    fn cli(&self, args: &[&str]) -> Result<String> {
        let port = format!("-rpcport={}", self.rpc_port);
        let user = format!("-rpcuser={RPC_USER}");
        let pass = format!("-rpcpassword={RPC_PASS}");
        let mut full = vec!["-regtest", &port, &user, &pass];
        full.extend_from_slice(args);
        run("bitcoin-cli", &full)
    }

    fn wallet_cli(&self, args: &[&str]) -> Result<String> {
        let port = format!("-rpcport={}", self.rpc_port);
        let user = format!("-rpcuser={RPC_USER}");
        let pass = format!("-rpcpassword={RPC_PASS}");
        let wallet = format!("-rpcwallet={WALLET}");
        let mut full = vec!["-regtest", &port, &user, &pass, &wallet];
        full.extend_from_slice(args);
        run("bitcoin-cli", &full)
    }
}
