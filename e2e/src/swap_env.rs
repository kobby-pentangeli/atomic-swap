//! A fully wired local swap environment and its lifecycle steps.
//!
//! [`AtomicSwap`] brings up a Bitcoin regtest node and one NFT chain (Anvil or a
//! Solana validator), deploys the contract/loads the program, and exposes each
//! swap step as a method that drives the real client. The tests and the demo
//! binary share this module, so they exercise identical flows.
//!
//! `AtomicSwap`s serialize through a process-wide lock: each spins up multiple chains,
//! so running them concurrently would thrash resources and collide on tooling
//! state regardless of the test harness's thread count.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};

use crate::bitcoin::BitcoinNode;
use crate::build::{self, ensure_built};
use crate::client::{ClaimBtc, Client, Commit, LockBtc, Mint, RefundBtc};
use crate::ethereum::{self, EthereumNode};
use crate::process::{Scratch, run_in};
use crate::solana::{self, SolanaNode};

/// Default swap parameters shared by every scenario.
const TOKEN_ID: u64 = 1;
const NFT_NAME: &str = "CrossChain Secret NFT";
const NFT_SYMBOL: &str = "CCSNFT";
const METADATA_URI: &str = "https://example.com/nft/1.json";
const BTC_AMOUNT_SATS: u64 = 100_000;
const ETH_PRICE_WEI: u64 = 1_000_000_000_000_000_000;
const SOL_PRICE_LAMPORTS: u64 = 1_000_000_000;
/// Bitcoin refund window in blocks; matches the client's safe minimum.
pub const SAFE_TIMEOUT: u32 = 288;
/// Seconds to fast-forward Ethereum so the commitment clears its minimum age.
const ETH_COMMIT_WARP_SECS: u64 = 61;

static SWAP_LOCK: Mutex<()> = Mutex::new(());

/// Which NFT chain a swap settles on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NftChain {
    /// Settle the NFT leg on Ethereum (Anvil + the Foundry contract).
    Ethereum,
    /// Settle the NFT leg on Solana (test validator + the Anchor program).
    Solana,
}

/// The NFT-chain node plus the deployed contract address, if any.
enum Nft {
    Eth {
        node: EthereumNode,
        contract: String,
    },
    Sol {
        node: SolanaNode,
    },
}

/// A running swap environment for one NFT chain.
pub struct AtomicSwap {
    _guard: MutexGuard<'static, ()>,
    _scratch: Scratch,
    btc: BitcoinNode,
    nft: Nft,
    client: Client,
    secret_file: PathBuf,
}

impl AtomicSwap {
    /// Bring up Bitcoin and the chosen NFT chain, ready for a swap.
    pub fn setup(chain: NftChain) -> Result<Self> {
        let guard = SWAP_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        ensure_built()?;

        let scratch = Scratch::new("swap")?;
        let secret_file = scratch.path().join("swap.secret");

        let btc = BitcoinNode::start()?;

        let nft = match chain {
            NftChain::Ethereum => {
                ensure_eth_deps()?;
                let node = EthereumNode::start(build::eth_dir())?;
                let contract = node.deploy(NFT_NAME, NFT_SYMBOL)?;
                Nft::Eth { node, contract }
            }
            NftChain::Solana => Nft::Sol {
                node: SolanaNode::start(&build::program_so(), &build::metaplex_fixture())?,
            },
        };

        Ok(Self {
            _guard: guard,
            _scratch: scratch,
            btc,
            nft,
            client: Client::new()?,
            secret_file,
        })
    }

    // --- Step 1: buyer locks Bitcoin ----------------------------------------

    /// Buyer locks Bitcoin in the HTLC with a `timeout`-block refund window.
    pub fn lock_btc(&self, timeout: u32) -> Result<LockBtc> {
        let secret_out = self.secret_file.to_string_lossy().into_owned();
        let timeout = timeout.to_string();
        let result: LockBtc = self.client.json(&[
            "lock-btc",
            "--btc-rpc",
            &self.btc.rpc_url(),
            "--btc-user",
            self.btc.rpc_user(),
            "--btc-pass",
            self.btc.rpc_pass(),
            "--btc-network",
            "regtest",
            "--buyer-btc-key",
            &self.btc.buyer.secret_hex,
            "--seller-btc-pubkey",
            &self.btc.seller.pubkey,
            "--btc-amount",
            &BTC_AMOUNT_SATS.to_string(),
            "--timeout",
            &timeout,
            "--secret-output",
            &secret_out,
        ])?;
        // Confirm the funding so the HTLC output is spendable by claim/refund.
        self.btc.mine(1)?;
        Ok(result)
    }

    /// Attempt to lock with an unsafe window; expected to be refused.
    pub fn expect_lock_rejected(&self, timeout: u32) -> Result<String> {
        let secret_out = self.secret_file.to_string_lossy().into_owned();
        self.client.expect_failure(&[
            "lock-btc",
            "--btc-rpc",
            &self.btc.rpc_url(),
            "--btc-user",
            self.btc.rpc_user(),
            "--btc-pass",
            self.btc.rpc_pass(),
            "--btc-network",
            "regtest",
            "--buyer-btc-key",
            &self.btc.buyer.secret_hex,
            "--seller-btc-pubkey",
            &self.btc.seller.pubkey,
            "--btc-amount",
            &BTC_AMOUNT_SATS.to_string(),
            "--timeout",
            &timeout.to_string(),
            "--secret-output",
            &secret_out,
        ])
    }

    // --- Step 2: seller commits the NFT -------------------------------------

    /// Seller commits the NFT to `secret_hash`. When `bound`, the mint is
    /// restricted to the buyer's address/pubkey.
    pub fn commit(&self, secret_hash: &str, bound: bool) -> Result<Commit> {
        let args = self.commit_args(secret_hash, bound);
        self.client.json(&str_refs(&args))
    }

    fn commit_args(&self, secret_hash: &str, bound: bool) -> Vec<String> {
        let mut args = vec!["commit-for-mint".into(), "--chain".into()];
        match &self.nft {
            Nft::Eth { node, contract } => {
                args.extend(owned([
                    "eth",
                    "--eth-rpc",
                    &node.rpc_url(),
                    "--seller-eth-key",
                    ethereum::SELLER.key,
                    "--nft-contract",
                    contract,
                    "--secret-hash",
                    secret_hash,
                    "--token-id",
                    &TOKEN_ID.to_string(),
                    "--nft-price",
                    &ETH_PRICE_WEI.to_string(),
                    "--metadata-uri",
                    METADATA_URI,
                ]));
                if bound {
                    args.extend(owned(["--buyer-address", ethereum::BUYER.address]));
                }
            }
            Nft::Sol { node } => {
                args.extend(owned([
                    "sol",
                    "--sol-rpc",
                    &node.rpc_url(),
                    "--sol-ws",
                    &node.ws_url(),
                    "--seller-sol-keypair",
                    &node.seller.keypair_path,
                    "--program-id",
                    solana::PROGRAM_ID,
                    "--name",
                    NFT_NAME,
                    "--symbol",
                    NFT_SYMBOL,
                    "--secret-hash",
                    secret_hash,
                    "--token-id",
                    &TOKEN_ID.to_string(),
                    "--nft-price",
                    &SOL_PRICE_LAMPORTS.to_string(),
                    "--metadata-uri",
                    METADATA_URI,
                ]));
                if bound {
                    args.extend(owned(["--sol-buyer", &node.buyer.pubkey]));
                }
            }
        }
        args
    }

    /// Fast-forward so the commitment clears its minimum age (Ethereum only).
    pub fn advance_for_mint(&self) -> Result<()> {
        if let Nft::Eth { node, .. } = &self.nft {
            node.advance_time(ETH_COMMIT_WARP_SECS)?;
        }
        Ok(())
    }

    // --- Step 3: buyer reveals the secret to mint ---------------------------

    /// Buyer reveals the secret (from the lock file) to mint the NFT.
    pub fn mint(&self) -> Result<Mint> {
        let args = self.mint_args(&self.minter_credentials());
        self.client.json(&str_refs(&args))
    }

    /// Attempt to mint as the wrong (non-bound) caller; expected to be refused.
    pub fn expect_mint_rejected_for_wrong_caller(&self) -> Result<String> {
        let args = self.mint_args(&self.wrong_minter_credentials());
        self.client.expect_failure(&str_refs(&args))
    }

    /// Attempt to mint the same token again after it was minted; expected to be
    /// refused (the minted token / persistent mint PDA blocks the replay).
    pub fn expect_mint_replay_rejected(&self) -> Result<String> {
        let args = self.mint_args(&self.minter_credentials());
        self.client.expect_failure(&str_refs(&args))
    }

    /// Mint credentials for the rightful buyer.
    fn minter_credentials(&self) -> (String, String) {
        match &self.nft {
            Nft::Eth { .. } => ("--buyer-eth-key".into(), ethereum::BUYER.key.into()),
            Nft::Sol { node } => (
                "--buyer-sol-keypair".into(),
                node.buyer.keypair_path.clone(),
            ),
        }
    }

    /// Mint credentials for a caller who is not the bound buyer (the seller).
    fn wrong_minter_credentials(&self) -> (String, String) {
        match &self.nft {
            Nft::Eth { .. } => ("--buyer-eth-key".into(), ethereum::SELLER.key.into()),
            Nft::Sol { node } => (
                "--buyer-sol-keypair".into(),
                node.seller.keypair_path.clone(),
            ),
        }
    }

    fn mint_args(&self, (key_flag, key_value): &(String, String)) -> Vec<String> {
        let secret_file = self.secret_file.to_string_lossy().into_owned();
        let mut args = vec!["mint-with-secret".into(), "--chain".into()];
        match &self.nft {
            Nft::Eth { node, contract } => args.extend(owned([
                "eth",
                "--eth-rpc",
                &node.rpc_url(),
                key_flag,
                key_value,
                "--nft-contract",
                contract,
                "--secret-file",
                &secret_file,
                "--token-id",
                &TOKEN_ID.to_string(),
            ])),
            Nft::Sol { node } => args.extend(owned([
                "sol",
                "--sol-rpc",
                &node.rpc_url(),
                "--sol-ws",
                &node.ws_url(),
                key_flag,
                key_value,
                "--program-id",
                solana::PROGRAM_ID,
                "--secret-file",
                &secret_file,
                "--token-id",
                &TOKEN_ID.to_string(),
            ])),
        }
        args
    }

    // --- Step 4: seller claims Bitcoin with the revealed secret -------------

    /// Seller claims the locked Bitcoin using the secret revealed on the NFT
    /// chain. This is the atomicity link: success proves the on-chain preimage
    /// unlocks the HTLC.
    pub fn claim_btc(&self, revealed_secret: &str, lock: &LockBtc) -> Result<ClaimBtc> {
        let result: ClaimBtc = self.client.json(&[
            "claim-btc",
            "--btc-rpc",
            &self.btc.rpc_url(),
            "--btc-user",
            self.btc.rpc_user(),
            "--btc-pass",
            self.btc.rpc_pass(),
            "--btc-network",
            "regtest",
            "--seller-btc-key",
            &self.btc.seller.secret_hex,
            "--buyer-btc-pubkey",
            &self.btc.buyer.pubkey,
            "--secret",
            revealed_secret,
            "--secret-hash",
            &lock.secret_hash,
            "--lock-txid",
            &lock.txid,
            "--lock-vout",
            "0",
            "--timeout",
            &lock.timeout_height.to_string(),
        ])?;
        self.btc.mine(1)?;
        Ok(result)
    }

    /// Attempt to claim with a secret that does not match the hashlock; expected
    /// to be refused (the HTLC's `OP_SHA256` equality fails).
    pub fn expect_claim_wrong_secret(&self, lock: &LockBtc) -> Result<String> {
        let bogus = "00".repeat(32);
        self.client.expect_failure(&[
            "claim-btc",
            "--btc-rpc",
            &self.btc.rpc_url(),
            "--btc-user",
            self.btc.rpc_user(),
            "--btc-pass",
            self.btc.rpc_pass(),
            "--btc-network",
            "regtest",
            "--seller-btc-key",
            &self.btc.seller.secret_hex,
            "--buyer-btc-pubkey",
            &self.btc.buyer.pubkey,
            "--secret",
            &bogus,
            "--secret-hash",
            &lock.secret_hash,
            "--lock-txid",
            &lock.txid,
            "--lock-vout",
            "0",
            "--timeout",
            &lock.timeout_height.to_string(),
        ])
    }

    // --- Recovery paths -----------------------------------------------------

    /// Seller cancels the (unminted) commitment.
    pub fn cancel(&self) -> Result<()> {
        let mut args = vec!["cancel-commit".into(), "--chain".into()];
        match &self.nft {
            Nft::Eth { node, contract } => args.extend(owned([
                "eth",
                "--eth-rpc",
                &node.rpc_url(),
                "--caller-eth-key",
                ethereum::SELLER.key,
                "--nft-contract",
                contract,
                "--token-id",
                &TOKEN_ID.to_string(),
            ])),
            Nft::Sol { node } => args.extend(owned([
                "sol",
                "--sol-rpc",
                &node.rpc_url(),
                "--sol-ws",
                &node.ws_url(),
                "--caller-sol-keypair",
                &node.seller.keypair_path,
                "--program-id",
                solana::PROGRAM_ID,
                "--token-id",
                &TOKEN_ID.to_string(),
            ])),
        }
        let _: serde_json::Value = self.client.json(&str_refs(&args))?;
        Ok(())
    }

    /// Buyer refunds the locked Bitcoin after the timeout height is reached.
    pub fn refund_btc(&self, lock: &LockBtc) -> Result<RefundBtc> {
        self.mine_to(lock.timeout_height)?;
        let result = self.refund_call()?;
        self.btc.mine(1)?;
        Ok(result)
    }

    /// Attempt to refund before the timeout height; expected to be refused.
    pub fn expect_refund_premature(&self) -> Result<String> {
        let secret_file = self.secret_file.to_string_lossy().into_owned();
        self.client.expect_failure(&[
            "refund-btc",
            "--btc-rpc",
            &self.btc.rpc_url(),
            "--btc-user",
            self.btc.rpc_user(),
            "--btc-pass",
            self.btc.rpc_pass(),
            "--btc-network",
            "regtest",
            "--buyer-btc-key",
            &self.btc.buyer.secret_hex,
            "--seller-btc-pubkey",
            &self.btc.seller.pubkey,
            "--secret-file",
            &secret_file,
            "--lock-vout",
            "0",
        ])
    }

    fn refund_call(&self) -> Result<RefundBtc> {
        let secret_file = self.secret_file.to_string_lossy().into_owned();
        self.client.json(&[
            "refund-btc",
            "--btc-rpc",
            &self.btc.rpc_url(),
            "--btc-user",
            self.btc.rpc_user(),
            "--btc-pass",
            self.btc.rpc_pass(),
            "--btc-network",
            "regtest",
            "--buyer-btc-key",
            &self.btc.buyer.secret_hex,
            "--seller-btc-pubkey",
            &self.btc.seller.pubkey,
            "--secret-file",
            &secret_file,
            "--lock-vout",
            "0",
        ])
    }

    // --- Assertions / observers ---------------------------------------------

    /// Confirmed Bitcoin balance (sats) at the seller's claim address.
    pub fn seller_btc_sats(&self) -> Result<u64> {
        self.btc.balance_sats(&self.btc.seller.address)
    }

    /// On Ethereum, the current owner of the token; `None` on Solana.
    pub fn eth_token_owner(&self) -> Result<Option<String>> {
        match &self.nft {
            Nft::Eth { node, contract } => node.owner_of(contract, TOKEN_ID).map(Some),
            Nft::Sol { .. } => Ok(None),
        }
    }

    /// The buyer's expected NFT-owner identity, for the happy-path assertion.
    pub fn expected_nft_owner(&self) -> Option<String> {
        match &self.nft {
            Nft::Eth { .. } => Some(ethereum::BUYER.address.to_lowercase()),
            Nft::Sol { .. } => None,
        }
    }

    fn mine_to(&self, height: u32) -> Result<()> {
        let current = self.btc.height()?;
        if u64::from(height) > current {
            let needed =
                u32::try_from(u64::from(height) - current).context("Block gap exceeded u32")?;
            self.btc.mine(needed)?;
        }
        Ok(())
    }
}

/// Run `forge soldeer install` if the Foundry dependencies are not present.
fn ensure_eth_deps() -> Result<()> {
    let deps = build::eth_dir().join("dependencies");
    if !deps.exists() {
        run_in(&build::eth_dir(), "forge", &["soldeer", "install"])
            .context("Failed to install Foundry dependencies")?;
    }
    Ok(())
}

/// Map a borrowed argument list into owned `String`s.
fn owned<const N: usize>(args: [&str; N]) -> Vec<String> {
    args.into_iter().map(str::to_string).collect()
}

/// Borrow an owned argument list as `&str` for the client wrapper.
fn str_refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}
