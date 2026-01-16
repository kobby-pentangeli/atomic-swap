//! Core data structures used throughout the swap
//! execution pipeline, including chain identifiers and command arguments.

use std::path::PathBuf;

use bitcoin::{Address as BtcAddress, Network, Txid};
use ethers::core::types::{Address as EthAddress, U256};
use serde::{Deserialize, Serialize};

/// Target blockchain for NFT operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Ethereum,
    Solana,
}

impl core::str::FromStr for Chain {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "eth" | "ethereum" => Ok(Self::Ethereum),
            "sol" | "solana" => Ok(Self::Solana),
            _ => Err(anyhow::anyhow!("Invalid chain: {s}. Use 'eth' or 'sol'")),
        }
    }
}

impl AsRef<str> for Chain {
    fn as_ref(&self) -> &str {
        match self {
            Self::Ethereum => "ethereum",
            Self::Solana => "solana",
        }
    }
}

/// Ethereum NFT commitment information returned from the contract.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct CommitmentInfo {
    /// SHA-256 hash of the secret required to mint.
    pub secret_hash: [u8; 32],
    /// Address of the seller who created the commitment.
    pub seller: EthAddress,
    /// Address of the authorized buyer (zero address if unrestricted).
    pub buyer: EthAddress,
    /// Price in wei required to mint the NFT.
    pub price: U256,
    /// Unix timestamp when the commitment was created.
    pub commit_time: U256,
    /// Whether this commitment is still active (not yet minted or cancelled).
    pub is_active: bool,
    /// IPFS or HTTP URI for the NFT metadata.
    pub token_uri: String,
}

/// Arguments for the lock-btc command.
///
/// Used by the buyer to lock Bitcoin funds in an HTLC.
#[derive(Debug)]
pub struct LockBtcArgs {
    /// Bitcoin RPC endpoint URL.
    pub btc_rpc: String,
    /// Bitcoin RPC username.
    pub btc_user: String,
    /// Bitcoin RPC password.
    pub btc_pass: String,
    /// Bitcoin network (mainnet, testnet, signet, regtest).
    pub btc_network: Network,
    /// Buyer's Bitcoin private key in WIF format.
    pub buyer_btc_key: String,
    /// Seller's Bitcoin public key in hex format.
    pub seller_btc_pubkey: String,
    /// Amount to lock in satoshis.
    pub btc_amount: u64,
    /// HTLC timeout in blocks.
    pub timeout: u32,
    /// Optional file path to write the generated secret.
    pub secret_output_file: Option<PathBuf>,
}

/// Arguments for the commit-for-mint command.
///
/// Used by the seller to commit an NFT for minting on Ethereum or Solana.
#[derive(Debug, Clone)]
pub struct CommitForMintArgs {
    /// Target blockchain for the NFT.
    pub chain: Chain,
    /// Ethereum RPC endpoint URL.
    pub eth_rpc: Option<String>,
    /// Seller's Ethereum private key.
    pub seller_eth_key: Option<String>,
    /// Ethereum NFT contract address.
    pub nft_contract: Option<EthAddress>,
    /// Authorized buyer address (None for unrestricted).
    pub buyer_address: Option<EthAddress>,
    /// Solana RPC endpoint URL.
    pub sol_rpc: Option<String>,
    /// Solana WebSocket endpoint URL.
    pub sol_ws: Option<String>,
    /// Path to seller's Solana keypair file.
    pub seller_sol_keypair: Option<String>,
    /// Solana HTLC program ID.
    pub program_id: Option<String>,
    /// NFT name (Solana only).
    pub name: Option<String>,
    /// NFT symbol (Solana only).
    pub symbol: Option<String>,
    /// SHA-256 hash of the secret.
    pub secret_hash: [u8; 32],
    /// Token ID for the NFT.
    pub token_id: u64,
    /// NFT price (wei for Ethereum, lamports for Solana).
    pub nft_price: u64,
    /// NFT metadata URI.
    pub metadata_uri: String,
}

/// Arguments for the mint-with-secret command.
///
/// Used by the buyer to reveal the secret and mint the NFT.
#[derive(Debug, Clone)]
pub struct MintWithSecretArgs {
    /// Target blockchain for the NFT.
    pub chain: Chain,
    /// Ethereum RPC endpoint URL.
    pub eth_rpc: Option<String>,
    /// Buyer's Ethereum private key.
    pub buyer_eth_key: Option<String>,
    /// Ethereum NFT contract address.
    pub nft_contract: Option<EthAddress>,
    /// Solana RPC endpoint URL.
    pub sol_rpc: Option<String>,
    /// Solana WebSocket endpoint URL.
    pub sol_ws: Option<String>,
    /// Path to buyer's Solana keypair file.
    pub buyer_sol_keypair: Option<String>,
    /// Solana HTLC program ID.
    pub program_id: Option<String>,
    /// The 32-byte secret preimage.
    pub secret: [u8; 32],
    /// Token ID to mint.
    pub token_id: u64,
}

/// Arguments for the claim-btc command.
///
/// Used by the seller to claim Bitcoin from the HTLC using the revealed secret.
#[derive(Debug)]
pub struct ClaimBtcArgs {
    /// Bitcoin RPC endpoint URL.
    pub btc_rpc: String,
    /// Bitcoin RPC username.
    pub btc_user: String,
    /// Bitcoin RPC password.
    pub btc_pass: String,
    /// Bitcoin network (mainnet, testnet, signet, regtest).
    pub btc_network: Network,
    /// Seller's Bitcoin private key in WIF format.
    pub seller_btc_key: String,
    /// Buyer's Bitcoin public key in hex format.
    pub buyer_btc_pubkey: String,
    /// The 32-byte secret preimage.
    pub secret: [u8; 32],
    /// SHA-256 hash of the secret (for verification).
    pub secret_hash: [u8; 32],
    /// Transaction ID of the lock transaction.
    pub lock_txid: Txid,
    /// Output index in the lock transaction.
    pub lock_vout: u32,
    /// HTLC timeout in blocks.
    pub timeout: u32,
    /// Optional destination address (defaults to seller's wallet).
    pub destination: Option<BtcAddress>,
}

/// Arguments for the cancel-commit command.
///
/// Used to cancel an NFT commitment. On Ethereum, the seller can cancel
/// before timeout; anyone can cancel after timeout. On Solana, only the
/// seller can cancel.
#[derive(Debug, Clone)]
pub struct CancelCommitArgs {
    /// Target blockchain for the NFT.
    pub chain: Chain,
    /// Ethereum RPC endpoint URL.
    pub eth_rpc: Option<String>,
    /// Caller's Ethereum private key.
    pub caller_eth_key: Option<String>,
    /// Ethereum NFT contract address.
    pub nft_contract: Option<EthAddress>,
    /// Solana RPC endpoint URL.
    pub sol_rpc: Option<String>,
    /// Solana WebSocket endpoint URL.
    pub sol_ws: Option<String>,
    /// Path to caller's Solana keypair file.
    pub caller_sol_keypair: Option<String>,
    /// Solana HTLC program ID.
    pub program_id: Option<String>,
    /// Token ID of the commitment to cancel.
    pub token_id: u64,
}
