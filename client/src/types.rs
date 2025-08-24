use bitcoin::{Address as BtcAddress, Network, Txid};
use ethers::core::types::{Address as EthAddress, U256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
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

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct CommitmentInfo {
    pub secret_hash: [u8; 32],
    pub seller: EthAddress,
    pub buyer: EthAddress,
    pub price: U256,
    pub commit_time: U256,
    pub is_active: bool,
    pub token_uri: String,
}

#[derive(Debug)]
pub struct LockBtcArgs {
    pub btc_rpc: String,
    pub btc_user: String,
    pub btc_pass: String,
    pub btc_network: Network,
    pub buyer_btc_key: String,
    pub seller_btc_pubkey: String,
    pub btc_amount: u64,
    pub timeout: u32,
}

#[derive(Debug, Clone)]
pub struct CommitForMintArgs {
    pub chain: Chain,
    // Ethereum fields
    pub eth_rpc: Option<String>,
    pub seller_eth_key: Option<String>,
    pub nft_contract: Option<EthAddress>,
    pub buyer_address: Option<EthAddress>,
    // Solana fields
    pub sol_rpc: Option<String>,
    pub sol_ws: Option<String>,
    pub seller_sol_keypair: Option<String>,
    pub program_id: Option<String>,
    pub name: Option<String>,
    pub symbol: Option<String>,
    // Common fields
    pub secret_hash: [u8; 32],
    pub token_id: u64,
    pub nft_price: u64,
    pub metadata_uri: String,
}

#[derive(Debug, Clone)]
pub struct MintWithSecretArgs {
    pub chain: Chain,
    // Ethereum fields
    pub eth_rpc: Option<String>,
    pub buyer_eth_key: Option<String>,
    pub nft_contract: Option<EthAddress>,
    // Solana fields
    pub sol_rpc: Option<String>,
    pub sol_ws: Option<String>,
    pub buyer_sol_keypair: Option<String>,
    pub program_id: Option<String>,
    // Common fields
    pub secret: [u8; 32],
    pub token_id: u64,
}

#[derive(Debug)]
pub struct ClaimBtcArgs {
    pub btc_rpc: String,
    pub btc_user: String,
    pub btc_pass: String,
    pub btc_network: Network,
    pub seller_btc_key: String,
    pub buyer_btc_pubkey: String,
    pub secret: [u8; 32],
    pub secret_hash: [u8; 32],
    pub lock_txid: Txid,
    pub lock_vout: u32,
    pub timeout: u32,
    pub destination: Option<BtcAddress>,
}
