use bitcoin::{Address as BtcAddress, Network};
use ethers::core::types::{Address as EthAddress, H256, U64, U256};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SwapState {
    pub swap_id: String,
    pub secret_hash: [u8; 32],
    pub btc_locked: bool,
    pub btc_txid: Option<String>,
    pub eth_committed: bool,
    pub eth_commit_tx: Option<String>,
    pub nft_minted: bool,
    pub nft_mint_tx: Option<String>,
    pub btc_claimed: bool,
    pub btc_claim_tx: Option<String>,
    pub revealed_secret: Option<[u8; 32]>,
    pub status: SwapStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum SwapStatus {
    Created,
    /// Step 1: Bitcoin locked by buyer
    BtcLocked,
    /// Step 2: NFT committed by seller
    EthCommitted,
    /// Step 3: NFT minted by buyer (secret revealed)
    NFTMinted,
    /// Step 4: Bitcoin claimed by seller
    BtcClaimed,
    Expired,
    Failed(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapConfig {
    pub btc_network: bitcoin::Network,
    pub btc_amount: u64,
    pub nft_price: u64,
    pub token_id: u64,
    pub metadata_uri: String,
    pub timeout: u32,
    pub buyer: Option<EthAddress>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum SwapEvent {
    BtcLocked {
        txid: String,
        amount: u64,
        htlc_address: String,
    },
    EthCommitted {
        tx_hash: String,
        token_id: u64,
        secret_hash: [u8; 32],
    },
    SecretRevealed {
        tx_hash: String,
        secret: [u8; 32],
        token_id: u64,
    },
    NFTMinted {
        tx_hash: String,
        token_id: u64,
        owner: EthAddress,
    },
    BtcClaimed {
        txid: String,
        amount: u64,
    },
    CommitCancelled {
        token_id: u64,
        secret: [u8; 32],
        seller: EthAddress,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinTx {
    pub txid: bitcoin::Txid,
    pub confirmations: u32,
    pub block_hash: Option<bitcoin::BlockHash>,
    pub block_time: Option<usize>,
}

impl BitcoinTx {
    pub fn block_height(&self) -> Option<u64> {
        if self.confirmations > 0 {
            // TODO (kobby-pentangeli): This would need the current height to be accurate
            // For now, we return a placeholder that indicates confirmation
            Some(800_000) // Placeholder mainnet height
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct UtxoInfo {
    /// ID of the output.
    pub outpoint: bitcoin::OutPoint,
    /// Contents of the output.
    pub tx_out: bitcoin::TxOut,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EthereumTx {
    pub hash: H256,
    pub block_number: Option<U64>,
    pub block_hash: Option<H256>,
    pub tx_index: Option<U64>,
    pub confirmations: Option<u64>,
    pub gas_used: Option<U256>,
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

pub struct AtomicSwapConfig {
    pub btc_rpc: String,
    pub btc_user: String,
    pub btc_pass: String,
    pub btc_network: Network,
    pub buyer_btc_key: String,
    pub seller_btc_pubkey: String,
    pub eth_rpc: String,
    pub buyer_eth_key: String,
    pub nft_contract: EthAddress,
    pub btc_amount: u64,
    pub nft_price: u64,
    pub token_id: u64,
    pub metadata_uri: String,
    pub timeout: u32,
}

pub struct CommitForMintConfig {
    pub eth_rpc: String,
    pub seller_eth_key: String,
    pub nft_contract: EthAddress,
    pub secret_hash: [u8; 32],
    pub token_id: u64,
    pub nft_price: u64,
    pub buyer_address: Option<EthAddress>,
    pub metadata_uri: String,
}

pub struct ClaimBtcConfig {
    pub btc_rpc: String,
    pub btc_user: String,
    pub btc_pass: String,
    pub btc_network: Network,
    pub seller_btc_key: String,
    pub buyer_btc_pubkey: String,
    pub secret: [u8; 32],
    pub secret_hash: [u8; 32],
    pub lock_txid: bitcoin::Txid,
    pub lock_vout: u32,
    pub timeout: u32,
    pub destination: Option<BtcAddress>,
}

pub struct MonitorConfig {
    pub btc_rpc: String,
    pub btc_user: String,
    pub btc_pass: String,
    pub btc_network: Network,
    pub eth_rpc: String,
    pub eth_key: String,
    pub nft_contract: EthAddress,
}
