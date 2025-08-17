use ethers::core::types::{Address as EthAddress, H256, U256};
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

impl SwapState {
    pub fn new(secret_hash: [u8; 32]) -> Self {
        let now = chrono::Utc::now();
        Self {
            swap_id: uuid::Uuid::new_v4().to_string(),
            secret_hash,
            btc_locked: false,
            btc_txid: None,
            eth_committed: false,
            eth_commit_tx: None,
            nft_minted: false,
            nft_mint_tx: None,
            btc_claimed: false,
            btc_claim_tx: None,
            revealed_secret: None,
            status: SwapStatus::Created,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn update_status(&mut self, new_status: SwapStatus) {
        self.status = new_status;
        self.updated_at = chrono::Utc::now();
    }

    pub fn complete(&self) -> bool {
        matches!(self.status, SwapStatus::BtcClaimed)
    }

    pub fn failed(&self) -> bool {
        matches!(self.status, SwapStatus::Failed(_) | SwapStatus::Expired)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapConfig {
    pub btc_network: bitcoin::Network,
    pub btc_amount: u64,
    pub nft_price: u64,
    pub token_id: u64,
    pub metadata_uri: String,
    pub timeout: u16,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinTx {
    pub txid: bitcoin::Txid,
    pub confirmations: u32,
    pub block_hash: Option<bitcoin::BlockHash>,
    pub block_time: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EthereumTx {
    pub hash: H256,
    pub block_number: Option<U256>,
    pub block_hash: Option<H256>,
    pub tx_index: Option<U256>,
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
