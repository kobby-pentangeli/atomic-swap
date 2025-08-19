use bitcoin::{Address as BtcAddress, Network};
use ethers::core::types::{Address as EthAddress, H256, U64, U256};
use serde::{Deserialize, Serialize};

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

pub struct LockBtcConfig {
    pub btc_rpc: String,
    pub btc_user: String,
    pub btc_pass: String,
    pub btc_network: Network,
    pub buyer_btc_key: String,
    pub seller_btc_pubkey: String,
    pub btc_amount: u64,
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

pub struct MintWithSecretConfig {
    pub eth_rpc: String,
    pub buyer_eth_key: String,
    pub nft_contract: EthAddress,
    pub secret: [u8; 32],
    pub token_id: u64,
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

pub struct MonitorEventsConfig {
    pub btc_rpc: String,
    pub btc_user: String,
    pub btc_pass: String,
    pub btc_network: Network,
    pub eth_rpc: String,
    pub eth_key: String,
    pub nft_contract: EthAddress,
}
