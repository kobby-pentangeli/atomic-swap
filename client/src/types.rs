use bitcoin::{Address as BtcAddress, Network, OutPoint, TxOut, Txid};
use ethers::core::types::{Address as EthAddress, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct UtxoInfo {
    pub outpoint: OutPoint,
    pub tx_out: TxOut,
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

#[derive(Debug)]
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

#[derive(Debug)]
pub struct MintWithSecretConfig {
    pub eth_rpc: String,
    pub buyer_eth_key: String,
    pub nft_contract: EthAddress,
    pub secret: [u8; 32],
    pub token_id: u64,
}

#[derive(Debug)]
pub struct ClaimBtcConfig {
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
