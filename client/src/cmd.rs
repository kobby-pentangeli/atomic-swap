use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "crosschain-secret-mint")]
#[command(about = "A cross-chain atomic swap: Bitcoin for NFT")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run the complete swap flow
    AtomicSwap {
        /// Bitcoin RPC URL
        #[arg(long, default_value = "http://localhost:18443")]
        btc_rpc: String,
        /// Bitcoin RPC username
        #[arg(long, default_value = "user")]
        btc_user: String,
        /// Bitcoin RPC password
        #[arg(long, default_value = "password")]
        btc_pass: String,
        /// Bitcoin network
        #[arg(long, default_value = "regtest")]
        btc_network: String,
        /// Buyer's Bitcoin private key (WIF format)
        #[arg(long)]
        buyer_btc_key: String,
        /// Seller's Bitcoin public key (hex)
        #[arg(long)]
        seller_btc_pubkey: String,
        /// Ethereum RPC URL
        #[arg(long, default_value = "http://localhost:8545")]
        eth_rpc: String,
        /// Buyer's Ethereum private key (hex)
        #[arg(long)]
        buyer_eth_key: String,
        /// NFT contract address
        #[arg(long)]
        nft_contract: String,
        /// Amount of Bitcoin to lock (in satoshis)
        #[arg(long, default_value = "1000000")] // 0.01 BTC
        btc_amount: u64,
        /// NFT price in wei
        #[arg(long, default_value = "1000000000000000000")] // 1 ETH
        nft_price: u64,
        /// Token ID to mint
        #[arg(long, default_value = "1")]
        token_id: u64,
        /// NFT metadata URI
        #[arg(long, default_value = "https://example.com/nft/1.json")]
        metadata_uri: String,
        /// HTLC timeout in blocks
        #[arg(long, default_value = "144")] // ~24 hours on Bitcoin
        timeout: u16,
    },
    /// Seller workflow - commit NFT after seeing Bitcoin lock
    CommitForMint {
        /// Ethereum RPC URL
        #[arg(long, default_value = "http://localhost:8545")]
        eth_rpc: String,
        /// Seller's Ethereum private key (hex)
        #[arg(long)]
        seller_eth_key: String,
        /// NFT contract address
        #[arg(long)]
        nft_contract: String,
        /// Secret hash from buyer's Bitcoin lock (hex)
        #[arg(long)]
        secret_hash: String,
        /// Token ID to commit for minting
        #[arg(long)]
        token_id: u64,
        /// NFT price in wei
        #[arg(long)]
        nft_price: u64,
        /// Buyer's Ethereum address (optional, for restricted minting)
        #[arg(long)]
        buyer_address: Option<String>,
        /// NFT metadata URI
        #[arg(long)]
        metadata_uri: String,
    },
    /// Claim Bitcoin using revealed secret
    ClaimBtc {
        /// Bitcoin RPC URL
        #[arg(long, default_value = "http://localhost:18443")]
        btc_rpc: String,
        /// Bitcoin RPC username
        #[arg(long, default_value = "user")]
        btc_user: String,
        /// Bitcoin RPC password
        #[arg(long, default_value = "password")]
        btc_pass: String,
        /// Bitcoin network
        #[arg(long, default_value = "regtest")]
        btc_network: String,
        /// Seller's Bitcoin private key (WIF format)
        #[arg(long)]
        seller_btc_key: String,
        /// Buyer's Bitcoin public key (hex)
        #[arg(long)]
        buyer_btc_pubkey: String,
        /// Secret revealed from Ethereum (hex)
        #[arg(long)]
        secret: String,
        /// Secret hash (hex, for verification)
        #[arg(long)]
        secret_hash: String,
        /// Bitcoin transaction ID of the lock
        #[arg(long)]
        lock_txid: String,
        /// Output index in the lock transaction
        #[arg(long, default_value = "0")]
        lock_vout: u32,
        /// HTLC timeout in blocks
        #[arg(long, default_value = "144")]
        timeout: u16,
        /// Destination address (optional)
        #[arg(long)]
        destination: Option<String>,
    },
    /// Monitor events and state
    Monitor {
        /// Bitcoin RPC URL
        #[arg(long, default_value = "http://localhost:18443")]
        btc_rpc: String,
        /// Bitcoin RPC username
        #[arg(long, default_value = "user")]
        btc_user: String,
        /// Bitcoin RPC password
        #[arg(long, default_value = "password")]
        btc_pass: String,
        /// Bitcoin network
        #[arg(long, default_value = "regtest")]
        btc_network: String,
        /// Ethereum RPC URL
        #[arg(long, default_value = "http://localhost:8545")]
        eth_rpc: String,
        /// Ethereum private key for monitoring
        #[arg(long)]
        eth_key: String,
        /// NFT contract address
        #[arg(long)]
        nft_contract: String,
    },
}
