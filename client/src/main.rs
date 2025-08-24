use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

pub mod btc;
pub mod eth;
pub mod execute;
pub mod sol;
pub mod types;

use types::{Chain, ClaimBtcArgs, CommitForMintArgs, LockBtcArgs, MintWithSecretArgs};

const DEFAULT_BTC_RPC_URL: &str = "http://localhost:18443";
const DEFAULT_ETH_RPC_URL: &str = "http://localhost:8545";
const DEFAULT_SOL_RPC_URL: &str = "http://localhost:8899";
const DEFAULT_SOL_WS_URL: &str = "ws://localhost:8900";

#[derive(Parser)]
#[command(name = "crosschain-secret-mint")]
#[command(about = "A cross-chain atomic swap: Bitcoin for NFT")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// TODO (kobby-pentangeli): specify these params in `.env` or JSON
#[derive(Subcommand)]
enum Commands {
    /// Buyer locks Bitcoin
    LockBtc {
        /// Bitcoin RPC URL
        #[arg(long, default_value = DEFAULT_BTC_RPC_URL)]
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
        /// Buyer's Bitcoin private key
        #[arg(long)]
        buyer_btc_key: String,
        /// Seller's Bitcoin public key
        #[arg(long)]
        seller_btc_pubkey: String,
        /// Amount of Bitcoin to lock (in satoshis)
        #[arg(long, default_value = "100000")] // 0.001 BTC
        btc_amount: u64,
        /// HTLC timeout in blocks
        #[arg(long, default_value = "144")] // ~24 hours on Bitcoin
        timeout: u32,
    },

    /// Seller commits NFT after buyer locks Bitcoin
    CommitForMint {
        /// Target blockchain for NFT minting (eth/sol)
        #[arg(long)]
        chain: String,

        // Ethereum-specific options
        /// Ethereum RPC URL (required if chain=eth)
        #[arg(long, default_value = DEFAULT_ETH_RPC_URL)]
        eth_rpc: Option<String>,
        /// Seller's Ethereum private key (required if chain=eth)
        #[arg(long)]
        seller_eth_key: Option<String>,
        /// NFT contract address (required if chain=eth)
        #[arg(long)]
        nft_contract: Option<String>,
        /// Buyer's Ethereum address (optional, for restricted minting)
        #[arg(long)]
        buyer_address: Option<String>,

        // Solana-specific options
        /// Solana RPC URL (required if chain=sol)
        #[arg(long, default_value = DEFAULT_SOL_RPC_URL)]
        sol_rpc: Option<String>,
        /// Solana WebSocket URL (required if chain=sol)
        #[arg(long, default_value = DEFAULT_SOL_WS_URL)]
        sol_ws: Option<String>,
        /// Seller's Solana keypair file path (required if chain=sol)
        #[arg(long)]
        seller_sol_keypair: Option<String>,
        /// Solana HTLC program ID (required if chain=sol)
        #[arg(long)]
        program_id: Option<String>,
        /// NFT name (required if chain=sol)
        #[arg(long)]
        name: Option<String>,
        /// NFT symbol (required if chain=sol)
        #[arg(long)]
        symbol: Option<String>,

        // Common fields
        /// Secret hash from buyer's Bitcoin lock (hex)
        #[arg(long)]
        secret_hash: String,
        /// Token ID to commit for minting
        #[arg(long)]
        token_id: u64,
        /// NFT price (wei for Ethereum, lamports for Solana)
        #[arg(long)]
        nft_price: u64,
        /// NFT metadata URI
        #[arg(long)]
        metadata_uri: String,
    },

    /// Buyer reveals shared secret to mint NFT
    MintWithSecret {
        /// Target blockchain for NFT minting (eth/sol)
        #[arg(long)]
        chain: String,

        // Ethereum-specific options
        /// Ethereum RPC URL (required if chain=eth)
        #[arg(long, default_value = DEFAULT_ETH_RPC_URL)]
        eth_rpc: Option<String>,
        /// Buyer's Ethereum private key (hex, required if chain=eth)
        #[arg(long)]
        buyer_eth_key: Option<String>,
        /// NFT contract address (required if chain=eth)
        #[arg(long)]
        nft_contract: Option<String>,

        // Solana-specific options
        /// Solana RPC URL (required if chain=sol)
        #[arg(long, default_value = DEFAULT_SOL_RPC_URL)]
        sol_rpc: Option<String>,
        /// Solana WebSocket URL (required if chain=sol)
        #[arg(long, default_value = DEFAULT_SOL_WS_URL)]
        sol_ws: Option<String>,
        /// Buyer's Solana keypair file path (required if chain=sol)
        #[arg(long)]
        buyer_sol_keypair: Option<String>,
        /// Solana HTLC program ID (required if chain=sol)
        #[arg(long)]
        program_id: Option<String>,

        // Common fields
        /// Shared secret (hex)
        #[arg(long)]
        secret: String,
        /// Token ID to mint
        #[arg(long)]
        token_id: u64,
    },

    /// Seller claims Bitcoin using revealed secret
    ClaimBtc {
        /// Bitcoin RPC URL
        #[arg(long, default_value = DEFAULT_BTC_RPC_URL)]
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
        timeout: u32,
        /// Destination address (optional)
        #[arg(long)]
        destination: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::LockBtc {
            btc_rpc,
            btc_user,
            btc_pass,
            btc_network,
            buyer_btc_key,
            seller_btc_pubkey,
            btc_amount,
            timeout,
        } => {
            let args = LockBtcArgs {
                btc_rpc,
                btc_user,
                btc_pass,
                btc_network: btc::utils::parse_network(&btc_network)?,
                buyer_btc_key,
                seller_btc_pubkey,
                btc_amount,
                timeout,
            };

            execute::lock_bitcoin(args).await
        }

        Commands::CommitForMint {
            chain,
            eth_rpc,
            seller_eth_key,
            nft_contract,
            buyer_address,
            sol_rpc,
            sol_ws,
            seller_sol_keypair,
            program_id,
            name,
            symbol,
            secret_hash,
            token_id,
            nft_price,
            metadata_uri,
        } => {
            let chain = chain
                .parse::<Chain>()
                .context("Invalid chain specification")?;

            let args = CommitForMintArgs {
                chain: chain.clone(),
                // Ethereum fields
                eth_rpc,
                seller_eth_key,
                nft_contract: nft_contract
                    .map(|s| s.parse())
                    .transpose()
                    .context("Invalid NFT contract address")?,
                buyer_address: buyer_address
                    .map(|s| s.parse())
                    .transpose()
                    .context("Invalid buyer address")?,
                // Solana fields
                sol_rpc,
                sol_ws,
                seller_sol_keypair,
                program_id,
                name,
                symbol,
                // Common fields
                secret_hash: decode_hex_hash(&secret_hash, "secret hash")?,
                token_id,
                nft_price,
                metadata_uri,
            };

            match chain {
                Chain::Ethereum => {
                    if args.eth_rpc.is_none()
                        || args.seller_eth_key.is_none()
                        || args.nft_contract.is_none()
                    {
                        return Err(anyhow::anyhow!(
                            "For Ethereum: --eth-rpc, --seller-eth-key, and --nft-contract are required"
                        ));
                    }
                }
                Chain::Solana => {
                    if args.sol_rpc.is_none()
                        || args.sol_ws.is_none()
                        || args.seller_sol_keypair.is_none()
                        || args.program_id.is_none()
                        || args.name.is_none()
                        || args.symbol.is_none()
                    {
                        return Err(anyhow::anyhow!(
                            "For Solana: --sol-rpc, --sol-ws, --seller-sol-keypair, --program-id, --name, and --symbol are required"
                        ));
                    }
                }
            }

            execute::commit_for_mint(args).await
        }

        Commands::MintWithSecret {
            chain,
            eth_rpc,
            buyer_eth_key,
            nft_contract,
            sol_rpc,
            sol_ws,
            buyer_sol_keypair,
            program_id,
            secret,
            token_id,
        } => {
            let chain = chain
                .parse::<Chain>()
                .context("Invalid chain specification")?;

            let args = MintWithSecretArgs {
                chain: chain.clone(),
                // Ethereum fields
                eth_rpc,
                buyer_eth_key,
                nft_contract: nft_contract
                    .map(|s| s.parse())
                    .transpose()
                    .context("Invalid NFT contract address")?,
                // Solana fields
                sol_rpc,
                sol_ws,
                buyer_sol_keypair,
                program_id,
                // Common fields
                secret: decode_hex_secret(&secret)?,
                token_id,
            };

            match chain {
                Chain::Ethereum => {
                    if args.eth_rpc.is_none()
                        || args.buyer_eth_key.is_none()
                        || args.nft_contract.is_none()
                    {
                        return Err(anyhow::anyhow!(
                            "For Ethereum: --eth-rpc, --buyer-eth-key, and --nft-contract are required"
                        ));
                    }
                }
                Chain::Solana => {
                    if args.sol_rpc.is_none()
                        || args.sol_ws.is_none()
                        || args.buyer_sol_keypair.is_none()
                        || args.program_id.is_none()
                    {
                        return Err(anyhow::anyhow!(
                            "For Solana: --sol-rpc, --sol-ws, --buyer-sol-keypair, and --program-id are required"
                        ));
                    }
                }
            }

            execute::mint_with_secret(args).await
        }

        Commands::ClaimBtc {
            btc_rpc,
            btc_user,
            btc_pass,
            btc_network,
            seller_btc_key,
            buyer_btc_pubkey,
            secret,
            secret_hash,
            lock_txid,
            lock_vout,
            timeout,
            destination,
        } => {
            let network = btc::utils::parse_network(&btc_network)?;
            let args = ClaimBtcArgs {
                btc_rpc,
                btc_user,
                btc_pass,
                btc_network: network,
                seller_btc_key,
                buyer_btc_pubkey,
                secret: decode_hex_secret(&secret)?,
                secret_hash: decode_hex_hash(&secret_hash, "secret hash")?,
                lock_txid: lock_txid.parse().context("Invalid lock transaction ID")?,
                lock_vout,
                timeout,
                destination: destination
                    .map(|s| btc::utils::parse_btc_address(&s, network))
                    .transpose()?,
            };

            execute::claim_bitcoin(args).await
        }
    }
}

fn decode_hex_hash(hex_str: &str, field_name: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(hex_str).with_context(|| format!("Invalid hex encoding for {field_name}"))?;

    bytes.clone().try_into().map_err(|_| {
        anyhow::anyhow!(
            "Invalid {field_name} length: expected 32 bytes, got {}",
            bytes.len()
        )
    })
}

fn decode_hex_secret(hex_str: &str) -> Result<[u8; 32]> {
    decode_hex_hash(hex_str, "secret")
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use btc::utils::parse_network;

    use super::*;

    #[test]
    fn test_parse_network() {
        assert!(matches!(
            parse_network("mainnet").unwrap(),
            Network::Bitcoin
        ));
        assert!(matches!(
            parse_network("testnet").unwrap(),
            Network::Testnet
        ));
        assert!(matches!(parse_network("signet").unwrap(), Network::Signet));
        assert!(matches!(
            parse_network("regtest").unwrap(),
            Network::Regtest
        ));
        assert!(parse_network("invalid").is_err());
    }

    #[test]
    fn test_decode_hex_hash() {
        let valid_hash = "a".repeat(64); // 32 bytes in hex
        assert!(decode_hex_hash(&valid_hash, "test").is_ok());

        let invalid_length = "a".repeat(30); // 15 bytes in hex
        assert!(decode_hex_hash(&invalid_length, "test").is_err());

        let invalid_hex = "zz".repeat(32);
        assert!(decode_hex_hash(&invalid_hex, "test").is_err());
    }
}
