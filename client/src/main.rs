//! Cross-chain atomic swap CLI.
//!
//! Orchestrates the full
//! swap lifecycle including locking funds, committing NFTs, revealing secrets,
//! and claiming assets.
//!
//! # Commands
//!
//! - `lock-btc`: Lock Bitcoin in an HTLC (buyer, step 1)
//! - `commit-for-mint`: Commit NFT for minting (seller, step 2)
//! - `mint-with-secret`: Mint NFT by revealing secret (buyer, step 3)
//! - `claim-btc`: Claim Bitcoin using revealed secret (seller, step 4)
//! - `cancel-commit`: Cancel an expired or unwanted commitment

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};

pub mod btc;
pub mod config;
pub mod eth;
pub mod execute;
pub mod sol;
pub mod types;
pub mod utils;

use types::{
    CancelCommitArgs, Chain, ClaimBtcArgs, CommitForMintArgs, LockBtcArgs, MintWithSecretArgs,
    RefundBtcArgs,
};

const DEFAULT_BTC_RPC_URL: &str = "http://localhost:18443";
const DEFAULT_ETH_RPC_URL: &str = "http://localhost:8545";
const DEFAULT_SOL_RPC_URL: &str = "http://localhost:8899";
const DEFAULT_SOL_WS_URL: &str = "ws://localhost:8900";

#[derive(Parser)]
#[command(name = "atomic-swap")]
#[command(about = "A cross-chain atomic swap: Bitcoin for NFT")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

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
        /// File path to securely write the generated secret (optional)
        #[arg(long)]
        secret_output: Option<PathBuf>,
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
        /// Shared secret (hex, mutually exclusive with --secret-file)
        #[arg(long, conflicts_with = "secret_file")]
        secret: Option<String>,
        /// File containing the secret (mutually exclusive with --secret)
        #[arg(long, conflicts_with = "secret")]
        secret_file: Option<PathBuf>,
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
        /// Secret revealed from Ethereum (hex, mutually exclusive with --secret-file)
        #[arg(long, conflicts_with = "secret_file")]
        secret: Option<String>,
        /// File containing the secret (mutually exclusive with --secret)
        #[arg(long, conflicts_with = "secret")]
        secret_file: Option<PathBuf>,
        /// Secret hash (hex, for verification; optional if using --secret-file)
        #[arg(long)]
        secret_hash: Option<String>,
        /// Bitcoin transaction ID of the lock (optional if using --secret-file)
        #[arg(long)]
        lock_txid: Option<String>,
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

    /// Cancel an NFT commitment (seller only, or anyone after timeout)
    CancelCommit {
        /// Target blockchain (eth/sol)
        #[arg(long)]
        chain: String,

        // Ethereum-specific options
        /// Ethereum RPC URL (required if chain=eth)
        #[arg(long, default_value = DEFAULT_ETH_RPC_URL)]
        eth_rpc: Option<String>,
        /// Caller's Ethereum private key (required if chain=eth)
        #[arg(long)]
        caller_eth_key: Option<String>,
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
        /// Caller's Solana keypair file path (required if chain=sol)
        #[arg(long)]
        caller_sol_keypair: Option<String>,
        /// Solana HTLC program ID (required if chain=sol)
        #[arg(long)]
        program_id: Option<String>,

        // Common fields
        /// Token ID of the commitment to cancel
        #[arg(long)]
        token_id: u64,
    },

    /// Buyer withdraws Bitcoin from an HTLC after timeout expiry
    RefundBtc {
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
        /// File containing the generated secret from the lock transaction
        #[arg(long)]
        secret_file: PathBuf,
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
            secret_output,
        } => {
            let args = LockBtcArgs {
                btc_rpc,
                btc_user,
                btc_pass,
                btc_network: utils::parse_btc_network(&btc_network)?,
                buyer_btc_key,
                seller_btc_pubkey,
                btc_amount,
                timeout,
                secret_output_file: secret_output,
            };

            execute::lock_bitcoin(args)
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
                secret_hash: utils::decode_hex_hash(&secret_hash, "secret hash")?,
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
                        return Err(anyhow!(
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
                        return Err(anyhow!(
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
            secret_file,
            token_id,
        } => {
            let chain = chain
                .parse::<Chain>()
                .context("Invalid chain specification")?;

            let (secret_bytes, _, _) = utils::resolve_secrets(secret, secret_file)?;

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
                secret: secret_bytes,
                token_id,
            };

            match chain {
                Chain::Ethereum => {
                    if args.eth_rpc.is_none()
                        || args.buyer_eth_key.is_none()
                        || args.nft_contract.is_none()
                    {
                        return Err(anyhow!(
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
                        return Err(anyhow!(
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
            secret_file,
            secret_hash,
            lock_txid,
            lock_vout,
            timeout,
            destination,
        } => {
            let network = utils::parse_btc_network(&btc_network)?;

            // Resolve secret from either --secret or --secret-file
            let (secret_bytes, file_secret_hash, file_lock_txid) =
                utils::resolve_secrets(secret, secret_file.clone())?;

            let final_secret_hash = secret_hash
                .map(|h| utils::decode_hex_hash(&h, "secret hash"))
                .transpose()?
                .or(file_secret_hash)
                .ok_or_else(|| {
                    anyhow!("Secret hash required (use --secret-hash or provide via --secret-file)")
                })?;

            let final_lock_txid = lock_txid
                .map(|s| s.parse())
                .transpose()
                .context("Invalid lock transaction ID")?
                .or(file_lock_txid)
                .ok_or_else(|| {
                    anyhow!("Lock txid required (use --lock-txid or provide via --secret-file)")
                })?;

            let args = ClaimBtcArgs {
                btc_rpc,
                btc_user,
                btc_pass,
                btc_network: network,
                seller_btc_key,
                buyer_btc_pubkey,
                secret: secret_bytes,
                secret_hash: final_secret_hash,
                lock_txid: final_lock_txid,
                lock_vout,
                timeout,
                destination: destination
                    .map(|s| utils::parse_btc_address(&s, network))
                    .transpose()?,
            };

            execute::claim_bitcoin(args)
        }

        Commands::CancelCommit {
            chain,
            eth_rpc,
            caller_eth_key,
            nft_contract,
            sol_rpc,
            sol_ws,
            caller_sol_keypair,
            program_id,
            token_id,
        } => {
            let chain = chain
                .parse::<Chain>()
                .context("Invalid chain specification")?;

            let args = CancelCommitArgs {
                chain: chain.clone(),
                // Ethereum fields
                eth_rpc,
                caller_eth_key,
                nft_contract: nft_contract
                    .map(|s| s.parse())
                    .transpose()
                    .context("Invalid NFT contract address")?,
                // Solana fields
                sol_rpc,
                sol_ws,
                caller_sol_keypair,
                program_id,
                // Common fields
                token_id,
            };

            match chain {
                Chain::Ethereum => {
                    if args.eth_rpc.is_none()
                        || args.caller_eth_key.is_none()
                        || args.nft_contract.is_none()
                    {
                        return Err(anyhow!(
                            "For Ethereum: --eth-rpc, --caller-eth-key, and --nft-contract are required"
                        ));
                    }
                }
                Chain::Solana => {
                    if args.sol_rpc.is_none()
                        || args.sol_ws.is_none()
                        || args.caller_sol_keypair.is_none()
                        || args.program_id.is_none()
                    {
                        return Err(anyhow!(
                            "For Solana: --sol-rpc, --sol-ws, --caller-sol-keypair, and --program-id are required"
                        ));
                    }
                }
            }

            execute::cancel_commitment(args).await
        }

        Commands::RefundBtc {
            btc_rpc,
            btc_user,
            btc_pass,
            btc_network,
            buyer_btc_key,
            seller_btc_pubkey,
            secret_file,
            lock_vout,
            timeout,
            destination,
        } => {
            let network = utils::parse_btc_network(&btc_network)?;

            let args = RefundBtcArgs {
                btc_rpc,
                btc_user,
                btc_pass,
                btc_network: network,
                buyer_btc_key,
                seller_btc_pubkey,
                secret_file,
                lock_vout,
                timeout,
                destination: destination
                    .map(|s| utils::parse_btc_address(&s, network))
                    .transpose()?,
            };

            execute::refund_bitcoin(args)
        }
    }
}
