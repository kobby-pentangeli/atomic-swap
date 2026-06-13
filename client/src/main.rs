//! Cross-chain atomic swap CLI.
//!
//! Orchestrates the full swap lifecycle including locking funds, committing NFTs,
//! revealing secrets, and claiming assets.
//!
//! # Commands
//!
//! - `lock-btc`: Lock Bitcoin in an HTLC (buyer, step 1)
//! - `commit-for-mint`: Commit NFT for minting (seller, step 2)
//! - `mint-with-secret`: Mint NFT by revealing secret (buyer, step 3)
//! - `claim-btc`: Claim Bitcoin using revealed secret (seller, step 4)
//! - `cancel-commit`: Cancel an expired or unwanted commitment (seller)
//! - `refund-btc`: Reclaim Bitcoin after timeout expiry (buyer)
//!
//! # Configuration
//!
//! Arguments can be provided via command-line flags or environment variables
//! (loaded from `.env` file). Use `--no-env` to disable `.env` loading.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::{ArgAction, Parser, Subcommand};

pub mod btc;
pub mod eth;
pub mod execute;
pub mod sol;
pub mod types;
pub mod utils;

use types::{
    CancelCommitArgs, Chain, ClaimBtcArgs, CommitForMintArgs, EthCancelArgs, EthCommitArgs,
    EthMintArgs, LockBtcArgs, MintWithSecretArgs, Printable, RefundBtcArgs, ResultFmt,
    SolCancelArgs, SolCommitArgs, SolMintArgs,
};

const DEFAULT_BTC_RPC_URL: &str = "http://localhost:18443";
const DEFAULT_ETH_RPC_URL: &str = "http://localhost:8545";
const DEFAULT_SOL_RPC_URL: &str = "http://localhost:8899";
const DEFAULT_SOL_WS_URL: &str = "ws://localhost:8900";

#[derive(Parser)]
#[command(name = "atomic-swap")]
#[command(about = "A cross-chain atomic swap: Bitcoin for NFT")]
#[command(version)]
struct Cli {
    /// Disable loading configuration from .env file
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    no_env: bool,

    /// Output format (human, json)
    #[arg(short, long, global = true, default_value = "human")]
    output: ResultFmt,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Buyer locks Bitcoin in an HTLC
    LockBtc {
        /// Bitcoin RPC URL
        #[arg(long, env = "BTC_RPC_URL", default_value = DEFAULT_BTC_RPC_URL)]
        btc_rpc: String,
        /// Bitcoin RPC username
        #[arg(long, env = "BTC_RPC_USER", default_value = "user")]
        btc_user: String,
        /// Bitcoin RPC password
        #[arg(long, env = "BTC_RPC_PASSWORD", default_value = "password")]
        btc_pass: String,
        /// Bitcoin network (mainnet, testnet, signet, regtest)
        #[arg(long, env = "BTC_NETWORK", default_value = "regtest")]
        btc_network: String,
        /// Buyer's Bitcoin private key (WIF or hex)
        #[arg(long, env = "BUYER_BTC_PRIVKEY")]
        buyer_btc_key: String,
        /// Seller's Bitcoin public key (hex)
        #[arg(long, env = "SELLER_BTC_PUBKEY")]
        seller_btc_pubkey: String,
        /// Amount of Bitcoin to lock (in satoshis)
        #[arg(long, env = "BTC_AMOUNT", default_value = "100000")]
        btc_amount: u64,
        /// HTLC timeout as a relative window in blocks from the current chain tip
        #[arg(long, env = "HTLC_TIMEOUT", default_value = "144")]
        timeout: u32,
        /// File path to securely write the generated secret
        #[arg(long)]
        secret_output: Option<PathBuf>,
    },

    /// Seller commits NFT after buyer locks Bitcoin
    CommitForMint {
        /// Target blockchain for NFT minting (eth/sol)
        #[arg(long)]
        chain: String,

        // Ethereum-specific options
        /// Ethereum RPC URL
        #[arg(long, env = "ETH_RPC_URL", default_value = DEFAULT_ETH_RPC_URL)]
        eth_rpc: Option<String>,
        /// Seller's Ethereum private key (hex with 0x prefix)
        #[arg(long, env = "SELLER_ETH_PRIVKEY")]
        seller_eth_key: Option<String>,
        /// NFT contract address
        #[arg(long, env = "NFT_CONTRACT_ADDRESS")]
        nft_contract: Option<String>,
        /// Buyer's Ethereum address (for restricted minting)
        #[arg(long)]
        buyer_address: Option<String>,

        // Solana-specific options
        /// Solana RPC URL
        #[arg(long, env = "SOL_RPC_URL", default_value = DEFAULT_SOL_RPC_URL)]
        sol_rpc: Option<String>,
        /// Solana WebSocket URL
        #[arg(long, env = "SOL_WS_URL", default_value = DEFAULT_SOL_WS_URL)]
        sol_ws: Option<String>,
        /// Seller's Solana keypair file path
        #[arg(long, env = "SELLER_SOL_KEYPAIR")]
        seller_sol_keypair: Option<String>,
        /// Solana HTLC program ID
        #[arg(long, env = "SOL_PROGRAM_ID")]
        program_id: Option<String>,
        /// NFT name
        #[arg(long, env = "NFT_NAME")]
        name: Option<String>,
        /// NFT symbol
        #[arg(long, env = "NFT_SYMBOL")]
        symbol: Option<String>,
        /// Authorized buyer's Solana pubkey (base58, for restricted minting)
        #[arg(long)]
        sol_buyer: Option<String>,

        // Common fields
        /// Secret hash from buyer's Bitcoin lock (hex)
        #[arg(long)]
        secret_hash: String,
        /// Token ID to commit for minting
        #[arg(long, env = "TOKEN_ID")]
        token_id: Option<u64>,
        /// NFT price (wei for Ethereum, lamports for Solana)
        #[arg(long, env = "ETH_NFT_PRICE")]
        nft_price: Option<u64>,
        /// NFT metadata URI
        #[arg(long, env = "METADATA_URI")]
        metadata_uri: Option<String>,
    },

    /// Buyer reveals shared secret to mint NFT
    MintWithSecret {
        /// Target blockchain for NFT minting (eth/sol)
        #[arg(long)]
        chain: String,

        // Ethereum-specific options
        /// Ethereum RPC URL
        #[arg(long, env = "ETH_RPC_URL", default_value = DEFAULT_ETH_RPC_URL)]
        eth_rpc: Option<String>,
        /// Buyer's Ethereum private key (hex with 0x prefix)
        #[arg(long, env = "BUYER_ETH_PRIVKEY")]
        buyer_eth_key: Option<String>,
        /// NFT contract address
        #[arg(long, env = "NFT_CONTRACT_ADDRESS")]
        nft_contract: Option<String>,

        // Solana-specific options
        /// Solana RPC URL
        #[arg(long, env = "SOL_RPC_URL", default_value = DEFAULT_SOL_RPC_URL)]
        sol_rpc: Option<String>,
        /// Solana WebSocket URL
        #[arg(long, env = "SOL_WS_URL", default_value = DEFAULT_SOL_WS_URL)]
        sol_ws: Option<String>,
        /// Buyer's Solana keypair file path
        #[arg(long, env = "BUYER_SOL_KEYPAIR")]
        buyer_sol_keypair: Option<String>,
        /// Solana HTLC program ID
        #[arg(long, env = "SOL_PROGRAM_ID")]
        program_id: Option<String>,

        // Common fields
        /// Shared secret (hex, mutually exclusive with --secret-file)
        #[arg(long, conflicts_with = "secret_file")]
        secret: Option<String>,
        /// File containing the secret (mutually exclusive with --secret)
        #[arg(long, conflicts_with = "secret")]
        secret_file: Option<PathBuf>,
        /// Token ID to mint
        #[arg(long, env = "TOKEN_ID")]
        token_id: Option<u64>,
    },

    /// Seller claims Bitcoin using revealed secret
    ClaimBtc {
        /// Bitcoin RPC URL
        #[arg(long, env = "BTC_RPC_URL", default_value = DEFAULT_BTC_RPC_URL)]
        btc_rpc: String,
        /// Bitcoin RPC username
        #[arg(long, env = "BTC_RPC_USER", default_value = "user")]
        btc_user: String,
        /// Bitcoin RPC password
        #[arg(long, env = "BTC_RPC_PASSWORD", default_value = "password")]
        btc_pass: String,
        /// Bitcoin network (mainnet, testnet, signet, regtest)
        #[arg(long, env = "BTC_NETWORK", default_value = "regtest")]
        btc_network: String,
        /// Seller's Bitcoin private key (WIF format)
        #[arg(long, env = "SELLER_BTC_PRIVKEY")]
        seller_btc_key: String,
        /// Buyer's Bitcoin public key (hex)
        #[arg(long, env = "BUYER_BTC_PUBKEY")]
        buyer_btc_pubkey: String,
        /// Secret revealed from NFT chain (hex, mutually exclusive with --secret-file)
        #[arg(long, conflicts_with = "secret_file")]
        secret: Option<String>,
        /// File containing the secret (mutually exclusive with --secret)
        #[arg(long, conflicts_with = "secret")]
        secret_file: Option<PathBuf>,
        /// Secret hash (hex, for verification)
        #[arg(long)]
        secret_hash: Option<String>,
        /// Bitcoin transaction ID of the lock
        #[arg(long)]
        lock_txid: Option<String>,
        /// Output index in the lock transaction
        #[arg(long, default_value = "0")]
        lock_vout: u32,
        /// Absolute HTLC timeout height (read from --secret-file when provided)
        #[arg(long, env = "HTLC_TIMEOUT")]
        timeout: Option<u32>,
        /// Destination address for claimed Bitcoin
        #[arg(long)]
        destination: Option<String>,
    },

    /// Cancel an NFT commitment (seller only, or anyone after timeout)
    CancelCommit {
        /// Target blockchain (eth/sol)
        #[arg(long)]
        chain: String,

        // Ethereum-specific options
        /// Ethereum RPC URL
        #[arg(long, env = "ETH_RPC_URL", default_value = DEFAULT_ETH_RPC_URL)]
        eth_rpc: Option<String>,
        /// Caller's Ethereum private key (hex with 0x prefix)
        #[arg(long, env = "SELLER_ETH_PRIVKEY")]
        caller_eth_key: Option<String>,
        /// NFT contract address
        #[arg(long, env = "NFT_CONTRACT_ADDRESS")]
        nft_contract: Option<String>,

        // Solana-specific options
        /// Solana RPC URL
        #[arg(long, env = "SOL_RPC_URL", default_value = DEFAULT_SOL_RPC_URL)]
        sol_rpc: Option<String>,
        /// Solana WebSocket URL
        #[arg(long, env = "SOL_WS_URL", default_value = DEFAULT_SOL_WS_URL)]
        sol_ws: Option<String>,
        /// Caller's Solana keypair file path
        #[arg(long, env = "SELLER_SOL_KEYPAIR")]
        caller_sol_keypair: Option<String>,
        /// Solana HTLC program ID
        #[arg(long, env = "SOL_PROGRAM_ID")]
        program_id: Option<String>,

        // Common fields
        /// Token ID of the commitment to cancel
        #[arg(long, env = "TOKEN_ID")]
        token_id: Option<u64>,
    },

    /// Buyer withdraws Bitcoin from an HTLC after timeout expiry
    RefundBtc {
        /// Bitcoin RPC URL
        #[arg(long, env = "BTC_RPC_URL", default_value = DEFAULT_BTC_RPC_URL)]
        btc_rpc: String,
        /// Bitcoin RPC username
        #[arg(long, env = "BTC_RPC_USER", default_value = "user")]
        btc_user: String,
        /// Bitcoin RPC password
        #[arg(long, env = "BTC_RPC_PASSWORD", default_value = "password")]
        btc_pass: String,
        /// Bitcoin network (mainnet, testnet, signet, regtest)
        #[arg(long, env = "BTC_NETWORK", default_value = "regtest")]
        btc_network: String,
        /// Buyer's Bitcoin private key (WIF or hex)
        #[arg(long, env = "BUYER_BTC_PRIVKEY")]
        buyer_btc_key: String,
        /// Seller's Bitcoin public key (hex)
        #[arg(long, env = "SELLER_BTC_PUBKEY")]
        seller_btc_pubkey: String,
        /// File containing the generated secret from the lock transaction
        #[arg(long)]
        secret_file: PathBuf,
        /// Output index in the lock transaction
        #[arg(long, default_value = "0")]
        lock_vout: u32,
        /// Destination address for refunded Bitcoin
        #[arg(long)]
        destination: Option<String>,
    },
}

/// Validates that a required field is present, returning an error if missing.
fn require<T>(value: Option<T>, field_name: &str, env_var: &str) -> Result<T> {
    value.ok_or_else(|| {
        anyhow!(
            "Missing required argument: --{} (or set {} env var)",
            field_name.replace('_', "-"),
            env_var
        )
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file first (before parsing args) unless --no-env is present
    // We check for --no-env manually since clap hasn't parsed yet
    let args = std::env::args().collect::<Vec<String>>();
    if !args.iter().any(|a| a == "--no-env") {
        let _ = dotenvy::dotenv();
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let output_format = cli.output;

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

            let result = execute::lock_bitcoin(args)?;
            result.print(output_format);
            Ok(())
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
            sol_buyer,
            secret_hash,
            token_id,
            nft_price,
            metadata_uri,
        } => {
            let chain = chain
                .parse::<Chain>()
                .context("Invalid chain specification")?;

            let secret_hash = utils::decode_hex_hash(&secret_hash, "secret hash")?;
            let token_id = require(token_id, "token_id", "TOKEN_ID")?;
            let metadata_uri = require(metadata_uri, "metadata_uri", "METADATA_URI")?;

            let args = match chain {
                Chain::Ethereum => CommitForMintArgs::Ethereum(EthCommitArgs {
                    eth_rpc: require(eth_rpc, "eth_rpc", "ETH_RPC_URL")?,
                    seller_eth_key: require(
                        seller_eth_key,
                        "seller_eth_key",
                        "SELLER_ETH_PRIVKEY",
                    )?,
                    nft_contract: require(nft_contract, "nft_contract", "NFT_CONTRACT_ADDRESS")?
                        .parse()
                        .context("Invalid NFT contract address")?,
                    buyer: buyer_address
                        .map(|s| s.parse())
                        .transpose()
                        .context("Invalid buyer address")?,
                    secret_hash,
                    token_id,
                    price: require(nft_price, "nft_price", "ETH_NFT_PRICE")?,
                    metadata_uri,
                }),
                Chain::Solana => CommitForMintArgs::Solana(SolCommitArgs {
                    sol_rpc: require(sol_rpc, "sol_rpc", "SOL_RPC_URL")?,
                    sol_ws: require(sol_ws, "sol_ws", "SOL_WS_URL")?,
                    seller_sol_keypair: require(
                        seller_sol_keypair,
                        "seller_sol_keypair",
                        "SELLER_SOL_KEYPAIR",
                    )?,
                    program_id: require(program_id, "program_id", "SOL_PROGRAM_ID")?,
                    name: require(name, "name", "NFT_NAME")?,
                    symbol: require(symbol, "symbol", "NFT_SYMBOL")?,
                    buyer: sol_buyer
                        .map(|s| s.parse())
                        .transpose()
                        .context("Invalid Solana buyer pubkey")?,
                    secret_hash,
                    token_id,
                    price: nft_price
                        .or_else(|| std::env::var("SOL_NFT_PRICE").ok()?.parse().ok())
                        .ok_or_else(|| {
                            anyhow!(
                                "Missing required argument: --nft-price (or set SOL_NFT_PRICE env var)"
                            )
                        })?,
                    metadata_uri,
                }),
            };

            let result = execute::commit_for_mint(args).await?;
            result.print(output_format);
            Ok(())
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

            let (secret, _, _, _) = utils::resolve_secrets(secret, secret_file)?;
            let token_id = require(token_id, "token_id", "TOKEN_ID")?;

            let args = match chain {
                Chain::Ethereum => MintWithSecretArgs::Ethereum(EthMintArgs {
                    eth_rpc: require(eth_rpc, "eth_rpc", "ETH_RPC_URL")?,
                    buyer_eth_key: require(buyer_eth_key, "buyer_eth_key", "BUYER_ETH_PRIVKEY")?,
                    nft_contract: require(nft_contract, "nft_contract", "NFT_CONTRACT_ADDRESS")?
                        .parse()
                        .context("Invalid NFT contract address")?,
                    secret,
                    token_id,
                }),
                Chain::Solana => MintWithSecretArgs::Solana(SolMintArgs {
                    sol_rpc: require(sol_rpc, "sol_rpc", "SOL_RPC_URL")?,
                    sol_ws: require(sol_ws, "sol_ws", "SOL_WS_URL")?,
                    buyer_sol_keypair: require(
                        buyer_sol_keypair,
                        "buyer_sol_keypair",
                        "BUYER_SOL_KEYPAIR",
                    )?,
                    program_id: require(program_id, "program_id", "SOL_PROGRAM_ID")?,
                    secret,
                    token_id,
                }),
            };

            let result = execute::mint_with_secret(args).await?;
            result.print(output_format);
            Ok(())
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

            let (secret, file_secret_hash, file_lock_txid, file_timeout) =
                utils::resolve_secrets(secret, secret_file.clone())?;

            let secret_hash = secret_hash
                .map(|h| utils::decode_hex_hash(&h, "secret hash"))
                .transpose()?
                .or(file_secret_hash)
                .ok_or_else(|| {
                    anyhow!("Secret hash required (use --secret-hash or provide via --secret-file)")
                })?;

            let lock_txid = lock_txid
                .map(|s| s.parse())
                .transpose()
                .context("Invalid lock transaction ID")?
                .or(file_lock_txid)
                .ok_or_else(|| {
                    anyhow!("Lock txid required (use --lock-txid or provide via --secret-file)")
                })?;

            let timeout = timeout.or(file_timeout).ok_or_else(|| {
                anyhow!("Timeout height required (use --timeout or provide via --secret-file)")
            })?;

            let args = ClaimBtcArgs {
                btc_rpc,
                btc_user,
                btc_pass,
                btc_network: network,
                seller_btc_key,
                buyer_btc_pubkey,
                secret,
                secret_hash,
                lock_txid,
                lock_vout,
                timeout,
                destination: destination
                    .map(|s| utils::parse_btc_address(&s, network))
                    .transpose()?,
            };

            let result = execute::claim_bitcoin(args)?;
            result.print(output_format);
            Ok(())
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

            let token_id = require(token_id, "token_id", "TOKEN_ID")?;

            let args = match chain {
                Chain::Ethereum => CancelCommitArgs::Ethereum(EthCancelArgs {
                    eth_rpc: require(eth_rpc, "eth_rpc", "ETH_RPC_URL")?,
                    caller_eth_key: require(
                        caller_eth_key,
                        "caller_eth_key",
                        "SELLER_ETH_PRIVKEY",
                    )?,
                    nft_contract: require(nft_contract, "nft_contract", "NFT_CONTRACT_ADDRESS")?
                        .parse()
                        .context("Invalid NFT contract address")?,
                    token_id,
                }),
                Chain::Solana => CancelCommitArgs::Solana(SolCancelArgs {
                    sol_rpc: require(sol_rpc, "sol_rpc", "SOL_RPC_URL")?,
                    sol_ws: require(sol_ws, "sol_ws", "SOL_WS_URL")?,
                    caller_sol_keypair: require(
                        caller_sol_keypair,
                        "caller_sol_keypair",
                        "SELLER_SOL_KEYPAIR",
                    )?,
                    program_id: require(program_id, "program_id", "SOL_PROGRAM_ID")?,
                    token_id,
                }),
            };

            let result = execute::cancel_commitment(args).await?;
            result.print(output_format);
            Ok(())
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
                destination: destination
                    .map(|s| utils::parse_btc_address(&s, network))
                    .transpose()?,
            };

            let result = execute::refund_bitcoin(args)?;
            result.print(output_format);
            Ok(())
        }
    }
}
