use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};

pub mod btc;
pub mod config;
pub mod eth;
pub mod execute;
pub mod sol;
pub mod types;

use types::{
    CancelCommitArgs, Chain, ClaimBtcArgs, CommitForMintArgs, LockBtcArgs, MintWithSecretArgs,
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
                btc_network: btc::utils::parse_network(&btc_network)?,
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

            let secret_bytes = resolve_secret(secret, secret_file)?;

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
            let network = btc::utils::parse_network(&btc_network)?;

            // Resolve secret from either --secret or --secret-file
            let (secret_bytes, file_secret_hash, file_lock_txid) =
                resolve_secret_with_metadata(secret, secret_file.clone())?;

            let final_secret_hash = secret_hash
                .map(|h| decode_hex_hash(&h, "secret hash"))
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
                    .map(|s| btc::utils::parse_btc_address(&s, network))
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
    }
}

fn decode_hex_hash(hex_str: &str, field_name: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(hex_str).with_context(|| format!("Invalid hex encoding for {field_name}"))?;

    bytes.clone().try_into().map_err(|_| {
        anyhow!(
            "Invalid {field_name} length: expected 32 bytes, got {}",
            bytes.len()
        )
    })
}

fn decode_hex_secret(hex_str: &str) -> Result<[u8; 32]> {
    decode_hex_hash(hex_str, "secret")
}

/// Resolves a secret from either a direct hex string or a file.
fn resolve_secret(secret: Option<String>, secret_file: Option<PathBuf>) -> Result<[u8; 32]> {
    match (secret, secret_file) {
        (Some(s), None) => decode_hex_secret(&s),
        (None, Some(path)) => {
            let (secret_bytes, _, _) = parse_secret_file(&path)?;
            Ok(secret_bytes)
        }
        (None, None) => Err(anyhow!("Either --secret or --secret-file must be provided")),
        (Some(_), Some(_)) => Err(anyhow!("--secret and --secret-file are mutually exclusive")),
    }
}

/// Secret file data containing the secret and optional metadata.
type SecretFileData = ([u8; 32], Option<[u8; 32]>, Option<bitcoin::Txid>);

/// Resolves a secret and optional metadata from either a direct hex string or a file.
fn resolve_secret_with_metadata(
    secret: Option<String>,
    secret_file: Option<PathBuf>,
) -> Result<SecretFileData> {
    match (secret, secret_file) {
        (Some(s), None) => Ok((decode_hex_secret(&s)?, None, None)),
        (None, Some(path)) => {
            let (secret_bytes, secret_hash, lock_txid) = parse_secret_file(&path)?;
            Ok((secret_bytes, secret_hash, lock_txid))
        }
        (None, None) => Err(anyhow!("Either --secret or --secret-file must be provided")),
        (Some(_), Some(_)) => Err(anyhow!("--secret and --secret-file are mutually exclusive")),
    }
}

/// Parses a secret file in the format generated by lock_bitcoin.
///
/// The file format is:
/// ```text
/// SECRET=<hex>
/// SECRET_HASH=<hex>
/// LOCK_TXID=<txid>
/// ```
fn parse_secret_file(path: &Path) -> Result<SecretFileData> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read secret file: {}", path.display()))?;

    let mut secret: Option<[u8; 32]> = None;
    let mut secret_hash: Option<[u8; 32]> = None;
    let mut lock_txid: Option<bitcoin::Txid> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "SECRET" => {
                    secret = Some(decode_hex_secret(value.trim())?);
                }
                "SECRET_HASH" => {
                    secret_hash = Some(decode_hex_hash(value.trim(), "secret hash")?);
                }
                "LOCK_TXID" => {
                    lock_txid = Some(
                        value
                            .trim()
                            .parse()
                            .context("Invalid LOCK_TXID in secret file")?,
                    );
                }
                _ => {} // Ignore unknown keys
            }
        }
    }

    let secret = secret.ok_or_else(|| anyhow!("SECRET not found in file: {}", path.display()))?;

    Ok((secret, secret_hash, lock_txid))
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
