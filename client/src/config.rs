//! Configuration system for the client.
//!
//! Configuration is loaded from environment variables. Use a `.env` file in the
//! project directory for convenience (copy from `.env.template`).
//!
//! All file paths (keypairs, secrets) should be relative to the project directory.

use std::env;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Root configuration containing all chain-specific settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Bitcoin network configuration.
    pub bitcoin: BitcoinConfig,
    /// Ethereum network configuration.
    pub ethereum: EthereumConfig,
    /// Solana network configuration.
    pub solana: SolanaConfig,
    /// Swap-specific settings.
    pub swap: SwapConfig,
}

/// Bitcoin network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinConfig {
    /// Bitcoin RPC URL.
    pub rpc_url: String,
    /// RPC username.
    pub rpc_user: String,
    /// RPC password.
    pub rpc_pass: String,
    /// Bitcoin network (mainnet, testnet, signet, regtest).
    pub network: String,
    /// Default HTLC timeout in blocks.
    pub default_timeout_blocks: u32,
    /// Buyer's Bitcoin private key (hex or WIF).
    pub buyer_private_key: Option<String>,
    /// Buyer's Bitcoin public key (hex).
    pub buyer_public_key: Option<String>,
    /// Seller's Bitcoin private key (hex or WIF).
    pub seller_private_key: Option<String>,
    /// Seller's Bitcoin public key (hex).
    pub seller_public_key: Option<String>,
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:18443".to_string(),
            rpc_user: "user".to_string(),
            rpc_pass: "password".to_string(),
            network: "regtest".to_string(),
            default_timeout_blocks: 144,
            buyer_private_key: None,
            buyer_public_key: None,
            seller_private_key: None,
            seller_public_key: None,
        }
    }
}

/// Ethereum network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumConfig {
    /// Ethereum RPC URL.
    pub rpc_url: String,
    /// NFT contract address.
    pub nft_contract: Option<String>,
    /// Chain ID (for transaction signing).
    pub chain_id: Option<u64>,
    /// Buyer's Ethereum private key (hex with 0x prefix).
    pub buyer_private_key: Option<String>,
    /// Seller's Ethereum private key (hex with 0x prefix).
    pub seller_private_key: Option<String>,
}

impl Default for EthereumConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:8545".to_string(),
            nft_contract: None,
            chain_id: None,
            buyer_private_key: None,
            seller_private_key: None,
        }
    }
}

/// Solana network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaConfig {
    /// Solana RPC URL.
    pub rpc_url: String,
    /// Solana WebSocket URL.
    pub ws_url: String,
    /// HTLC program ID.
    pub program_id: Option<String>,
    /// Path to buyer's keypair file.
    pub buyer_keypair_path: Option<String>,
    /// Path to seller's keypair file.
    pub seller_keypair_path: Option<String>,
}

impl Default for SolanaConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
            program_id: None,
            buyer_keypair_path: Some(".swap/keypairs/buyer.json".to_string()),
            seller_keypair_path: Some(".swap/keypairs/seller.json".to_string()),
        }
    }
}

/// Swap-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapConfig {
    /// Default Bitcoin amount in satoshis.
    pub default_btc_amount: u64,
    /// Default Ethereum NFT price in wei.
    pub eth_nft_price: u64,
    /// Default Solana NFT price in lamports.
    pub sol_nft_price: u64,
    /// Default token ID for NFT minting.
    pub default_token_id: Option<u64>,
    /// Default metadata URI for NFT.
    pub default_metadata_uri: Option<String>,
    /// Default NFT name (Solana).
    pub nft_name: Option<String>,
    /// Default NFT symbol (Solana).
    pub nft_symbol: Option<String>,
    /// Minimum commitment time before minting (seconds).
    pub min_commitment_time_secs: u64,
    /// Commitment timeout (seconds).
    pub commitment_timeout_secs: u64,
    /// Default HTLC timeout in blocks.
    pub htlc_timeout_blocks: u32,
}

impl Default for SwapConfig {
    fn default() -> Self {
        Self {
            default_btc_amount: 100_000,
            eth_nft_price: 0,
            sol_nft_price: 0,
            default_token_id: None,
            default_metadata_uri: None,
            nft_name: None,
            nft_symbol: None,
            min_commitment_time_secs: 60,
            commitment_timeout_secs: 86400,
            htlc_timeout_blocks: 144,
        }
    }
}

/// A wrapper around sensitive data that is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    /// Creates a new secret from a string.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Loads a secret from a file, trimming whitespace.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read secret from {}", path.display()))?;
        Ok(Self(content.trim().to_string()))
    }

    /// Loads a secret from an environment variable.
    pub fn from_env(var_name: &str) -> Result<Self> {
        let value = env::var(var_name)
            .with_context(|| format!("Environment variable {var_name} not set"))?;
        Ok(Self(value))
    }

    /// Returns a reference to the secret value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Returns Some(value) from env var if set, None otherwise.
fn env_var_opt(name: &str) -> Option<String> {
    env::var(name).ok().filter(|s| !s.is_empty())
}

/// Parses an env var as type T if set.
fn env_var_parsed<T: std::str::FromStr>(name: &str) -> Option<T> {
    env_var_opt(name).and_then(|v| v.parse().ok())
}

impl Config {
    /// Loads configuration from environment variables.
    ///
    /// Loads `.env` file from current directory if present, then applies
    /// environment variable overrides.
    pub fn load() -> Result<Self> {
        let _ = dotenvy::dotenv();
        Ok(Self::default().apply_env_overrides())
    }

    /// Applies environment variable overrides to the configuration.
    fn apply_env_overrides(self) -> Self {
        Self {
            bitcoin: BitcoinConfig {
                rpc_url: env_var_opt("BTC_RPC_URL").unwrap_or(self.bitcoin.rpc_url),
                rpc_user: env_var_opt("BTC_RPC_USER").unwrap_or(self.bitcoin.rpc_user),
                rpc_pass: env_var_opt("BTC_RPC_PASSWORD").unwrap_or(self.bitcoin.rpc_pass),
                network: env_var_opt("BTC_NETWORK").unwrap_or(self.bitcoin.network),
                default_timeout_blocks: env_var_parsed("HTLC_TIMEOUT")
                    .unwrap_or(self.bitcoin.default_timeout_blocks),
                buyer_private_key: env_var_opt("BUYER_BTC_PRIVKEY")
                    .or(self.bitcoin.buyer_private_key),
                buyer_public_key: env_var_opt("BUYER_BTC_PUBKEY").or(self.bitcoin.buyer_public_key),
                seller_private_key: env_var_opt("SELLER_BTC_PRIVKEY")
                    .or(self.bitcoin.seller_private_key),
                seller_public_key: env_var_opt("SELLER_BTC_PUBKEY")
                    .or(self.bitcoin.seller_public_key),
            },
            ethereum: EthereumConfig {
                rpc_url: env_var_opt("ETH_RPC_URL").unwrap_or(self.ethereum.rpc_url),
                nft_contract: env_var_opt("NFT_CONTRACT_ADDRESS").or(self.ethereum.nft_contract),
                chain_id: env_var_parsed("ETH_CHAIN_ID").or(self.ethereum.chain_id),
                buyer_private_key: env_var_opt("BUYER_ETH_PRIVKEY")
                    .or(self.ethereum.buyer_private_key),
                seller_private_key: env_var_opt("SELLER_ETH_PRIVKEY")
                    .or(self.ethereum.seller_private_key),
            },
            solana: SolanaConfig {
                rpc_url: env_var_opt("SOL_RPC_URL").unwrap_or(self.solana.rpc_url),
                ws_url: env_var_opt("SOL_WS_URL").unwrap_or(self.solana.ws_url),
                program_id: env_var_opt("SOL_PROGRAM_ID").or(self.solana.program_id),
                buyer_keypair_path: env_var_opt("BUYER_SOL_KEYPAIR")
                    .or(self.solana.buyer_keypair_path),
                seller_keypair_path: env_var_opt("SELLER_SOL_KEYPAIR")
                    .or(self.solana.seller_keypair_path),
            },
            swap: SwapConfig {
                default_btc_amount: env_var_parsed("BTC_AMOUNT")
                    .unwrap_or(self.swap.default_btc_amount),
                eth_nft_price: env_var_parsed("ETH_NFT_PRICE").unwrap_or(self.swap.eth_nft_price),
                sol_nft_price: env_var_parsed("SOL_NFT_PRICE").unwrap_or(self.swap.sol_nft_price),
                default_token_id: env_var_parsed("TOKEN_ID").or(self.swap.default_token_id),
                default_metadata_uri: env_var_opt("METADATA_URI")
                    .or(self.swap.default_metadata_uri),
                nft_name: env_var_opt("NFT_NAME").or(self.swap.nft_name),
                nft_symbol: env_var_opt("NFT_SYMBOL").or(self.swap.nft_symbol),
                min_commitment_time_secs: self.swap.min_commitment_time_secs,
                commitment_timeout_secs: self.swap.commitment_timeout_secs,
                htlc_timeout_blocks: env_var_parsed("HTLC_TIMEOUT")
                    .unwrap_or(self.swap.htlc_timeout_blocks),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = Config::default();
        assert_eq!(config.bitcoin.network, "regtest");
        assert_eq!(config.bitcoin.default_timeout_blocks, 144);
        assert_eq!(config.swap.default_btc_amount, 100_000);
    }

    #[test]
    fn secret_redacted_debug() {
        let secret = Secret::new("super_secret_value".to_string());
        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("super_secret"));
    }

    #[test]
    fn secret_expose() {
        let secret = Secret::new("my_secret".to_string());
        assert_eq!(secret.expose(), "my_secret");
    }
}
