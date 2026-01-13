//! Configuration system for the client.
//!
//! This module provides a layered configuration system that loads settings from:
//! 1. Default values
//! 2. Configuration file (TOML format)
//! 3. Environment variables (with `ATOMIC_SWAP_` prefix)
//! 4. `.env` file in the current directory
//!
//! Later sources override earlier ones, allowing flexible configuration.

use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Environment variable prefix for configuration.
const ENV_PREFIX: &str = "ATOMIC_SWAP_";

/// Configuration file name.
const CONFIG_FILE_NAME: &str = "config.toml";

/// Root configuration containing all chain-specific settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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
    /// Buyer's Bitcoin private key (hex, WIF, or path to file).
    pub buyer_private_key: Option<String>,
    /// Buyer's Bitcoin public key (hex).
    pub buyer_public_key: Option<String>,
    /// Seller's Bitcoin private key (hex, WIF, or path to file).
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
            default_timeout_blocks: 144, // ~24 hours on mainnet
            buyer_private_key: None,
            buyer_public_key: None,
            seller_private_key: None,
            seller_public_key: None,
        }
    }
}

/// Ethereum network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EthereumConfig {
    /// Ethereum RPC URL.
    pub rpc_url: String,
    /// NFT contract address.
    pub nft_contract: Option<String>,
    /// Chain ID (for transaction signing).
    pub chain_id: Option<u64>,
    /// Buyer's Ethereum private key (hex).
    pub buyer_private_key: Option<String>,
    /// Seller's Ethereum private key (hex).
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
#[serde(default)]
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
            buyer_keypair_path: None,
            seller_keypair_path: None,
        }
    }
}

/// Swap-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
            default_btc_amount: 100_000, // 0.001 BTC
            eth_nft_price: 0,
            sol_nft_price: 0,
            default_token_id: None,
            default_metadata_uri: None,
            nft_name: None,
            nft_symbol: None,
            min_commitment_time_secs: 60,
            commitment_timeout_secs: 86400, // 24 hours
            htlc_timeout_blocks: 144,       // ~24 hours on mainnet
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
        let content = fs::read_to_string(path)
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

/// Returns `other` if it differs from `default`, otherwise returns `base`.
fn override_if_changed<T: PartialEq>(base: T, other: T, default: &T) -> T {
    if &other != default { other } else { base }
}

/// Returns Some(value) from env var if set and parseable, None otherwise.
fn env_var_opt(name: &str) -> Option<String> {
    env::var(name).ok()
}

/// Parses an env var as type T if set.
fn env_var_parsed<T: std::str::FromStr>(name: &str) -> Option<T> {
    env::var(name).ok().and_then(|v| v.parse().ok())
}

impl Config {
    /// Loads configuration from all available sources.
    ///
    /// Sources are loaded in order (later sources override earlier):
    /// 1. Default values
    /// 2. System config file (`~/.config/atomic-swap/config.toml`)
    /// 3. Local config file (`./config.toml`)
    /// 4. Environment variables (with `ATOMIC_SWAP_` prefix)
    /// 5. `.env` file in current directory
    pub fn load() -> Result<Self> {
        let _ = dotenvy::dotenv();

        let mut config = Self::default();

        if let Some(config_path) = Self::system_config_path()
            && config_path.exists()
        {
            config = config.merge_from_file(&config_path)?;
        }

        let local_config = PathBuf::from(CONFIG_FILE_NAME);
        if local_config.exists() {
            config = config.merge_from_file(&local_config)?;
        }

        config = config.apply_env_overrides();

        Ok(config)
    }

    /// Loads configuration from a specific file path.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        Ok(config)
    }

    /// Merges configuration from a file into the current configuration.
    fn merge_from_file(self, path: &Path) -> Result<Self> {
        let file_config = Self::from_file(path)?;
        Ok(self.merge(file_config))
    }

    /// Merges another configuration into this one.
    ///
    /// Values from `other` override values in `self` if they differ from defaults.
    fn merge(self, other: Self) -> Self {
        let btc_default = BitcoinConfig::default();
        let eth_default = EthereumConfig::default();
        let sol_default = SolanaConfig::default();
        let swap_default = SwapConfig::default();

        Self {
            bitcoin: BitcoinConfig {
                rpc_url: override_if_changed(
                    self.bitcoin.rpc_url,
                    other.bitcoin.rpc_url,
                    &btc_default.rpc_url,
                ),
                rpc_user: override_if_changed(
                    self.bitcoin.rpc_user,
                    other.bitcoin.rpc_user,
                    &btc_default.rpc_user,
                ),
                rpc_pass: override_if_changed(
                    self.bitcoin.rpc_pass,
                    other.bitcoin.rpc_pass,
                    &btc_default.rpc_pass,
                ),
                network: override_if_changed(
                    self.bitcoin.network,
                    other.bitcoin.network,
                    &btc_default.network,
                ),
                default_timeout_blocks: if other.bitcoin.default_timeout_blocks
                    != btc_default.default_timeout_blocks
                {
                    other.bitcoin.default_timeout_blocks
                } else {
                    self.bitcoin.default_timeout_blocks
                },
                buyer_private_key: other
                    .bitcoin
                    .buyer_private_key
                    .or(self.bitcoin.buyer_private_key),
                buyer_public_key: other
                    .bitcoin
                    .buyer_public_key
                    .or(self.bitcoin.buyer_public_key),
                seller_private_key: other
                    .bitcoin
                    .seller_private_key
                    .or(self.bitcoin.seller_private_key),
                seller_public_key: other
                    .bitcoin
                    .seller_public_key
                    .or(self.bitcoin.seller_public_key),
            },
            ethereum: EthereumConfig {
                rpc_url: override_if_changed(
                    self.ethereum.rpc_url,
                    other.ethereum.rpc_url,
                    &eth_default.rpc_url,
                ),
                nft_contract: other.ethereum.nft_contract.or(self.ethereum.nft_contract),
                chain_id: other.ethereum.chain_id.or(self.ethereum.chain_id),
                buyer_private_key: other
                    .ethereum
                    .buyer_private_key
                    .or(self.ethereum.buyer_private_key),
                seller_private_key: other
                    .ethereum
                    .seller_private_key
                    .or(self.ethereum.seller_private_key),
            },
            solana: SolanaConfig {
                rpc_url: override_if_changed(
                    self.solana.rpc_url,
                    other.solana.rpc_url,
                    &sol_default.rpc_url,
                ),
                ws_url: override_if_changed(
                    self.solana.ws_url,
                    other.solana.ws_url,
                    &sol_default.ws_url,
                ),
                program_id: other.solana.program_id.or(self.solana.program_id),
                buyer_keypair_path: other
                    .solana
                    .buyer_keypair_path
                    .or(self.solana.buyer_keypair_path),
                seller_keypair_path: other
                    .solana
                    .seller_keypair_path
                    .or(self.solana.seller_keypair_path),
            },
            swap: SwapConfig {
                default_btc_amount: if other.swap.default_btc_amount
                    != swap_default.default_btc_amount
                {
                    other.swap.default_btc_amount
                } else {
                    self.swap.default_btc_amount
                },
                eth_nft_price: if other.swap.eth_nft_price != swap_default.eth_nft_price {
                    other.swap.eth_nft_price
                } else {
                    self.swap.eth_nft_price
                },
                sol_nft_price: if other.swap.sol_nft_price != swap_default.sol_nft_price {
                    other.swap.sol_nft_price
                } else {
                    self.swap.sol_nft_price
                },
                default_token_id: other.swap.default_token_id.or(self.swap.default_token_id),
                default_metadata_uri: other
                    .swap
                    .default_metadata_uri
                    .or(self.swap.default_metadata_uri),
                nft_name: other.swap.nft_name.or(self.swap.nft_name),
                nft_symbol: other.swap.nft_symbol.or(self.swap.nft_symbol),
                min_commitment_time_secs: if other.swap.min_commitment_time_secs
                    != swap_default.min_commitment_time_secs
                {
                    other.swap.min_commitment_time_secs
                } else {
                    self.swap.min_commitment_time_secs
                },
                commitment_timeout_secs: if other.swap.commitment_timeout_secs
                    != swap_default.commitment_timeout_secs
                {
                    other.swap.commitment_timeout_secs
                } else {
                    self.swap.commitment_timeout_secs
                },
                htlc_timeout_blocks: if other.swap.htlc_timeout_blocks
                    != swap_default.htlc_timeout_blocks
                {
                    other.swap.htlc_timeout_blocks
                } else {
                    self.swap.htlc_timeout_blocks
                },
            },
        }
    }

    /// Applies environment variable overrides to the configuration.
    fn apply_env_overrides(self) -> Self {
        Self {
            bitcoin: BitcoinConfig {
                rpc_url: env_var_opt(&format!("{ENV_PREFIX}BTC_RPC_URL"))
                    .unwrap_or(self.bitcoin.rpc_url),
                rpc_user: env_var_opt(&format!("{ENV_PREFIX}BTC_RPC_USER"))
                    .unwrap_or(self.bitcoin.rpc_user),
                rpc_pass: env_var_opt(&format!("{ENV_PREFIX}BTC_RPC_PASS"))
                    .unwrap_or(self.bitcoin.rpc_pass),
                network: env_var_opt(&format!("{ENV_PREFIX}BTC_NETWORK"))
                    .unwrap_or(self.bitcoin.network),
                default_timeout_blocks: env_var_parsed(&format!("{ENV_PREFIX}BTC_TIMEOUT_BLOCKS"))
                    .unwrap_or(self.bitcoin.default_timeout_blocks),
                buyer_private_key: env_var_opt(&format!("{ENV_PREFIX}BUYER_BTC_PRIVKEY"))
                    .or(self.bitcoin.buyer_private_key),
                buyer_public_key: env_var_opt(&format!("{ENV_PREFIX}BUYER_BTC_PUBKEY"))
                    .or(self.bitcoin.buyer_public_key),
                seller_private_key: env_var_opt(&format!("{ENV_PREFIX}SELLER_BTC_PRIVKEY"))
                    .or(self.bitcoin.seller_private_key),
                seller_public_key: env_var_opt(&format!("{ENV_PREFIX}SELLER_BTC_PUBKEY"))
                    .or(self.bitcoin.seller_public_key),
            },
            ethereum: EthereumConfig {
                rpc_url: env_var_opt(&format!("{ENV_PREFIX}ETH_RPC_URL"))
                    .unwrap_or(self.ethereum.rpc_url),
                nft_contract: env_var_opt(&format!("{ENV_PREFIX}ETH_NFT_CONTRACT"))
                    .or(self.ethereum.nft_contract),
                chain_id: env_var_parsed(&format!("{ENV_PREFIX}ETH_CHAIN_ID"))
                    .or(self.ethereum.chain_id),
                buyer_private_key: env_var_opt(&format!("{ENV_PREFIX}BUYER_ETH_PRIVKEY"))
                    .or(self.ethereum.buyer_private_key),
                seller_private_key: env_var_opt(&format!("{ENV_PREFIX}SELLER_ETH_PRIVKEY"))
                    .or(self.ethereum.seller_private_key),
            },
            solana: SolanaConfig {
                rpc_url: env_var_opt(&format!("{ENV_PREFIX}SOL_RPC_URL"))
                    .unwrap_or(self.solana.rpc_url),
                ws_url: env_var_opt(&format!("{ENV_PREFIX}SOL_WS_URL"))
                    .unwrap_or(self.solana.ws_url),
                program_id: env_var_opt(&format!("{ENV_PREFIX}SOL_PROGRAM_ID"))
                    .or(self.solana.program_id),
                buyer_keypair_path: env_var_opt(&format!("{ENV_PREFIX}BUYER_SOL_KEYPAIR"))
                    .or(self.solana.buyer_keypair_path),
                seller_keypair_path: env_var_opt(&format!("{ENV_PREFIX}SELLER_SOL_KEYPAIR"))
                    .or(self.solana.seller_keypair_path),
            },
            swap: SwapConfig {
                default_btc_amount: env_var_parsed(&format!("{ENV_PREFIX}BTC_AMOUNT"))
                    .unwrap_or(self.swap.default_btc_amount),
                eth_nft_price: env_var_parsed(&format!("{ENV_PREFIX}ETH_NFT_PRICE"))
                    .unwrap_or(self.swap.eth_nft_price),
                sol_nft_price: env_var_parsed(&format!("{ENV_PREFIX}SOL_NFT_PRICE"))
                    .unwrap_or(self.swap.sol_nft_price),
                default_token_id: env_var_parsed(&format!("{ENV_PREFIX}TOKEN_ID"))
                    .or(self.swap.default_token_id),
                default_metadata_uri: env_var_opt(&format!("{ENV_PREFIX}METADATA_URI"))
                    .or(self.swap.default_metadata_uri),
                nft_name: env_var_opt(&format!("{ENV_PREFIX}NFT_NAME")).or(self.swap.nft_name),
                nft_symbol: env_var_opt(&format!("{ENV_PREFIX}NFT_SYMBOL"))
                    .or(self.swap.nft_symbol),
                min_commitment_time_secs: env_var_parsed(&format!(
                    "{ENV_PREFIX}MIN_COMMITMENT_TIME_SECS"
                ))
                .unwrap_or(self.swap.min_commitment_time_secs),
                commitment_timeout_secs: env_var_parsed(&format!(
                    "{ENV_PREFIX}COMMITMENT_TIMEOUT_SECS"
                ))
                .unwrap_or(self.swap.commitment_timeout_secs),
                htlc_timeout_blocks: env_var_parsed(&format!("{ENV_PREFIX}HTLC_TIMEOUT"))
                    .unwrap_or(self.swap.htlc_timeout_blocks),
            },
        }
    }

    /// Returns the system configuration file path.
    fn system_config_path() -> Option<PathBuf> {
        ProjectDirs::from("com", "atomic-swap", "atomic-swap")
            .map(|dirs| dirs.config_dir().join(CONFIG_FILE_NAME))
    }

    /// Generates a sample configuration file content.
    pub fn sample_config() -> String {
        let config = Self::default();
        toml::to_string_pretty(&config).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.bitcoin.network, "regtest");
        assert_eq!(config.bitcoin.default_timeout_blocks, 144);
        assert_eq!(config.swap.default_btc_amount, 100_000);
    }

    #[test]
    fn test_secret_redacted_debug() {
        let secret = Secret::new("super_secret_value".to_string());
        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("super_secret"));
    }

    #[test]
    fn test_secret_expose() {
        let secret = Secret::new("my_secret".to_string());
        assert_eq!(secret.expose(), "my_secret");
    }

    #[test]
    fn test_config_merge() {
        let base = Config::default();
        let mut override_config = Config::default();
        override_config.bitcoin.network = "mainnet".to_string();
        override_config.ethereum.nft_contract = Some("0x1234".to_string());

        let merged = base.merge(override_config);
        assert_eq!(merged.bitcoin.network, "mainnet");
        assert_eq!(merged.ethereum.nft_contract, Some("0x1234".to_string()));
    }

    #[test]
    fn test_sample_config_generation() {
        let sample = Config::sample_config();
        assert!(sample.contains("[bitcoin]"));
        assert!(sample.contains("[ethereum]"));
        assert!(sample.contains("[solana]"));
        assert!(sample.contains("[swap]"));
    }
}
