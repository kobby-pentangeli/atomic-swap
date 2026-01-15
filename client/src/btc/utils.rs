//! Bitcoin utility functions for address parsing and validation.

use anyhow::{Context, Result, anyhow};
use bitcoin::address::NetworkUnchecked;
use bitcoin::key::Keypair;
use bitcoin::{Address, Network, OutPoint, PublicKey, TxOut};

/// Information about an unspent transaction output (UTXO).
///
/// Contains both the outpoint (transaction ID and output index) and
/// the output details (value and script).
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    /// The outpoint identifying this UTXO.
    pub outpoint: OutPoint,
    /// The transaction output details.
    pub tx_out: TxOut,
}

/// Parse and validate a Bitcoin address for the specified network.
///
/// # Arguments
///
/// * `addr` - The address string to parse.
/// * `network` - The expected Bitcoin network.
///
/// # Returns
///
/// The parsed and validated address.
///
/// # Errors
///
/// Returns an error if:
/// - The address format is invalid
/// - The address is for a different network
///
/// # Example
///
/// ```ignore
/// let address = parse_btc_address(
///     "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
///     Network::Regtest
/// )?;
/// ```
pub fn parse_btc_address(addr: &str, network: Network) -> Result<Address> {
    addr.parse::<Address<NetworkUnchecked>>()
        .context("Invalid Bitcoin address format")
        .and_then(|unchecked| {
            unchecked
                .require_network(network)
                .map_err(|_| anyhow!("Address is not valid for {} network", network))
        })
}

/// Parse a network string into a Bitcoin network type.
///
/// Supports common aliases for each network type.
///
/// # Supported Values
///
/// | Network  | Accepted Values                    |
/// |----------|-------------------------------------|
/// | Mainnet  | `mainnet`, `main`, `bitcoin`        |
/// | Testnet  | `testnet`, `test`, `testnet3`       |
/// | Signet   | `signet`                            |
/// | Regtest  | `regtest`, `reg`                    |
///
/// # Arguments
///
/// * `network` - The network string to parse.
///
/// # Returns
///
/// The corresponding `Network` enum value.
///
/// # Errors
///
/// Returns an error if the network string is not recognized.
pub fn parse_btc_network(network: &str) -> Result<Network> {
    match network.to_lowercase().as_str() {
        "mainnet" | "main" | "bitcoin" => Ok(Network::Bitcoin),
        "testnet" | "test" | "testnet3" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" | "reg" => Ok(Network::Regtest),
        _ => Err(anyhow!(
            "Invalid network '{}'. Supported: mainnet, testnet, signet, regtest",
            network
        )),
    }
}

/// Parse and validate a Bitcoin keypair from WIF format.
///
/// # Arguments
///
/// * `key` - The private key in WIF (Wallet Import Format) or hex.
/// * `role` - Description of the key's purpose (for error messages).
///
/// # Returns
///
/// The parsed keypair.
///
/// # Errors
///
/// Returns an error if the key format is invalid.
pub fn validate_btc_keypair(key: &str, role: &str) -> Result<Keypair> {
    key.parse::<Keypair>()
        .with_context(|| format!("Invalid Bitcoin private key for {role}"))
}

/// Parse and validate a Bitcoin public key.
///
/// Accepts both compressed (33 bytes) and uncompressed (65 bytes)
/// public key formats in hex.
///
/// # Arguments
///
/// * `key` - The public key in hex format.
/// * `role` - Description of the key's purpose (for error messages).
///
/// # Returns
///
/// The parsed public key.
///
/// # Errors
///
/// Returns an error if the key format is invalid.
pub fn validate_btc_pubkey(key: &str, role: &str) -> Result<PublicKey> {
    key.parse::<PublicKey>()
        .with_context(|| format!("Invalid Bitcoin public key for {role}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btc_network_parse() {
        assert!(matches!(parse_btc_network("mainnet"), Ok(Network::Bitcoin)));
        assert!(matches!(parse_btc_network("MAINNET"), Ok(Network::Bitcoin)));
        assert!(matches!(parse_btc_network("testnet"), Ok(Network::Testnet)));
        assert!(matches!(parse_btc_network("regtest"), Ok(Network::Regtest)));
        assert!(matches!(parse_btc_network("signet"), Ok(Network::Signet)));
        assert!(parse_btc_network("invalid").is_err());
    }
}
