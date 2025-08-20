use anyhow::{Context, Result};
use bitcoin::address::NetworkUnchecked;
use bitcoin::key::Keypair;
use bitcoin::{Address, Network, PublicKey};

pub fn parse_btc_address(addr: &str, network: Network) -> anyhow::Result<bitcoin::Address> {
    let addr = addr
        .parse::<Address<NetworkUnchecked>>()
        .context("Invalid Bitcoin address format")?
        .require_network(network)
        .context("Bitcoin address network mismatch")?;
    Ok(addr)
}

pub fn parse_network(network: &str) -> anyhow::Result<Network> {
    match network.to_lowercase().as_str() {
        "mainnet" | "main" => Ok(Network::Bitcoin),
        "testnet" | "test" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" | "reg" => Ok(Network::Regtest),
        _ => Err(anyhow::anyhow!(
            "Invalid network '{network}'. Supported: mainnet, testnet, signet, regtest"
        )),
    }
}

pub fn validate_btc_keypair(key: &str, role: &str) -> Result<Keypair> {
    key.parse::<Keypair>()
        .with_context(|| format!("Invalid Bitcoin private key for {}", role))
}

pub fn validate_btc_pubkey(key: &str, role: &str) -> Result<PublicKey> {
    key.parse::<PublicKey>()
        .with_context(|| format!("Invalid Bitcoin public key for {}", role))
}
