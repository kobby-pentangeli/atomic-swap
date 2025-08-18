use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::{Amount, Network, PublicKey};
use bitcoincore_rpc::Auth;
use btc_htlc::{Contract as BtcContract, HtlcParams, generate_secret};
use clap::Parser;
use ethers::types::U256;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, timeout};
use tracing::{Instrument, debug, error, info, instrument, warn};

pub mod btc;
pub mod cmd;
pub mod eth;
pub mod types;

use btc::BtcClient;
use cmd::Commands;
use eth::EthClient;
use types::{AtomicSwapConfig, ClaimBtcConfig, CommitForMintConfig, MonitorConfig, SwapEvent};

const MAX_BTC_CONFIRMATION_WAIT: Duration = Duration::from_secs(600); // 10 minutes
const MAX_ETH_CONFIRMATION_WAIT: Duration = Duration::from_secs(600); // 10 minutes
const MAX_COMMITMENT_WAIT: Duration = Duration::from_secs(1200); // 20 minutes
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const CONFIRMATION_CHECK_INTERVAL: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let cli = cmd::Cli::parse();

    match cli.command {
        Commands::AtomicSwap {
            btc_rpc,
            btc_user,
            btc_pass,
            btc_network,
            buyer_btc_key,
            seller_btc_pubkey,
            eth_rpc,
            buyer_eth_key,
            nft_contract,
            btc_amount,
            nft_price,
            token_id,
            metadata_uri,
            timeout,
        } => {
            let config = AtomicSwapConfig {
                btc_rpc,
                btc_user,
                btc_pass,
                btc_network: parse_network(&btc_network)?,
                buyer_btc_key,
                seller_btc_pubkey,
                eth_rpc,
                buyer_eth_key,
                nft_contract: nft_contract
                    .parse()
                    .context("Invalid NFT contract address")?,
                btc_amount,
                nft_price,
                token_id,
                metadata_uri,
                timeout,
            };

            execute_atomic_swap(config).await
        }
        Commands::CommitForMint {
            eth_rpc,
            seller_eth_key,
            nft_contract,
            secret_hash,
            token_id,
            nft_price,
            buyer_address,
            metadata_uri,
        } => {
            let config = CommitForMintConfig {
                eth_rpc,
                seller_eth_key,
                nft_contract: nft_contract
                    .parse()
                    .context("Invalid NFT contract address")?,
                secret_hash: decode_hex_hash(&secret_hash, "secret hash")?,
                token_id,
                nft_price,
                buyer_address: buyer_address
                    .map(|s| s.parse())
                    .transpose()
                    .context("Invalid buyer address")?,
                metadata_uri,
            };

            execute_commit_for_mint(config).await
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
            let network = parse_network(&btc_network)?;
            let config = ClaimBtcConfig {
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
                    .map(|s| parse_btc_address(&s, network))
                    .transpose()?,
            };

            execute_claim_bitcoin(config).await
        }
        Commands::Monitor {
            btc_rpc,
            btc_user,
            btc_pass,
            btc_network,
            eth_rpc,
            eth_key,
            nft_contract,
        } => {
            let config = MonitorConfig {
                btc_rpc,
                btc_user,
                btc_pass,
                btc_network: parse_network(&btc_network)?,
                eth_rpc,
                eth_key,
                nft_contract: nft_contract
                    .parse()
                    .context("Invalid NFT contract address")?,
            };

            execute_monitor(config).await
        }
    }
}

async fn execute_atomic_swap(config: AtomicSwapConfig) -> Result<()> {
    info!(
        btc_network = %config.btc_network,
        nft_contract = %config.nft_contract,
        "Initializing cross-chain atomic swap"
    );

    let buyer_keypair = validate_btc_key(&config.buyer_btc_key, "buyer")?;
    let seller_pubkey = validate_btc_pubkey(&config.seller_btc_pubkey, "seller")?;
    let buyer_pubkey = PublicKey::from(buyer_keypair.public_key());

    let (secret, secret_hash) = generate_secret();
    info!(
        secret_hash = %hex::encode(secret_hash.as_byte_array()),
        "Generated secret pair for atomic swap"
    );

    let contract_params = HtlcParams {
        secret_hash,
        seller: seller_pubkey,
        buyer: buyer_pubkey,
        timeout: config.timeout,
        network: config.btc_network,
    };
    let btc_contract = BtcContract::new(contract_params);
    let htlc_address = btc_contract.address();

    info!(
        htlc_address = %htlc_address,
        seller_pubkey = %seller_pubkey,
        buyer_pubkey = %buyer_pubkey,
        timeout_blocks = %config.timeout,
        "Created HTLC contract"
    );

    let auth = Auth::UserPass(config.btc_user.clone(), config.btc_pass.clone());
    let btc_client = BtcClient::new(&config.btc_rpc, auth, config.btc_network, buyer_keypair)
        .context("Failed to initialize Bitcoin client")?;

    let eth_client = EthClient::new(&config.eth_rpc, &config.buyer_eth_key, config.nft_contract)
        .await
        .context("Failed to initialize Ethereum client")?;

    info!(
        btc_network = %config.btc_network,
        eth_contract = %config.nft_contract,
        buyer_eth_address = %eth_client.get_address(),
        "Connected to blockchain networks"
    );

    let lock_txid = execute_bitcoin_lock(&btc_client, &btc_contract, config.btc_amount).await?;

    wait_for_seller_commitment(&eth_client, &config, &secret_hash, &htlc_address).await?;

    let mint_tx = execute_nft_mint(&eth_client, secret, config.token_id).await?;

    provide_claim_instructions(&config, &secret, &secret_hash, lock_txid, &buyer_pubkey);

    info!(
        lock_txid = %lock_txid,
        mint_tx = %mint_tx,
        "Cross-chain atomic swap completed successfully"
    );

    Ok(())
}

async fn execute_bitcoin_lock(
    btc_client: &BtcClient,
    btc_contract: &BtcContract,
    btc_amount: u64,
) -> Result<bitcoin::Txid> {
    info!("Initiating Bitcoin lock transaction");

    let amount = Amount::from_sat(btc_amount);
    let lock_txid = btc_client
        .lock_funds(btc_contract, amount)
        .await
        .context("Failed to lock Bitcoin funds")?;

    info!(
        txid = %lock_txid,
        amount_btc = %amount.to_btc(),
        htlc_address = %btc_contract.address(),
        "Bitcoin funds locked successfully"
    );

    let confirmation_start = Instant::now();
    loop {
        if confirmation_start.elapsed() > MAX_BTC_CONFIRMATION_WAIT {
            warn!("Bitcoin confirmation timeout reached, proceeding anyway");
            break;
        }

        match btc_client.get_transaction_info(&lock_txid) {
            Ok(tx_info) if tx_info.confirmations > 0 => {
                info!(
                    confirmations = tx_info.confirmations,
                    duration_secs = confirmation_start.elapsed().as_secs(),
                    "Bitcoin transaction confirmed"
                );
                break;
            }
            Ok(_) => {
                debug!("Waiting for Bitcoin confirmation...");
                sleep(CONFIRMATION_CHECK_INTERVAL).await;
            }
            Err(e) => {
                warn!(error = %e, "Failed to check Bitcoin transaction status");
                sleep(CONFIRMATION_CHECK_INTERVAL).await;
            }
        }
    }

    Ok(lock_txid)
}

#[instrument(skip_all, fields(token_id = %config.token_id))]
async fn wait_for_seller_commitment(
    eth_client: &EthClient,
    config: &AtomicSwapConfig,
    secret_hash: &sha256::Hash,
    htlc_address: &bitcoin::Address,
) -> Result<()> {
    info!("Waiting for seller NFT commitment on Ethereum");

    // Provide seller instructions
    print_seller_instructions(config, secret_hash, htlc_address, eth_client.get_address());

    let wait_start = Instant::now();
    loop {
        if wait_start.elapsed() > MAX_COMMITMENT_WAIT {
            return Err(anyhow::anyhow!(
                "Timeout waiting for seller commitment after {} seconds",
                MAX_COMMITMENT_WAIT.as_secs()
            ));
        }

        match timeout(
            POLL_INTERVAL,
            eth_client.get_commitment(U256::from(config.token_id)),
        )
        .await
        {
            Ok(Ok(commitment)) => {
                if commitment.is_active && commitment.secret_hash == *secret_hash.as_byte_array() {
                    info!(
                        seller = %commitment.seller,
                        price_wei = %commitment.price,
                        commit_time = %commitment.commit_time,
                        duration_secs = wait_start.elapsed().as_secs(),
                        "Seller commitment verified successfully"
                    );
                    return Ok(());
                } else if commitment.is_active {
                    warn!("Found commitment but secret hash mismatch");
                }
            }
            Ok(Err(_)) => {
                debug!("No commitment found yet, continuing to wait");
            }
            Err(_) => {
                debug!("Commitment check timed out, retrying");
            }
        }

        sleep(POLL_INTERVAL).await;
    }
}

async fn execute_nft_mint(
    eth_client: &EthClient,
    secret: [u8; 32],
    token_id: u64,
) -> Result<ethers::types::H256> {
    info!("Executing NFT mint with secret reveal");
    if !eth_client.can_mint_now(U256::from(token_id)).await? {
        info!("Waiting for minimum commitment time to pass");

        let wait_start = Instant::now();
        loop {
            if wait_start.elapsed() > Duration::from_secs(300) {
                // 5 minutes max
                return Err(anyhow::anyhow!("Timeout waiting for mint availability"));
            }

            if eth_client.can_mint_now(U256::from(token_id)).await? {
                info!("Minimum commitment time passed, proceeding with mint");
                break;
            }

            sleep(Duration::from_secs(10)).await;
        }
    }

    let mint_tx = eth_client
        .mint_with_secret(secret, U256::from(token_id))
        .await
        .context("Failed to execute NFT mint transaction")?;

    info!(
        tx_hash = %mint_tx,
        secret_revealed = %hex::encode(secret),
        "NFT minted successfully, secret revealed on Ethereum"
    );

    let confirmation_start = Instant::now();
    loop {
        if confirmation_start.elapsed() > MAX_ETH_CONFIRMATION_WAIT {
            warn!("Ethereum confirmation timeout reached");
            break;
        }

        match timeout(
            CONFIRMATION_CHECK_INTERVAL,
            eth_client.get_transaction_info(mint_tx),
        )
        .await
        {
            Ok(Ok(tx_info)) => {
                if let Some(c) = tx_info.confirmations
                    && c > 0
                {
                    info!(
                        confirmations = c,
                        duration_secs = confirmation_start.elapsed().as_secs(),
                        "Ethereum transaction confirmed"
                    );
                    break;
                }
            }
            Ok(Err(e)) => {
                warn!(error = %e, "Failed to check Ethereum transaction status");
            }
            Err(_) => {
                debug!("Transaction status check timed out");
            }
        }

        sleep(CONFIRMATION_CHECK_INTERVAL).await;
    }

    Ok(mint_tx)
}

fn print_seller_instructions(
    config: &AtomicSwapConfig,
    secret_hash: &sha256::Hash,
    htlc_address: &bitcoin::Address,
    buyer_eth_address: ethers::types::Address,
) {
    info!("=== SELLER INSTRUCTIONS ===");
    info!("Bitcoin has been locked in HTLC: {htlc_address}");
    info!("Secret Hash: {}", hex::encode(secret_hash.as_byte_array()));
    info!("To commit the NFT for minting, run:");
    info!("");
    info!("cargo run -- commit-for-mint \\");
    info!("  --seller-eth-key <YOUR_ETH_PRIVATE_KEY> \\");
    info!("  --nft-contract {} \\", config.nft_contract);
    info!(
        "  --secret-hash {} \\",
        hex::encode(secret_hash.as_byte_array())
    );
    info!("  --token-id {} \\", config.token_id);
    info!("  --nft-price {} \\", config.nft_price);
    info!("  --buyer-address {} \\", buyer_eth_address);
    info!("  --metadata-uri '{}'", config.metadata_uri);
    info!("");
    info!("===============================");
}

fn provide_claim_instructions(
    config: &AtomicSwapConfig,
    secret: &[u8; 32],
    secret_hash: &sha256::Hash,
    lock_txid: bitcoin::Txid,
    buyer_pubkey: &PublicKey,
) {
    info!("=== SELLER CLAIM INSTRUCTIONS ===");
    info!("The secret has been revealed on Ethereum");
    info!("Secret: {}", hex::encode(secret));
    info!("To claim the Bitcoin, run:");
    info!("");
    info!("cargo run -- claim-btc \\");
    info!("  --seller-btc-key <YOUR_BTC_PRIVATE_KEY> \\");
    info!("  --buyer-btc-pubkey {} \\", buyer_pubkey);
    info!("  --secret {} \\", hex::encode(secret));
    info!(
        "  --secret-hash {} \\",
        hex::encode(secret_hash.as_byte_array())
    );
    info!("  --lock-txid {} \\", lock_txid);
    info!("  --lock-vout 0 \\");
    info!("  --timeout {}", config.timeout);
    info!("");
    info!("==================================");
}

async fn execute_commit_for_mint(config: CommitForMintConfig) -> Result<()> {
    info!(
        nft_contract = %config.nft_contract,
        token_id = %config.token_id,
        secret_hash = %hex::encode(config.secret_hash),
        "Executing NFT commitment for minting"
    );

    let eth_client = EthClient::new(&config.eth_rpc, &config.seller_eth_key, config.nft_contract)
        .await
        .context("Failed to initialize Ethereum client")?;

    info!(
        seller_address = %eth_client.get_address(),
        "Connected to Ethereum as seller"
    );

    match eth_client.get_commitment(U256::from(config.token_id)).await {
        Ok(commitment) if commitment.is_active => {
            return Err(anyhow::anyhow!(
                "Token {} already has an active commitment from seller {:?}",
                config.token_id,
                commitment.seller
            ));
        }
        Ok(_) => {
            debug!("No existing commitment found, proceeding");
        }
        Err(e) => {
            debug!(error = %e, "Error checking existing commitment, proceeding anyway");
        }
    }

    let tx_hash = eth_client
        .commit_for_mint(
            config.secret_hash,
            U256::from(config.token_id),
            U256::from(config.nft_price),
            config.buyer_address,
            config.metadata_uri.clone(),
        )
        .await
        .context("Failed to commit NFT for minting")?;

    info!(
        tx_hash = %tx_hash,
        token_id = %config.token_id,
        price_wei = %config.nft_price,
        buyer_restriction = ?config.buyer_address,
        metadata_uri = %config.metadata_uri,
        "NFT commitment transaction submitted"
    );

    wait_for_ethereum_confirmation(&eth_client, tx_hash, "commitment").await?;

    info!("NFT commitment completed successfully. Buyer can now reveal secret to mint.");
    Ok(())
}

#[instrument(skip_all)]
async fn execute_claim_bitcoin(config: ClaimBtcConfig) -> Result<()> {
    info!(
        lock_txid = %config.lock_txid,
        lock_vout = %config.lock_vout,
        "Executing Bitcoin claim with revealed secret"
    );

    // Verify secret matches hash
    let computed_hash = sha256::Hash::hash(&config.secret);
    if computed_hash.as_byte_array() != &config.secret_hash {
        return Err(anyhow::anyhow!(
            "Secret verification failed: computed hash {} doesn't match provided hash {}",
            hex::encode(computed_hash.as_byte_array()),
            hex::encode(config.secret_hash)
        ));
    }

    info!(
        secret_verified = true,
        secret_hash = %hex::encode(config.secret_hash),
        "Secret verification passed"
    );

    let seller_keypair = validate_btc_key(&config.seller_btc_key, "seller")?;
    let buyer_pubkey = validate_btc_pubkey(&config.buyer_btc_pubkey, "buyer")?;
    let seller_pubkey = PublicKey::from(seller_keypair.public_key());

    let contract_params = HtlcParams {
        secret_hash: sha256::Hash::from_byte_array(config.secret_hash),
        seller: seller_pubkey,
        buyer: buyer_pubkey,
        timeout: config.timeout,
        network: config.btc_network,
    };
    let btc_contract = BtcContract::new(contract_params);

    info!(
        htlc_address = %btc_contract.address(),
        seller_pubkey = %seller_pubkey,
        buyer_pubkey = %buyer_pubkey,
        "Reconstructed HTLC contract"
    );

    let auth = Auth::UserPass(config.btc_user.clone(), config.btc_pass.clone());
    let btc_client = BtcClient::new(&config.btc_rpc, auth, config.btc_network, seller_keypair)
        .context("Failed to initialize Bitcoin client")?;

    let claim_tx = btc_client
        .claim_funds(
            &btc_contract,
            &config.secret,
            config.lock_txid,
            config.lock_vout,
            config.destination.clone(),
        )
        .await
        .context("Failed to claim Bitcoin funds")?;

    info!(
        claim_txid = %claim_tx,
        from_htlc = %format!("{}:{}", config.lock_txid, config.lock_vout),
        destination = ?config.destination.as_ref().map(|d| d.to_string()).unwrap_or_else(|| "seller wallet".to_string()),
        "Bitcoin claimed successfully"
    );

    info!("Cross-chain atomic swap fully completed - all parties have received their assets");
    Ok(())
}

#[instrument(skip_all)]
async fn execute_monitor(config: MonitorConfig) -> Result<()> {
    info!(
        btc_network = %config.btc_network,
        nft_contract = %config.nft_contract,
        "Starting cross-chain event monitor"
    );

    let auth = Auth::UserPass(config.btc_user.clone(), config.btc_pass.clone());
    let dummy_keypair = Keypair::new(&Secp256k1::new(), &mut rand::thread_rng());

    let btc_client = Arc::new(
        BtcClient::new(&config.btc_rpc, auth, config.btc_network, dummy_keypair)
            .context("Failed to initialize Bitcoin client")?,
    );

    let eth_client = Arc::new(
        EthClient::new(&config.eth_rpc, &config.eth_key, config.nft_contract)
            .await
            .context("Failed to initialize Ethereum client")?,
    );

    info!("Connected to both networks, starting event monitoring");

    let (tx, mut rx) = mpsc::channel::<String>(1000);

    let btc_client_clone = btc_client.clone();
    let tx_btc = tx.clone();
    let btc_monitor = tokio::spawn(
        async move {
            if let Err(e) = btc_client_clone
                .monitor_blocks(move |height| {
                    let _ = tx_btc.try_send(format!("Bitcoin block #{height}"));
                    Ok(())
                })
                .await
            {
                error!(error = %e, "Bitcoin monitoring failed");
            }
        }
        .instrument(tracing::info_span!("btc_monitor")),
    );

    let eth_client_clone = eth_client.clone();
    let tx_eth = tx.clone();
    let eth_monitor = tokio::spawn(
        async move {
            if let Err(e) = eth_client_clone
                .monitor_events(move |event| {
                    let event_str = format_swap_event(&event);
                    let _ = tx_eth.try_send(event_str);
                    Ok(())
                })
                .await
            {
                error!(error = %e, "Ethereum monitoring failed");
            }
        }
        .instrument(tracing::info_span!("eth_monitor")),
    );

    info!("Event monitoring active. Press Ctrl+C to stop.");

    tokio::select! {
        _ = async {
            while let Some(event) = rx.recv().await {
                info!("Event: {}", event);
            }
        } => {}
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received");
        }
    }

    info!("Shutting down monitoring tasks...");
    btc_monitor.abort();
    eth_monitor.abort();

    tokio::time::sleep(Duration::from_millis(100)).await;
    info!("Event monitoring stopped");

    Ok(())
}

async fn wait_for_ethereum_confirmation(
    eth_client: &EthClient,
    tx_hash: ethers::types::H256,
    operation: &str,
) -> Result<()> {
    info!(tx_hash = %tx_hash, operation, "Waiting for Ethereum confirmation");

    let start_time = Instant::now();
    loop {
        if start_time.elapsed() > MAX_ETH_CONFIRMATION_WAIT {
            warn!(
                duration_secs = start_time.elapsed().as_secs(),
                "Ethereum confirmation timeout, but transaction likely successful"
            );
            break;
        }

        match timeout(
            CONFIRMATION_CHECK_INTERVAL,
            eth_client.get_transaction_info(tx_hash),
        )
        .await
        {
            Ok(Ok(tx_info)) => {
                if let Some(c) = tx_info.confirmations
                    && c > 0
                {
                    info!(
                        confirmations = c,
                        duration_secs = start_time.elapsed().as_secs(),
                        operation,
                        "Ethereum transaction confirmed"
                    );
                    return Ok(());
                }
            }
            Ok(Err(e)) => {
                debug!(error = %e, "Failed to check transaction status");
            }
            Err(_) => {
                debug!("Transaction status check timed out");
            }
        }

        sleep(CONFIRMATION_CHECK_INTERVAL).await;
    }

    Ok(())
}

fn format_swap_event(event: &SwapEvent) -> String {
    match event {
        SwapEvent::EthCommitted {
            tx_hash,
            token_id,
            secret_hash,
        } => {
            format!(
                "NFT Committed - Token: {}, Hash: {}, Tx: {}",
                token_id,
                hex::encode(secret_hash),
                tx_hash
            )
        }
        SwapEvent::SecretRevealed {
            tx_hash,
            secret,
            token_id,
        } => {
            format!(
                "Secret Revealed - Token: {}, Secret: {}, Tx: {}",
                token_id,
                hex::encode(secret),
                tx_hash
            )
        }
        SwapEvent::NFTMinted {
            tx_hash,
            token_id,
            owner,
        } => {
            format!(
                "NFT Minted - Token: {}, Owner: {:?}, Tx: {}",
                token_id, owner, tx_hash
            )
        }
        _ => format!("Swap Event: {:?}", event),
    }
}

fn validate_btc_key(key: &str, role: &str) -> Result<Keypair> {
    key.parse::<Keypair>()
        .with_context(|| format!("Invalid Bitcoin private key for {}", role))
}

fn validate_btc_pubkey(key: &str, role: &str) -> Result<PublicKey> {
    key.parse::<PublicKey>()
        .with_context(|| format!("Invalid Bitcoin public key for {}", role))
}

fn decode_hex_hash(hex_str: &str, field_name: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(hex_str).with_context(|| format!("Invalid hex encoding for {}", field_name))?;

    bytes.clone().try_into().map_err(|_| {
        anyhow::anyhow!(
            "Invalid {} length: expected 32 bytes, got {}",
            field_name,
            bytes.len()
        )
    })
}

fn decode_hex_secret(hex_str: &str) -> Result<[u8; 32]> {
    decode_hex_hash(hex_str, "secret")
}

fn parse_btc_address(addr: &str, network: Network) -> Result<bitcoin::Address> {
    let addr = addr
        .parse::<bitcoin::Address<NetworkUnchecked>>()
        .context("Invalid Bitcoin address format")?
        .require_network(network)
        .context("Bitcoin address network mismatch")?;
    Ok(addr)
}

fn parse_network(network: &str) -> Result<Network> {
    match network.to_lowercase().as_str() {
        "mainnet" | "main" => Ok(Network::Bitcoin),
        "testnet" | "test" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" | "reg" => Ok(Network::Regtest),
        _ => Err(anyhow::anyhow!(
            "Invalid network '{}'. Supported: mainnet, testnet, signet, regtest",
            network
        )),
    }
}

#[cfg(test)]
mod tests {
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
