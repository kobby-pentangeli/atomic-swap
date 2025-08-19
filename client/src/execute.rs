use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::{Amount, PublicKey};
use bitcoincore_rpc::Auth;
use btc_htlc::{Contract as BtcContract, HtlcParams};
use ethers::types::{H256, U256};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, timeout};
use tracing::{Instrument, debug, error, info, instrument, warn};

use crate::eth::EthClient;
use crate::types::{
    AtomicSwapConfig, ClaimBtcConfig, CommitForMintConfig, MonitorConfig, SwapEvent,
};

const MAX_BTC_CONFIRMATION_WAIT: Duration = Duration::from_secs(60);
const MAX_ETH_CONFIRMATION_WAIT: Duration = Duration::from_secs(60);
const MAX_COMMITMENT_WAIT: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const CONFIRMATION_CHECK_INTERVAL: Duration = Duration::from_secs(10);

use crate::btc::{BtcClient, utils};
// For demonstration only
const SHARED_SECRET: &[u8] = b"crosschain-secret-mint";

// end-to-end atomic swap
pub async fn atomic_swap(config: AtomicSwapConfig) -> Result<()> {
    info!(
        btc_network = %config.btc_network,
        nft_contract = %config.nft_contract,
        "Initializing cross-chain atomic swap"
    );

    let buyer_keypair = utils::validate_btc_key(&config.buyer_btc_key, "buyer")?;
    let seller_pubkey = utils::validate_btc_pubkey(&config.seller_btc_pubkey, "seller")?;
    let buyer_pubkey = PublicKey::from(buyer_keypair.public_key());

    let secret_hash = btc_htlc::generate_secret_from_preimage(SHARED_SECRET);
    info!(
        secret_hash = %hex::encode(secret_hash),
        "Generated secret hash"
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

    let lock_txid = lock_bitcoin(&btc_client, &btc_contract, config.btc_amount).await?;
    let secret = H256::from_slice(SHARED_SECRET);
    let secret_hash = H256(secret_hash);

    wait_for_seller_commitment(&eth_client, &config, secret_hash, &htlc_address).await?;

    let mint_tx = mint_nft(&eth_client, secret, config.token_id).await?;

    provide_claim_instructions(&config, &secret, &secret_hash, lock_txid, &buyer_pubkey);

    info!(
        lock_txid = %lock_txid,
        mint_tx = %mint_tx,
        "Cross-chain atomic swap completed successfully"
    );

    Ok(())
}

async fn lock_bitcoin(
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

pub async fn commit_for_mint(config: CommitForMintConfig) -> Result<()> {
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
            H256(config.secret_hash),
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

#[instrument(skip_all, fields(token_id = %config.token_id))]
async fn wait_for_seller_commitment(
    eth_client: &EthClient,
    config: &AtomicSwapConfig,
    secret_hash: H256,
    htlc_address: &bitcoin::Address,
) -> Result<()> {
    info!("Waiting for seller NFT commitment on Ethereum");
    provide_commit_instructions(config, secret_hash, htlc_address, eth_client.get_address());

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
                if commitment.is_active && commitment.secret_hash == secret_hash[..] {
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

pub async fn mint_nft(
    eth_client: &EthClient,
    secret: H256,
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

#[instrument(skip_all)]
pub async fn claim_bitcoin(config: ClaimBtcConfig) -> Result<()> {
    info!(
        lock_txid = %config.lock_txid,
        lock_vout = %config.lock_vout,
        "Executing Bitcoin claim with revealed secret"
    );

    // Verify secret matches hash
    let computed_hash = Sha256::digest(config.secret);
    if *computed_hash != config.secret_hash {
        return Err(anyhow::anyhow!(
            "Secret verification failed: computed hash {} doesn't match provided hash {}",
            hex::encode(computed_hash),
            hex::encode(config.secret_hash)
        ));
    }

    info!(
        secret_verified = true,
        secret_hash = %hex::encode(config.secret_hash),
        "Secret verification passed"
    );

    let seller_keypair = utils::validate_btc_key(&config.seller_btc_key, "seller")?;
    let buyer_pubkey = utils::validate_btc_pubkey(&config.buyer_btc_pubkey, "buyer")?;
    let seller_pubkey = PublicKey::from(seller_keypair.public_key());

    let contract_params = HtlcParams {
        secret_hash: config.secret_hash,
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

fn provide_commit_instructions(
    config: &AtomicSwapConfig,
    secret_hash: H256,
    htlc_address: &bitcoin::Address,
    buyer_eth_address: ethers::types::Address,
) {
    info!("=== SELLER INSTRUCTIONS ===");
    info!("Bitcoin has been locked in HTLC: {htlc_address}");
    info!("Secret Hash: {}", hex::encode(secret_hash));
    info!("To commit the NFT for minting, run:");
    info!("");
    info!("cargo run -- commit-for-mint \\");
    info!("  --seller-eth-key <YOUR_ETH_PRIVATE_KEY> \\");
    info!("  --nft-contract {} \\", config.nft_contract);
    info!("  --secret-hash {} \\", hex::encode(secret_hash));
    info!("  --token-id {} \\", config.token_id);
    info!("  --nft-price {} \\", config.nft_price);
    info!("  --buyer-address {} \\", buyer_eth_address);
    info!("  --metadata-uri '{}'", config.metadata_uri);
    info!("");
    info!("===============================");
}

fn provide_claim_instructions(
    config: &AtomicSwapConfig,
    secret: &H256,
    secret_hash: &H256,
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
    info!("  --secret-hash {} \\", hex::encode(secret_hash));
    info!("  --lock-txid {} \\", lock_txid);
    info!("  --lock-vout 0 \\");
    info!("  --timeout {}", config.timeout);
    info!("");
    info!("==================================");
}

#[instrument(skip_all)]
pub async fn monitor(config: MonitorConfig) -> Result<()> {
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
