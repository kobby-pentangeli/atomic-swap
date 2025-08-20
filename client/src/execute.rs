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
use tokio::time::sleep;
use tracing::{Instrument, debug, error, info, instrument};

use crate::btc::{BtcClient, utils};
use crate::eth::EthClient;
use crate::types::{
    ClaimBtcConfig, CommitForMintConfig, LockBtcConfig, MintWithSecretConfig, MonitorEventsConfig,
    SwapEvent,
};

// TODO (kobby-pentangeli):
// Supply secret (preimage) as a file from CLI.
pub async fn lock_bitcoin(config: LockBtcConfig) -> Result<()> {
    let buyer_keypair = utils::validate_btc_keypair(&config.buyer_btc_key, "buyer")?;
    let seller_pubkey = utils::validate_btc_pubkey(&config.seller_btc_pubkey, "seller")?;
    let buyer_pubkey = PublicKey::from(buyer_keypair.public_key());

    let r_secret_hex = btc_htlc::generate_random_secret_hex(); // for now!
    let secret_bytes = btc_htlc::hex_to_secret(&r_secret_hex)?;
    let secret_hash = btc_htlc::generate_secret_from_preimage(&secret_bytes);

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

    info!("Initiating Bitcoin lock transaction");

    let amount = Amount::from_sat(config.btc_amount);

    let lock_txid = btc_client
        .lock_funds(&btc_contract, amount)
        .await
        .context("Failed to lock Bitcoin funds")?;

    info!(
        txid = %lock_txid,
        amount_btc = %amount.to_btc(),
        htlc_address = %btc_contract.address(),
        "Bitcoin funds locked successfully"
    );

    info!("Waiting for seller NFT commitment on Ethereum");

    // We log this for the demo
    info!("SECRET (hex): {}", hex::encode(secret_bytes));
    info!("SECRET_HASH: {}", hex::encode(secret_hash));
    info!("LOCK_TXID: {lock_txid}");

    Ok(())
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

    info!("NFT commitment completed successfully. Buyer can now reveal secret to mint.");
    Ok(())
}

pub async fn mint_with_secret(config: MintWithSecretConfig) -> Result<()> {
    info!("Executing NFT mint with secret reveal");

    let eth_client = EthClient::new(&config.eth_rpc, &config.buyer_eth_key, config.nft_contract)
        .await
        .context("Failed to initialize Ethereum client")?;

    let token_id = U256::from(config.token_id);
    let secret = H256(config.secret);

    // DEMO only
    info!("Waiting for minimum commitment time to pass");
    sleep(Duration::from_secs(10)).await;

    // if !eth_client.can_mint_now(token_id).await? {
    //     let wait_start = Instant::now();
    //     loop {
    //         if wait_start.elapsed() > Duration::from_secs(10) {
    //             return Err(anyhow::anyhow!("Timeout waiting for mint availability"));
    //         }

    //         if eth_client.can_mint_now(token_id).await? {
    //             info!("Minimum commitment time passed, proceeding with mint");
    //             break;
    //         }

    //         sleep(Duration::from_secs(3)).await;
    //     }
    // }

    let mint_tx = eth_client
        .mint_with_secret(secret, token_id)
        .await
        .context("Failed to execute NFT mint transaction")?;

    info!(
        tx_hash = %mint_tx,
        secret_revealed = %hex::encode(secret),
        "NFT minted successfully, secret revealed on Ethereum"
    );

    Ok(())
}

#[instrument(skip_all)]
pub async fn claim_bitcoin(config: ClaimBtcConfig) -> Result<()> {
    info!(
        lock_txid = %config.lock_txid,
        lock_vout = %config.lock_vout,
        "Executing Bitcoin claim with revealed secret"
    );

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

    let seller_keypair = utils::validate_btc_keypair(&config.seller_btc_key, "seller")?;
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

#[instrument(skip_all)]
pub async fn monitor_events(config: MonitorEventsConfig) -> Result<()> {
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
                info!("Event: {event}");
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

fn format_swap_event(event: &SwapEvent) -> String {
    match event {
        SwapEvent::EthCommitted {
            tx_hash,
            token_id,
            secret_hash,
        } => {
            format!(
                "NFT Committed - Token: {token_id}, Hash: {}, Tx: {tx_hash}",
                hex::encode(secret_hash)
            )
        }
        SwapEvent::SecretRevealed {
            tx_hash,
            secret,
            token_id,
        } => {
            format!(
                "Secret Revealed - Token: {token_id}, Secret: {}, Tx: {tx_hash}",
                hex::encode(secret)
            )
        }
        SwapEvent::NFTMinted {
            tx_hash,
            token_id,
            owner,
        } => {
            format!("NFT Minted - Token: {token_id}, Owner: {owner:?}, Tx: {tx_hash}")
        }
        _ => format!("Swap Event: {event:?}"),
    }
}
