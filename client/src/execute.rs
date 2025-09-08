use std::time::Duration;

use anchor_client::solana_sdk::signature::read_keypair_file;
use anyhow::{Context, Result, anyhow};
use bitcoin::{Amount, PublicKey};
use bitcoincore_rpc::Auth;
use btc_htlc::{Contract as BtcContract, HtlcParams};
use ethers::types::{H256, U256};
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use tracing::{debug, info, instrument};

use crate::btc::{BtcClient, utils};
use crate::eth::EthClient;
use crate::sol::SolClient;
use crate::types::{Chain, ClaimBtcArgs, CommitForMintArgs, LockBtcArgs, MintWithSecretArgs};

// TODO (kobby-pentangeli):
// Supply secret (preimage) as a file from CLI.
pub fn lock_bitcoin(args: LockBtcArgs) -> Result<()> {
    info!("Executing Bitcoin HTLC");

    let buyer_keypair = utils::validate_btc_keypair(&args.buyer_btc_key, "buyer")?;
    let seller_pubkey = utils::validate_btc_pubkey(&args.seller_btc_pubkey, "seller")?;
    let buyer_pubkey = PublicKey::from(buyer_keypair.public_key());

    let r_secret_hex = btc_htlc::generate_random_secret_hex(); // for now!
    let secret_bytes = btc_htlc::hex_to_secret(&r_secret_hex)?;
    let secret_hash = btc_htlc::hash_secret(&secret_bytes);

    let contract_params = HtlcParams {
        secret_hash,
        seller: seller_pubkey,
        buyer: buyer_pubkey,
        timeout: args.timeout,
        network: args.btc_network,
    };
    let btc_contract = BtcContract::new(contract_params);
    let htlc_address = btc_contract.address();

    info!(
        htlc_address = %htlc_address,
        seller_pubkey = %seller_pubkey,
        buyer_pubkey = %buyer_pubkey,
        timeout_blocks = %args.timeout,
        "Created HTLC contract"
    );

    let auth = Auth::UserPass(args.btc_user.clone(), args.btc_pass.clone());
    let btc_client = BtcClient::new(&args.btc_rpc, auth, args.btc_network, buyer_keypair)
        .context("Failed to initialize Bitcoin client")?;

    info!("Initiating Bitcoin lock transaction");

    let amount = Amount::from_sat(args.btc_amount);

    let lock_txid = btc_client
        .lock_funds(&btc_contract, amount)
        .context("Failed to lock Bitcoin funds")?;

    info!(
        txid = %lock_txid,
        amount_btc = %amount.to_btc(),
        htlc_address = %btc_contract.address(),
        "Bitcoin funds locked successfully"
    );

    info!("Waiting for seller NFT commitment");

    // We log this for the demo
    info!("SECRET (hex): {}", hex::encode(secret_bytes));
    info!("SECRET_HASH: {}", hex::encode(secret_hash));
    info!("LOCK_TXID: {lock_txid}");

    Ok(())
}

pub async fn commit_for_mint(args: CommitForMintArgs) -> Result<()> {
    match args.chain {
        Chain::Ethereum => commit_for_mint_eth(args).await,
        Chain::Solana => tokio::task::spawn_blocking(move || commit_for_mint_sol(args)).await?,
    }
}

pub async fn mint_with_secret(args: MintWithSecretArgs) -> Result<()> {
    match args.chain {
        Chain::Ethereum => mint_with_secret_eth(args).await,
        Chain::Solana => tokio::task::spawn_blocking(move || mint_with_secret_sol(args)).await?,
    }
}

async fn commit_for_mint_eth(args: CommitForMintArgs) -> Result<()> {
    info!("Executing NFT commitment for minting");

    let rpc_url = args.eth_rpc.as_ref().unwrap();
    let contract_addr = args.nft_contract.as_ref().unwrap();
    let token_id = args.token_id;
    let nft_price = args.nft_price;
    let metadata_uri = args.metadata_uri;
    let secret_hash = args.secret_hash;
    let private_key = args.seller_eth_key.as_ref().unwrap();

    let client = EthClient::new(rpc_url, private_key, *contract_addr)
        .await
        .context("Failed to initialize Ethereum client")?;

    info!(
        seller_address = %client.get_address(),
        "Connected to Ethereum as seller"
    );

    match client.get_commitment(U256::from(token_id)).await {
        Ok(commitment) if commitment.is_active => {
            return Err(anyhow!(
                "Token {token_id} already has an active commitment from seller {:?}",
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

    let tx_hash = client
        .commit_for_mint(
            H256(secret_hash),
            U256::from(token_id),
            U256::from(nft_price),
            args.buyer_address,
            metadata_uri.clone(),
        )
        .await
        .context("Failed to commit NFT for minting")?;

    info!(
        tx_hash = %tx_hash,
        token_id = %token_id,
        price_wei = %nft_price,
        buyer_restriction = ?args.buyer_address,
        metadata_uri = %metadata_uri,
        "NFT commitment transaction submitted"
    );

    info!("NFT commitment completed successfully. Buyer can now reveal secret to mint.");
    Ok(())
}

fn commit_for_mint_sol(args: CommitForMintArgs) -> Result<()> {
    info!("Executing Solana NFT commitment for minting");

    let program_id = args.program_id.as_ref().unwrap();
    let keypair_path = args.seller_sol_keypair.as_ref().unwrap();
    let rpc_url = args.sol_rpc.as_ref().unwrap();
    let ws_url = args.sol_ws.as_ref().unwrap();

    let token_id = args.token_id;
    let secret_hash = args.secret_hash;
    let name = args.name.as_ref().unwrap();
    let symbol = args.symbol.as_ref().unwrap();
    let metadata_uri = args.metadata_uri;
    let nft_price = args.nft_price;

    let payer = read_keypair_file(keypair_path).map_err(|e| anyhow!("{e}"))?;

    let client = SolClient::new(payer, program_id, rpc_url, ws_url)
        .context("Failed to initialize Solana client")?;

    if !client.is_initialized() {
        info!("Program not initialized, attempting to initialize...");
        let sig = client
            .initialize()
            .context("Failed to initialize Solana program")?;
        info!(signature = %sig, "Program initialized successfully");
    }

    match client.get_commitment(token_id) {
        Ok(commitment) if !commitment.is_used => {
            return Err(anyhow!(
                "Token {token_id} already has an active commitment from {}",
                commitment.seller
            ));
        }
        Ok(_) => {
            debug!("Commitment exists but is used, proceeding");
        }
        Err(e) => {
            debug!(error = %e, "No existing commitment found, proceeding");
        }
    }

    let sig = client
        .commit_for_mint(
            secret_hash,
            token_id,
            nft_price,
            name.clone(),
            symbol.clone(),
            metadata_uri.clone(),
        )
        .context("Failed to commit NFT for minting on Solana")?;

    info!(
        signature = %sig,
        token_id = %token_id,
        price_lamports = %nft_price,
        name = %name,
        symbol = %symbol,
        metadata_uri = %metadata_uri,
        "Solana NFT commitment transaction submitted"
    );

    info!("Solana NFT commitment completed successfully. Buyer can now reveal secret to mint.");
    Ok(())
}

async fn mint_with_secret_eth(args: MintWithSecretArgs) -> Result<()> {
    info!("Executing NFT mint with secret reveal");

    let rpc_url = args.eth_rpc.as_ref().unwrap();
    let contract_addr = args.nft_contract.as_ref().unwrap();
    let token_id = args.token_id;
    let private_key = args.buyer_eth_key.as_ref().unwrap();
    let secret = args.secret;

    let client = EthClient::new(rpc_url, private_key, *contract_addr)
        .await
        .context("Failed to initialize Ethereum client")?;

    let token_id = U256::from(token_id);
    let secret = H256(secret);

    // DEMO only
    info!("Waiting for minimum commitment time to pass");
    sleep(Duration::from_secs(10)).await;

    // if !client.can_mint_now(token_id).await? {
    //     let wait_start = Instant::now();
    //     loop {
    //         if wait_start.elapsed() > Duration::from_secs(10) {
    //             return Err(anyhow!("Timeout waiting for mint availability"));
    //         }

    //         if client.can_mint_now(token_id).await? {
    //             info!("Minimum commitment time passed, proceeding with mint");
    //             break;
    //         }

    //         sleep(Duration::from_secs(3)).await;
    //     }
    // }

    let txid = client
        .mint_with_secret(secret, token_id)
        .await
        .context("Failed to execute NFT mint transaction")?;

    info!(
        tx_hash = %txid,
        secret_revealed = %hex::encode(secret),
        "NFT minted successfully, secret revealed on Ethereum"
    );

    Ok(())
}

fn mint_with_secret_sol(args: MintWithSecretArgs) -> Result<()> {
    info!("Executing Solana NFT mint with secret reveal");

    let rpc_url = args.sol_rpc.as_ref().unwrap();
    let ws_url = args.sol_ws.as_ref().unwrap();
    let program_id = args.program_id.as_ref().unwrap();
    let keypair_path = args.buyer_sol_keypair.as_ref().unwrap();
    let payer = read_keypair_file(keypair_path).map_err(|e| anyhow::anyhow!("{e}"))?;

    let client = SolClient::new(payer, program_id, rpc_url, ws_url)
        .context("Failed to initialize Solana client")?;

    info!(
        buyer_address = %client.pubkey(),
        "Connected to Solana as buyer"
    );

    let sig = client
        .mint_with_secret(args.secret, args.token_id)
        .context("Failed to execute Solana NFT mint transaction")?;

    info!(
        signature = %sig,
        secret_revealed = %hex::encode(args.secret),
        token_id = %args.token_id,
        "Solana NFT minted successfully, secret revealed"
    );

    Ok(())
}

#[instrument(skip_all)]
pub fn claim_bitcoin(args: ClaimBtcArgs) -> Result<()> {
    info!(
        lock_txid = %args.lock_txid,
        lock_vout = %args.lock_vout,
        "Executing Bitcoin claim with revealed secret"
    );

    let computed_hash = Sha256::digest(args.secret);
    if *computed_hash != args.secret_hash {
        return Err(anyhow::anyhow!(
            "Secret verification failed: computed hash {} doesn't match provided hash {}",
            hex::encode(computed_hash),
            hex::encode(args.secret_hash)
        ));
    }

    info!(
        secret_verified = true,
        secret_hash = %hex::encode(args.secret_hash),
        "Secret verification passed"
    );

    let seller_keypair = utils::validate_btc_keypair(&args.seller_btc_key, "seller")?;
    let buyer_pubkey = utils::validate_btc_pubkey(&args.buyer_btc_pubkey, "buyer")?;
    let seller_pubkey = PublicKey::from(seller_keypair.public_key());

    let contract_params = HtlcParams {
        secret_hash: args.secret_hash,
        seller: seller_pubkey,
        buyer: buyer_pubkey,
        timeout: args.timeout,
        network: args.btc_network,
    };
    let btc_contract = BtcContract::new(contract_params);

    info!(
        htlc_address = %btc_contract.address(),
        seller_pubkey = %seller_pubkey,
        buyer_pubkey = %buyer_pubkey,
        "Reconstructed HTLC contract"
    );

    let auth = Auth::UserPass(args.btc_user.clone(), args.btc_pass.clone());
    let btc_client = BtcClient::new(&args.btc_rpc, auth, args.btc_network, seller_keypair)
        .context("Failed to initialize Bitcoin client")?;

    let claim_tx = btc_client
        .claim_funds(
            &btc_contract,
            &args.secret,
            args.lock_txid,
            args.lock_vout,
            args.destination.clone(),
        )
        .context("Failed to claim Bitcoin funds")?;

    info!(
        claim_txid = %claim_tx,
        from_htlc = %format!("{}:{}", args.lock_txid, args.lock_vout),
        destination = ?args.destination.as_ref().map(|d| d.to_string()).unwrap_or_else(|| "seller wallet".to_string()),
        "Bitcoin claimed successfully"
    );

    info!("Cross-chain atomic swap fully completed. All parties have received their assets");
    Ok(())
}
