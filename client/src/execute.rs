//! Implements the cross-chain atomic swap executor.
//!
//! This module orchestrates the atomic swap flow between Bitcoin and NFT chains
//! (Ethereum or Solana). It provides functions for each step of the swap:
//! 1. Lock Bitcoin in an HTLC
//! 2. Commit NFT for minting
//! 3. Mint NFT by revealing the secret
//! 4. Claim Bitcoin using the revealed secret
//!
//! Additionally, it provides recovery mechanisms:
//! - Cancel NFT commitment (seller only before timeout, anyone after timeout)
//! - Refund Bitcoin from HTLC after timeout expiry (buyer only)

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anchor_client::solana_sdk::signature::read_keypair_file;
use anyhow::{Context, Result, anyhow};
use bitcoin::{Amount, PublicKey};
use bitcoincore_rpc::Auth;
use btc_htlc::{Contract as BtcContract, HtlcParams};
use ethers::types::{H256, U256};
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use tracing::{debug, info, instrument};

use crate::btc::BtcClient;
use crate::eth::EthClient;
use crate::sol::SolClient;
use crate::types::{
    CancelCommitArgs, CancelResult, Chain, ClaimBtcArgs, ClaimBtcResult, CommitForMintArgs,
    CommitResult, LockBtcArgs, LockBtcResult, MintResult, MintWithSecretArgs, RefundBtcArgs,
    RefundBtcResult,
};
use crate::utils;

/// Maximum time to wait for mint availability.
const MINT_AVAILABILITY_TIMEOUT: Duration = Duration::from_secs(120);

/// Interval between mint availability checks.
const MINT_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Locks Bitcoin in an HTLC contract.
///
/// This is the first step of the atomic swap. The buyer generates a secret,
/// creates its hash, and locks Bitcoin that can be claimed by the seller
/// only if they know the secret.
pub fn lock_bitcoin(args: LockBtcArgs) -> Result<LockBtcResult> {
    info!("Executing Bitcoin HTLC");

    let buyer_keypair = utils::validate_btc_keypair(&args.buyer_btc_key, "buyer")?;
    let buyer_pubkey = PublicKey::from(buyer_keypair.public_key());
    let seller_pubkey = utils::validate_btc_pubkey(&args.seller_btc_pubkey, "seller")?;

    let r_secret_hex = btc_htlc::generate_random_secret_hex();
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

    debug!(
        htlc_address = %htlc_address,
        seller_pubkey = %seller_pubkey,
        buyer_pubkey = %buyer_pubkey,
        timeout_blocks = %args.timeout,
        "Created HTLC contract"
    );

    let auth = Auth::UserPass(args.btc_user.clone(), args.btc_pass.clone());
    let btc_client = BtcClient::new(&args.btc_rpc, auth, args.btc_network, buyer_keypair)
        .context("Failed to initialize Bitcoin client")?;

    debug!("Initiating Bitcoin lock transaction");
    let amount = Amount::from_sat(args.btc_amount);

    let lock_txid = btc_client
        .lock_funds(&btc_contract, amount)
        .context("Failed to lock Bitcoin funds")?;

    debug!(
        txid = %lock_txid,
        amount_btc = %amount.to_btc(),
        htlc_address = %btc_contract.address(),
        "Bitcoin funds locked successfully"
    );

    debug!(secret = %hex::encode(secret_bytes), "Generated secret");

    let secret_file = args.secret_output_file.unwrap_or_else(|| {
        PathBuf::from(utils::DEFAULT_SECRETS_DIR).join(utils::DEFAULT_SECRETS_FILE)
    });
    utils::write_secret_to_file(&secret_file, &secret_bytes, &secret_hash, &lock_txid)?;
    debug!(path = %secret_file.display(), "Secret written to file");

    Ok(LockBtcResult {
        txid: lock_txid.to_string(),
        htlc_address: htlc_address.to_string(),
        amount_sats: args.btc_amount,
        amount_btc: amount.to_btc(),
        secret_hash: hex::encode(secret_hash),
        secret_file: secret_file.display().to_string(),
        timeout_blocks: args.timeout,
    })
}

/// Commits an NFT for minting on the specified chain.
///
/// This is step 2 of the atomic swap. After the buyer locks Bitcoin, the seller
/// commits to minting an NFT using the same secret hash. The NFT can only be
/// minted by revealing the secret.
pub async fn commit_for_mint(args: CommitForMintArgs) -> Result<CommitResult> {
    match args.chain {
        Chain::Ethereum => commit_for_mint_eth(args).await,
        Chain::Solana => tokio::task::spawn_blocking(move || commit_for_mint_sol(args)).await?,
    }
}

/// Mints an NFT by revealing the secret on the specified chain.
///
/// This is step 3 of the atomic swap. The buyer reveals the secret to mint
/// the NFT. Once the secret is revealed on-chain, the seller can use it to
/// claim the locked Bitcoin.
pub async fn mint_with_secret(args: MintWithSecretArgs) -> Result<MintResult> {
    match args.chain {
        Chain::Ethereum => mint_with_secret_eth(args).await,
        Chain::Solana => tokio::task::spawn_blocking(move || mint_with_secret_sol(args)).await?,
    }
}

/// Claims Bitcoin from the HTLC using the revealed secret.
///
/// This is the final step (4) of the atomic swap. After the buyer reveals the
/// secret on the NFT chain, the seller uses the same secret to claim the
/// locked Bitcoin.
///
/// # Verification
///
/// The function verifies that the provided secret hashes to the expected
/// value before attempting the claim.
#[instrument(skip_all)]
pub fn claim_bitcoin(args: ClaimBtcArgs) -> Result<ClaimBtcResult> {
    debug!(
        lock_txid = %args.lock_txid,
        lock_vout = %args.lock_vout,
        "Executing Bitcoin claim with revealed secret"
    );

    let computed_hash = Sha256::digest(args.secret);
    if *computed_hash != args.secret_hash {
        return Err(anyhow!(
            "Secret verification failed: computed hash {} doesn't match provided hash {}",
            hex::encode(computed_hash),
            hex::encode(args.secret_hash)
        ));
    }

    debug!(
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

    debug!(
        htlc_address = %btc_contract.address(),
        seller_pubkey = %seller_pubkey,
        buyer_pubkey = %buyer_pubkey,
        "Reconstructed HTLC contract"
    );

    let auth = Auth::UserPass(args.btc_user.clone(), args.btc_pass.clone());
    let btc_client = BtcClient::new(&args.btc_rpc, auth, args.btc_network, seller_keypair)
        .context("Failed to initialize Bitcoin client")?;

    let from_htlc = format!("{}:{}", args.lock_txid, args.lock_vout);
    let destination = args
        .destination
        .as_ref()
        .map(|d| d.to_string())
        .unwrap_or_else(|| "seller wallet".to_string());

    let claim_txid = btc_client
        .claim_funds(
            &btc_contract,
            &args.secret,
            args.lock_txid,
            args.lock_vout,
            args.destination,
        )
        .context("Failed to claim Bitcoin funds")?;

    debug!(
        claim_txid = %claim_txid,
        from_htlc = %from_htlc,
        destination = %destination,
        "Bitcoin claimed successfully"
    );

    Ok(ClaimBtcResult {
        txid: claim_txid.to_string(),
        from_htlc,
        destination,
    })
}

/// Cancels an NFT commitment on the specified chain.
///
/// This allows the seller to cancel their commitment before the NFT is minted,
/// or allows anyone to clean up an expired commitment after the timeout period.
/// On Ethereum, only the seller can cancel before timeout; after timeout, anyone
/// can cancel. On Solana, only the seller can cancel.
pub async fn cancel_commitment(args: CancelCommitArgs) -> Result<CancelResult> {
    match args.chain {
        Chain::Ethereum => cancel_commitment_eth(args).await,
        Chain::Solana => tokio::task::spawn_blocking(move || cancel_commitment_sol(args)).await?,
    }
}

/// Refunds Bitcoin to the buyer from an HTLC after timeout expiry.
///
/// This is a recovery mechanism for the buyer when the swap fails to complete.
/// If the seller never claims the Bitcoin (e.g., the buyer never minted the NFT
/// or the swap was abandoned), the buyer can reclaim their locked funds after
/// the timeout period has passed.
///
/// # Prerequisites
///
/// - The HTLC timeout (specified during lock) must have expired
/// - The secret file from the original lock transaction must be available
/// - The funds must not have been claimed by the seller
///
/// # Security
///
/// Only the buyer (who locked the funds) can execute this refund, as it
/// requires the buyer's private key to sign the timeout spending path.
#[instrument(skip_all)]
pub fn refund_bitcoin(args: RefundBtcArgs) -> Result<RefundBtcResult> {
    debug!("Refunding Bitcoin from HTLC (timeout expiry)");

    let buyer_keypair = utils::validate_btc_keypair(&args.buyer_btc_key, "buyer")?;
    let buyer_pubkey = PublicKey::from(buyer_keypair.public_key());
    let seller_pubkey = utils::validate_btc_pubkey(&args.seller_btc_pubkey, "seller")?;

    let (_, secret_hash, lock_txid) = utils::parse_secret_file(&args.secret_file)?;

    let contract_params = HtlcParams {
        secret_hash,
        seller: seller_pubkey,
        buyer: buyer_pubkey,
        timeout: args.timeout,
        network: args.btc_network,
    };
    let btc_contract = BtcContract::new(contract_params);

    debug!(
        htlc_address = %btc_contract.address(),
        buyer_pubkey = %buyer_pubkey,
        seller_pubkey = %seller_pubkey,
        "Reconstructed HTLC contract"
    );

    let auth = Auth::UserPass(args.btc_user.clone(), args.btc_pass.clone());
    let btc_client = BtcClient::new(&args.btc_rpc, auth, args.btc_network, buyer_keypair)
        .context("Failed to initialize Bitcoin client")?;

    let from_htlc = format!("{}:{}", lock_txid, args.lock_vout);
    let destination = args
        .destination
        .as_ref()
        .map(|d| d.to_string())
        .unwrap_or_else(|| "buyer wallet".to_string());

    let refund_txid = btc_client
        .refund_timeout(&btc_contract, lock_txid, args.lock_vout, args.destination)
        .context("Failed to claim Bitcoin funds")?;

    debug!(
        refund_txid = %refund_txid,
        from_htlc = %from_htlc,
        destination = %destination,
        "Bitcoin refunded successfully"
    );

    Ok(RefundBtcResult {
        txid: refund_txid.to_string(),
        from_htlc,
        destination,
    })
}

/// Commits an NFT for minting on Ethereum.
async fn commit_for_mint_eth(args: CommitForMintArgs) -> Result<CommitResult> {
    debug!("Executing NFT commitment for minting");

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

    debug!(
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

    debug!(
        tx_hash = %tx_hash,
        token_id = %token_id,
        price_wei = %nft_price,
        metadata_uri = %metadata_uri,
        "NFT commitment transaction submitted"
    );

    Ok(CommitResult {
        chain: args.chain.as_ref().to_string(),
        tx_id: format!("{tx_hash:?}"),
        token_id,
        price: format!("{nft_price} wei"),
        metadata_uri,
    })
}

/// Commits an NFT for minting on Solana.
fn commit_for_mint_sol(args: CommitForMintArgs) -> Result<CommitResult> {
    debug!("Executing Solana NFT commitment for minting");

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
        debug!("Program not initialized, attempting to initialize...");
        let sig = client
            .initialize()
            .context("Failed to initialize Solana program")?;
        debug!(signature = %sig, "Program initialized successfully");
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

    debug!(
        signature = %sig,
        token_id = %token_id,
        price_lamports = %nft_price,
        name = %name,
        symbol = %symbol,
        metadata_uri = %metadata_uri,
        "Solana NFT commitment transaction submitted"
    );

    Ok(CommitResult {
        chain: args.chain.as_ref().to_string(),
        tx_id: sig.to_string(),
        token_id,
        price: format!("{nft_price} lamports"),
        metadata_uri,
    })
}

/// Mints an NFT on Ethereum by revealing the secret.
///
/// Waits for the minimum commitment time to pass before attempting to mint.
/// The revealed secret can then be used by the seller to claim the locked Bitcoin.
async fn mint_with_secret_eth(args: MintWithSecretArgs) -> Result<MintResult> {
    debug!("Executing NFT mint with secret reveal");

    let rpc_url = args.eth_rpc.as_ref().unwrap();
    let contract_addr = args.nft_contract.as_ref().unwrap();
    let token_id = args.token_id;
    let private_key = args.buyer_eth_key.as_ref().unwrap();
    let secret = args.secret;

    let client = EthClient::new(rpc_url, private_key, *contract_addr)
        .await
        .context("Failed to initialize Ethereum client")?;

    let token_id_u256 = U256::from(token_id);
    let secret_h256 = H256(secret);

    if !client.can_mint_now(token_id_u256).await? {
        debug!("Waiting for minimum commitment time to pass");
        let wait_start = Instant::now();
        loop {
            if wait_start.elapsed() > MINT_AVAILABILITY_TIMEOUT {
                return Err(anyhow!(
                    "Timeout waiting for mint availability after {:?}",
                    MINT_AVAILABILITY_TIMEOUT
                ));
            }

            if client.can_mint_now(token_id_u256).await? {
                debug!("Minimum commitment time passed, proceeding with mint");
                break;
            }

            debug!("Mint not yet available, waiting {:?}", MINT_CHECK_INTERVAL);
            sleep(MINT_CHECK_INTERVAL).await;
        }
    }

    let tx_hash = client
        .mint_with_secret(secret_h256, token_id_u256)
        .await
        .context("Failed to execute NFT mint transaction")?;

    debug!(
        tx_hash = %tx_hash,
        secret_revealed = %hex::encode(secret),
        "NFT minted successfully, secret revealed on Ethereum"
    );

    Ok(MintResult {
        chain: args.chain.as_ref().to_string(),
        tx_id: format!("{tx_hash:?}"),
        token_id,
        secret_revealed: hex::encode(secret),
    })
}

/// Mints an NFT on Solana by revealing the secret.
fn mint_with_secret_sol(args: MintWithSecretArgs) -> Result<MintResult> {
    debug!("Executing Solana NFT mint with secret reveal");

    let rpc_url = args.sol_rpc.as_ref().unwrap();
    let ws_url = args.sol_ws.as_ref().unwrap();
    let program_id = args.program_id.as_ref().unwrap();
    let keypair_path = args.buyer_sol_keypair.as_ref().unwrap();
    let payer = read_keypair_file(keypair_path).map_err(|e| anyhow!("{e}"))?;

    let client = SolClient::new(payer, program_id, rpc_url, ws_url)
        .context("Failed to initialize Solana client")?;

    debug!(
        buyer_address = %client.pubkey(),
        "Connected to Solana as buyer"
    );

    let token_id = args.token_id;
    let secret = args.secret;

    let sig = client
        .mint_with_secret(secret, token_id)
        .context("Failed to execute Solana NFT mint transaction")?;

    debug!(
        signature = %sig,
        secret_revealed = %hex::encode(secret),
        token_id = %token_id,
        "Solana NFT minted successfully, secret revealed"
    );

    Ok(MintResult {
        chain: args.chain.as_ref().to_string(),
        tx_id: sig.to_string(),
        token_id,
        secret_revealed: hex::encode(secret),
    })
}

/// Cancels an NFT commitment on Ethereum.
///
/// Only the seller can cancel before the commitment timeout. After the timeout
/// has passed, anyone can cancel the commitment to clean up expired state.
async fn cancel_commitment_eth(args: CancelCommitArgs) -> Result<CancelResult> {
    debug!("Executing Ethereum NFT commitment cancellation");

    let rpc_url = args.eth_rpc.as_ref().unwrap();
    let contract_addr = args.nft_contract.as_ref().unwrap();
    let private_key = args.caller_eth_key.as_ref().unwrap();
    let token_id = args.token_id;

    let client = EthClient::new(rpc_url, private_key, *contract_addr)
        .await
        .context("Failed to initialize Ethereum client")?;

    debug!(
        caller_address = %client.get_address(),
        token_id = %token_id,
        "Connected to Ethereum, attempting to cancel commitment"
    );

    let tx_hash = client
        .cancel_commitment(U256::from(token_id))
        .await
        .context("Failed to cancel commitment")?;

    debug!(
        tx_hash = %tx_hash,
        token_id = %token_id,
        "Commitment cancelled successfully"
    );

    Ok(CancelResult {
        chain: args.chain.as_ref().to_string(),
        tx_id: format!("{tx_hash:?}"),
        token_id,
    })
}

/// Cancels an NFT commitment on Solana.
///
/// Only the seller who created the commitment can cancel it. The commitment
/// must not have been used (NFT not yet minted).
fn cancel_commitment_sol(args: CancelCommitArgs) -> Result<CancelResult> {
    debug!("Executing Solana NFT commitment cancellation");

    let rpc_url = args.sol_rpc.as_ref().unwrap();
    let ws_url = args.sol_ws.as_ref().unwrap();
    let program_id = args.program_id.as_ref().unwrap();
    let keypair_path = args.caller_sol_keypair.as_ref().unwrap();
    let token_id = args.token_id;

    let payer = read_keypair_file(keypair_path).map_err(|e| anyhow!("{e}"))?;

    let client = SolClient::new(payer, program_id, rpc_url, ws_url)
        .context("Failed to initialize Solana client")?;

    debug!(
        caller_address = %client.pubkey(),
        token_id = %token_id,
        "Connected to Solana, attempting to cancel commitment"
    );

    let sig = client
        .cancel_commitment(token_id)
        .context("Failed to cancel Solana commitment")?;

    debug!(
        signature = %sig,
        token_id = %token_id,
        "Solana commitment cancelled successfully"
    );

    Ok(CancelResult {
        chain: args.chain.as_ref().to_string(),
        tx_id: sig.to_string(),
        token_id,
    })
}
