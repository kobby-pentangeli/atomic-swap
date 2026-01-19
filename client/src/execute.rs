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

use anyhow::{Context, Result, anyhow};
use bitcoin::{Amount, PublicKey};
use bitcoincore_rpc::Auth;
use btc_htlc::{Contract as BtcContract, HtlcParams};
use sha2::{Digest, Sha256};
use tracing::{debug, info, instrument};
use utils::{DEFAULT_SECRETS_DIR, DEFAULT_SECRETS_FILE};

use crate::btc::BtcClient;
use crate::types::{
    CancelCommitArgs, CancelResult, Chain, ClaimBtcArgs, ClaimBtcResult, CommitForMintArgs,
    CommitResult, LockBtcArgs, LockBtcResult, MintResult, MintWithSecretArgs, RefundBtcArgs,
    RefundBtcResult,
};
use crate::{eth, sol, utils};

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

    let secret_file = args
        .secret_output_file
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SECRETS_DIR).join(DEFAULT_SECRETS_FILE));
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
        Chain::Ethereum => eth::commit_for_mint(args).await,
        Chain::Solana => tokio::task::spawn_blocking(move || sol::commit_for_mint(args)).await?,
    }
}

/// Mints an NFT by revealing the secret on the specified chain.
///
/// This is step 3 of the atomic swap. The buyer reveals the secret to mint
/// the NFT. Once the secret is revealed on-chain, the seller can use it to
/// claim the locked Bitcoin.
pub async fn mint_with_secret(args: MintWithSecretArgs) -> Result<MintResult> {
    match args.chain {
        Chain::Ethereum => eth::mint_with_secret(args).await,
        Chain::Solana => tokio::task::spawn_blocking(move || sol::mint_with_secret(args)).await?,
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
        Chain::Ethereum => eth::cancel_commitment(args).await,
        Chain::Solana => tokio::task::spawn_blocking(move || sol::cancel_commitment(args)).await?,
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
