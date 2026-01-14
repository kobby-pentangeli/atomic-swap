//! Implements the cross-chain atomic swap executor.
//!
//! This module orchestrates the atomic swap flow between Bitcoin and NFT chains
//! (Ethereum or Solana). It provides functions for each step of the swap:
//! 1. Lock Bitcoin in an HTLC
//! 2. Commit NFT for minting
//! 3. Mint NFT by revealing the secret
//! 4. Claim Bitcoin using the revealed secret
//!
//! Additionally, it provides a cancellation mechanism:
//! - Cancel NFT commitment (seller only before timeout, anyone after timeout)

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anchor_client::solana_sdk::signature::read_keypair_file;
use anyhow::{Context, Result, anyhow};
use bitcoin::{Amount, PublicKey, Txid};
use bitcoincore_rpc::Auth;
use btc_htlc::{Contract as BtcContract, HtlcParams};
use ethers::types::{H256, U256};
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use tracing::{debug, info, instrument};

use crate::btc::{BtcClient, utils};
use crate::eth::EthClient;
use crate::sol::SolClient;
use crate::types::{
    CancelCommitArgs, Chain, ClaimBtcArgs, CommitForMintArgs, LockBtcArgs, MintWithSecretArgs,
};

/// Maximum time to wait for mint availability.
const MINT_AVAILABILITY_TIMEOUT: Duration = Duration::from_secs(120);

/// Interval between mint availability checks.
const MINT_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Default directory for swap secrets.
const DEFAULT_SECRETS_DIR: &str = ".swap/secrets";

/// Default secret file name.
const DEFAULT_SECRET_FILE: &str = "swap.secret";

/// Locks Bitcoin in an HTLC contract.
///
/// This is the first step of the atomic swap. The buyer generates a secret,
/// creates its hash, and locks Bitcoin that can be claimed by the seller
/// only if they know the secret.
pub fn lock_bitcoin(args: LockBtcArgs) -> Result<()> {
    info!("Executing Bitcoin HTLC");

    let buyer_keypair = utils::validate_btc_keypair(&args.buyer_btc_key, "buyer")?;
    let seller_pubkey = utils::validate_btc_pubkey(&args.seller_btc_pubkey, "seller")?;
    let buyer_pubkey = PublicKey::from(buyer_keypair.public_key());

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

    debug!(secret = %hex::encode(secret_bytes), "Generated secret");
    info!("SECRET_HASH: {}", hex::encode(secret_hash));
    info!("LOCK_TXID: {lock_txid}");

    let secret_file = args
        .secret_output_file
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SECRETS_DIR).join(DEFAULT_SECRET_FILE));
    write_secret_to_file(&secret_file, &secret_bytes, &secret_hash, &lock_txid)?;
    info!(path = %secret_file.display(), "Secret written to file");

    Ok(())
}

/// Commits an NFT for minting on the specified chain.
///
/// This is step 2 of the atomic swap. After the buyer locks Bitcoin, the seller
/// commits to minting an NFT using the same secret hash. The NFT can only be
/// minted by revealing the secret.
pub async fn commit_for_mint(args: CommitForMintArgs) -> Result<()> {
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
pub async fn mint_with_secret(args: MintWithSecretArgs) -> Result<()> {
    match args.chain {
        Chain::Ethereum => mint_with_secret_eth(args).await,
        Chain::Solana => tokio::task::spawn_blocking(move || mint_with_secret_sol(args)).await?,
    }
}

/// Cancels an NFT commitment on the specified chain.
///
/// This allows the seller to cancel their commitment before the NFT is minted,
/// or allows anyone to clean up an expired commitment after the timeout period.
/// On Ethereum, only the seller can cancel before timeout; after timeout, anyone
/// can cancel. On Solana, only the seller can cancel.
pub async fn cancel_commitment(args: CancelCommitArgs) -> Result<()> {
    match args.chain {
        Chain::Ethereum => cancel_commitment_eth(args).await,
        Chain::Solana => tokio::task::spawn_blocking(move || cancel_commitment_sol(args)).await?,
    }
}

/// Commits an NFT for minting on Ethereum.
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

/// Commits an NFT for minting on Solana.
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

/// Mints an NFT on Ethereum by revealing the secret.
///
/// Waits for the minimum commitment time to pass before attempting to mint.
/// The revealed secret can then be used by the seller to claim the locked Bitcoin.
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

    if !client.can_mint_now(token_id).await? {
        info!("Waiting for minimum commitment time to pass");
        let wait_start = Instant::now();
        loop {
            if wait_start.elapsed() > MINT_AVAILABILITY_TIMEOUT {
                return Err(anyhow!(
                    "Timeout waiting for mint availability after {:?}",
                    MINT_AVAILABILITY_TIMEOUT
                ));
            }

            if client.can_mint_now(token_id).await? {
                info!("Minimum commitment time passed, proceeding with mint");
                break;
            }

            debug!("Mint not yet available, waiting {:?}", MINT_CHECK_INTERVAL);
            sleep(MINT_CHECK_INTERVAL).await;
        }
    }

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

/// Mints an NFT on Solana by revealing the secret.
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

/// Cancels an NFT commitment on Ethereum.
///
/// Only the seller can cancel before the commitment timeout. After the timeout
/// has passed, anyone can cancel the commitment to clean up expired state.
async fn cancel_commitment_eth(args: CancelCommitArgs) -> Result<()> {
    info!("Executing Ethereum NFT commitment cancellation");

    let rpc_url = args.eth_rpc.as_ref().unwrap();
    let contract_addr = args.nft_contract.as_ref().unwrap();
    let private_key = args.caller_eth_key.as_ref().unwrap();
    let token_id = args.token_id;

    let client = EthClient::new(rpc_url, private_key, *contract_addr)
        .await
        .context("Failed to initialize Ethereum client")?;

    info!(
        caller_address = %client.get_address(),
        token_id = %token_id,
        "Connected to Ethereum, attempting to cancel commitment"
    );

    let tx_hash = client
        .cancel_commitment(U256::from(token_id))
        .await
        .context("Failed to cancel commitment")?;

    info!(
        tx_hash = %tx_hash,
        token_id = %token_id,
        "Commitment cancelled successfully"
    );

    Ok(())
}

/// Cancels an NFT commitment on Solana.
///
/// Only the seller who created the commitment can cancel it. The commitment
/// must not have been used (NFT not yet minted).
fn cancel_commitment_sol(args: CancelCommitArgs) -> Result<()> {
    info!("Executing Solana NFT commitment cancellation");

    let rpc_url = args.sol_rpc.as_ref().unwrap();
    let ws_url = args.sol_ws.as_ref().unwrap();
    let program_id = args.program_id.as_ref().unwrap();
    let keypair_path = args.caller_sol_keypair.as_ref().unwrap();
    let token_id = args.token_id;

    let payer = read_keypair_file(keypair_path).map_err(|e| anyhow!("{e}"))?;

    let client = SolClient::new(payer, program_id, rpc_url, ws_url)
        .context("Failed to initialize Solana client")?;

    info!(
        caller_address = %client.pubkey(),
        token_id = %token_id,
        "Connected to Solana, attempting to cancel commitment"
    );

    let sig = client
        .cancel_commitment(token_id)
        .context("Failed to cancel Solana commitment")?;

    info!(
        signature = %sig,
        token_id = %token_id,
        "Solana commitment cancelled successfully"
    );

    Ok(())
}

/// Claims Bitcoin from the HTLC using the revealed secret.
///
/// This is the final step of the atomic swap. After the buyer reveals the
/// secret on the NFT chain, the seller uses the same secret to claim the
/// locked Bitcoin.
///
/// # Verification
///
/// The function verifies that the provided secret hashes to the expected
/// value before attempting the claim.
#[instrument(skip_all)]
pub fn claim_bitcoin(args: ClaimBtcArgs) -> Result<()> {
    info!(
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

    let claim_txid = btc_client
        .claim_funds(
            &btc_contract,
            &args.secret,
            args.lock_txid,
            args.lock_vout,
            args.destination.clone(),
        )
        .context("Failed to claim Bitcoin funds")?;

    info!(
        claim_txid = %claim_txid,
        from_htlc = %format!("{}:{}", args.lock_txid, args.lock_vout),
        destination = ?args.destination.as_ref().map(|d| d.to_string()).unwrap_or_else(|| "seller wallet".to_string()),
        "Bitcoin claimed successfully"
    );

    info!("Cross-chain atomic swap fully completed. All parties have received their assets");
    Ok(())
}

/// Writes the generated secret and related data to a file with restricted permissions.
///
/// The file is created with mode 0600 (owner read/write only) to protect the secret.
/// The format is a simple key-value text file for easy parsing.
fn write_secret_to_file(
    path: &Path,
    secret: &[u8; 32],
    secret_hash: &[u8; 32],
    lock_txid: &Txid,
) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    // Create file with restricted permissions (Unix only)
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("Failed to create secret file: {}", path.display()))?;

    writeln!(file, "# Atomic Swap Secret File")?;
    writeln!(file, "SECRET={}", hex::encode(secret))?;
    writeln!(file, "SECRET_HASH={}", hex::encode(secret_hash))?;
    writeln!(file, "LOCK_TXID={lock_txid}")?;

    Ok(())
}
