//! Ethereum RPC client for the NFTSecretMint contract.
//!
//! Provides an interface for interacting with the NFTSecretMint smart
//! contract on Ethereum. It supports the full NFT commitment lifecycle:
//!
//! - Creating commitments for NFT minting
//! - Minting NFTs by revealing the secret preimage
//! - Cancelling commitments (by seller or after timeout)
//! - Querying commitment status and validity

use std::time::Instant;

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, B256, TxHash, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::{Context, Result, anyhow};
use tokio::time::sleep;
use tracing::{debug, info};
use url::Url;

use crate::types::{
    CancelResult, Chain, CommitResult, EthCancelArgs, EthCommitArgs, EthMintArgs, MintResult,
};
use crate::utils::{MINT_AVAILABILITY_TIMEOUT, MINT_CHECK_INTERVAL};

sol! {
    #[sol(rpc)]
    NFTSecretMint,
    "../agent/eth/abi/NFTSecretMint.json"
}

/// Window after commitment within which the secret may be revealed, mirroring
/// the contract's `COMMITMENT_TIMEOUT`; used only for the client-side cancel
/// pre-check (the contract enforces the authoritative value).
const COMMITMENT_TIMEOUT_SECS: u64 = 24 * 60 * 60;

/// Ethereum client for NFTSecretMint contract interactions.
///
/// Wraps a wallet-signing provider and the deployed contract address. Gas,
/// nonce, and chain-id are filled by the provider's recommended fillers.
pub struct EthClient {
    provider: DynProvider,
    contract_addr: Address,
    caller: Address,
}

impl EthClient {
    /// Creates a new Ethereum client connected to the NFTSecretMint contract.
    ///
    /// # Arguments
    ///
    /// * `rpc_url` - Ethereum JSON-RPC endpoint URL.
    /// * `private_key` - Hex-encoded private key for signing transactions.
    /// * `contract_addr` - Address of the deployed NFTSecretMint contract.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL or key cannot be parsed or the node is
    /// unreachable.
    pub async fn new(rpc_url: &str, private_key: &str, contract_addr: Address) -> Result<Self> {
        let url: Url = rpc_url.parse().context("Invalid Ethereum RPC URL")?;
        let signer: PrivateKeySigner =
            private_key.parse().context("Failed to parse private key")?;
        let caller = signer.address();

        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer))
            .connect_http(url)
            .erased();

        let chain_id = provider
            .get_chain_id()
            .await
            .context("Failed to connect to Ethereum node")?;
        info!(chain_id, "Connected to Ethereum");

        Ok(Self {
            provider,
            contract_addr,
            caller,
        })
    }

    /// Binds the contract to the wallet-signing provider for a single call.
    fn contract(&self) -> NFTSecretMint::NFTSecretMintInstance<DynProvider> {
        NFTSecretMint::new(self.contract_addr, self.provider.clone())
    }

    /// Creates a commitment for NFT minting.
    ///
    /// The seller calls this to commit to minting an NFT. The commitment
    /// includes a secret hash that must be revealed to complete the mint.
    ///
    /// # Arguments
    ///
    /// * `secret_hash` - SHA-256 hash of the secret preimage.
    /// * `token_id` - Unique identifier for the NFT.
    /// * `price` - Price in wei required to mint.
    /// * `buyer` - Authorized buyer address (zero address for an open mint).
    /// * `metadata_uri` - IPFS or HTTP URI for NFT metadata.
    pub async fn commit_for_mint(
        &self,
        secret_hash: B256,
        token_id: U256,
        price: U256,
        buyer: Address,
        metadata_uri: String,
    ) -> Result<TxHash> {
        let receipt = self
            .contract()
            .commitForMint(secret_hash, token_id, price, buyer, metadata_uri)
            .send()
            .await
            .context("Failed to send commit transaction")?
            .get_receipt()
            .await
            .context("Commit transaction failed")?;

        info!(tx_hash = %receipt.transaction_hash, "Commitment created successfully");
        Ok(receipt.transaction_hash)
    }

    /// Mints an NFT by revealing the secret.
    ///
    /// Validates that the commitment is active and that the minimum commitment
    /// time has passed before attempting to mint.
    pub async fn mint_with_secret(&self, secret: B256, token_id: U256) -> Result<TxHash> {
        let commit = self.get_commitment(token_id).await?;
        if !commit.isActive {
            return Err(anyhow!("No active commitment for this token"));
        }
        if !self.can_mint_now(token_id).await? {
            return Err(anyhow!(
                "Cannot mint yet: minimum commitment time has not passed or commitment has expired"
            ));
        }

        let receipt = self
            .contract()
            .mintWithSecret(secret, token_id)
            .value(commit.price)
            .send()
            .await
            .context("Failed to send mint transaction")?
            .get_receipt()
            .await
            .context("Mint transaction failed")?;

        Ok(receipt.transaction_hash)
    }

    /// Cancels an active commitment.
    ///
    /// Only the seller can cancel before the commitment timeout. After the
    /// timeout period (24 hours), anyone can cancel to clean up expired state.
    ///
    /// # Errors
    ///
    /// Returns an error if no active commitment exists, or if the caller is not
    /// the seller and the timeout has not yet passed.
    pub async fn cancel_commitment(&self, token_id: U256) -> Result<TxHash> {
        let commit = self.get_commitment(token_id).await?;
        if !commit.isActive {
            return Err(anyhow!("No active commitment to cancel"));
        }

        if commit.seller != self.caller {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let commit_time = u64::try_from(commit.commitTime)
                .context("Commitment timestamp exceeds the protocol maximum")?;
            let timeout_time = commit_time
                .checked_add(COMMITMENT_TIMEOUT_SECS)
                .ok_or_else(|| anyhow!("Commitment timeout overflows"))?;
            if now < timeout_time {
                return Err(anyhow!("Only seller can cancel before timeout"));
            }
        }

        let receipt = self
            .contract()
            .cancelCommitment(token_id)
            .send()
            .await
            .context("Failed to send cancel transaction")?
            .get_receipt()
            .await
            .context("Cancel transaction failed")?;

        info!(tx_hash = %receipt.transaction_hash, "Commitment cancelled successfully");
        Ok(receipt.transaction_hash)
    }

    /// Retrieves the on-chain commitment record for a token.
    pub async fn get_commitment(&self, token_id: U256) -> Result<NFTSecretMint::MintCommitment> {
        self.contract()
            .getCommitment(token_id)
            .call()
            .await
            .context("Failed to get commitment")
    }

    /// Checks if the minimum commitment time has passed and minting is allowed.
    pub async fn can_mint_now(&self, token_id: U256) -> Result<bool> {
        self.contract()
            .canMintNow(token_id)
            .call()
            .await
            .context("Failed to check if can mint now")
    }

    /// Returns the address of the connected wallet.
    pub fn caller(&self) -> Address {
        self.caller
    }
}

/// Commits an NFT for minting on Ethereum.
pub async fn commit_for_mint(args: EthCommitArgs) -> Result<CommitResult> {
    debug!("Executing NFT commitment for minting");

    let client = EthClient::new(&args.eth_rpc, &args.seller_eth_key, args.nft_contract)
        .await
        .context("Failed to initialize Ethereum client")?;

    debug!(seller_address = %client.caller(), "Connected to Ethereum as seller");

    let token_id = U256::from(args.token_id);
    if let Ok(commitment) = client.get_commitment(token_id).await
        && commitment.isActive
    {
        return Err(anyhow!(
            "Token {} already has an active commitment from seller {}",
            args.token_id,
            commitment.seller
        ));
    }

    let buyer = args.buyer.unwrap_or(Address::ZERO);
    let tx_hash = client
        .commit_for_mint(
            B256::from(args.secret_hash),
            token_id,
            U256::from(args.price),
            buyer,
            args.metadata_uri.clone(),
        )
        .await
        .context("Failed to commit NFT for minting")?;

    debug!(
        tx_hash = %tx_hash,
        token_id = args.token_id,
        price_wei = args.price,
        metadata_uri = %args.metadata_uri,
        "NFT commitment transaction submitted"
    );

    Ok(CommitResult {
        chain: Chain::Ethereum.as_ref().to_string(),
        tx_id: tx_hash.to_string(),
        token_id: args.token_id,
        price: format!("{} wei", args.price),
        metadata_uri: args.metadata_uri,
    })
}

/// Mints an NFT on Ethereum by revealing the secret.
///
/// Waits for the minimum commitment time to pass before attempting to mint.
/// The revealed secret can then be used by the seller to claim the locked Bitcoin.
pub async fn mint_with_secret(args: EthMintArgs) -> Result<MintResult> {
    debug!("Executing NFT mint with secret reveal");

    let client = EthClient::new(&args.eth_rpc, &args.buyer_eth_key, args.nft_contract)
        .await
        .context("Failed to initialize Ethereum client")?;

    let token_id = U256::from(args.token_id);
    let secret = B256::from(args.secret);

    if !client.can_mint_now(token_id).await? {
        debug!("Waiting for minimum commitment time to pass");
        let wait_start = Instant::now();
        loop {
            if wait_start.elapsed() > MINT_AVAILABILITY_TIMEOUT {
                return Err(anyhow!(
                    "Timeout waiting for mint availability after {:?}",
                    MINT_AVAILABILITY_TIMEOUT
                ));
            }

            if client.can_mint_now(token_id).await? {
                debug!("Minimum commitment time passed, proceeding with mint");
                break;
            }

            debug!("Mint not yet available, waiting {:?}", MINT_CHECK_INTERVAL);
            sleep(MINT_CHECK_INTERVAL).await;
        }
    }

    let tx_hash = client
        .mint_with_secret(secret, token_id)
        .await
        .context("Failed to execute NFT mint transaction")?;

    debug!(
        tx_hash = %tx_hash,
        secret_revealed = %hex::encode(args.secret),
        "NFT minted successfully, secret revealed on Ethereum"
    );

    Ok(MintResult {
        chain: Chain::Ethereum.as_ref().to_string(),
        tx_id: tx_hash.to_string(),
        token_id: args.token_id,
        secret_revealed: hex::encode(args.secret),
    })
}

/// Cancels an NFT commitment on Ethereum.
///
/// Only the seller can cancel before the commitment timeout. After the timeout
/// has passed, anyone can cancel the commitment to clean up expired state.
pub async fn cancel_commitment(args: EthCancelArgs) -> Result<CancelResult> {
    debug!("Executing Ethereum NFT commitment cancellation");

    let client = EthClient::new(&args.eth_rpc, &args.caller_eth_key, args.nft_contract)
        .await
        .context("Failed to initialize Ethereum client")?;

    debug!(
        caller_address = %client.caller(),
        token_id = args.token_id,
        "Connected to Ethereum, attempting to cancel commitment"
    );

    let tx_hash = client
        .cancel_commitment(U256::from(args.token_id))
        .await
        .context("Failed to cancel commitment")?;

    debug!(tx_hash = %tx_hash, token_id = args.token_id, "Commitment cancelled successfully");

    Ok(CancelResult {
        chain: Chain::Ethereum.as_ref().to_string(),
        tx_id: tx_hash.to_string(),
        token_id: args.token_id,
    })
}
