//! Ethereum RPC client for the NFTSecretMint contract.
//!
//! Provides an interface for interacting with the NFTSecretMint smart
//! contract on Ethereum. It supports the full NFT commitment lifecycle:
//!
//! - Creating commitments for NFT minting
//! - Minting NFTs by revealing the secret preimage
//! - Cancelling commitments (by seller or after timeout)
//! - Querying commitment status and validity

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use ethers::abi::Abi;
use ethers::contract::Contract;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, H256, U256};
use serde_json::Value;
use tokio::time::sleep;
use tracing::{debug, info};

use crate::types::{
    CancelCommitArgs, CancelResult, CommitForMintArgs, CommitResult, CommitmentInfo, MintResult,
    MintWithSecretArgs,
};
use crate::utils::{MINT_AVAILABILITY_TIMEOUT, MINT_CHECK_INTERVAL};

/// Embedded contract ABI for encoding/decoding calls and events.
const NFT_SECRET_MINT_JSON: &str = include_str!("../../agent/eth/abi/NFTSecretMint.json");

/// Contract method names.
const COMMIT_FOR_MINT: &str = "commitForMint";
const MINT_WITH_SECRET: &str = "mintWithSecret";
const CANCEL_COMMITMENT: &str = "cancelCommitment";
const GET_COMMITMENT: &str = "getCommitment";
const IS_COMMITMENT_VALID: &str = "isCommitmentValid";
const CAN_MINT_NOW: &str = "canMintNow";

/// Ethereum client for NFTSecretMint contract interactions.
///
/// Wraps an ethers provider and wallet to execute transactions against
/// the NFTSecretMint contract.
pub struct EthClient {
    provider: Provider<Http>,
    contract: Contract<SignerMiddleware<Provider<Http>, LocalWallet>>,
    wallet: LocalWallet,
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
    /// Returns an error if the connection fails or the private key is invalid.
    pub async fn new(rpc_url: &str, private_key: &str, contract_addr: Address) -> Result<Self> {
        let provider =
            Provider::<Http>::try_from(rpc_url).context("Failed to create Ethereum provider")?;
        let chain_id = provider.get_chainid().await?.as_u64();

        let wallet = private_key
            .parse::<LocalWallet>()
            .context("Failed to parse private key")?
            .with_chain_id(chain_id);

        let client = SignerMiddleware::new(provider.clone(), wallet.clone());

        let artifact: Value = serde_json::from_str(NFT_SECRET_MINT_JSON)?;
        let abi_json = artifact
            .get("abi")
            .ok_or_else(|| anyhow!("Missing ABI"))?
            .to_string();
        let abi = serde_json::from_str::<Abi>(&abi_json)?;
        let contract = Contract::new(contract_addr, abi, Arc::new(client));

        let block_number = provider
            .get_block_number()
            .await
            .context("Failed to connect to Ethereum node")?;
        info!("Connected to Ethereum, current block: {block_number}");

        Ok(Self {
            provider,
            contract,
            wallet,
        })
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
    /// * `buyer` - Optional authorized buyer address (None for unrestricted).
    /// * `metadata_uri` - IPFS or HTTP URI for NFT metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if a commitment already exists for this token ID.
    pub async fn commit_for_mint(
        &self,
        secret_hash: H256,
        token_id: U256,
        price: U256,
        buyer: Option<Address>,
        metadata_uri: String,
    ) -> Result<H256> {
        if let Ok(commitment) = self.get_commitment(token_id).await
            && commitment.is_active
        {
            return Err(anyhow!("Commitment already exists for this token ID"));
        }

        let buyer_addr = buyer.unwrap_or(Address::zero());
        let gas_price = self.get_gas_price().await?;

        let call = self
            .contract
            .method::<_, H256>(
                COMMIT_FOR_MINT,
                (secret_hash, token_id, price, buyer_addr, metadata_uri),
            )?
            .gas_price(gas_price);

        let pending_tx = call
            .send()
            .await
            .context("Failed to send commit transaction")?;

        let receipt = pending_tx.await?.context("Transaction failed")?;
        let tx_hash = receipt.transaction_hash;
        info!("Commitment created successfully: {tx_hash:?}");

        Ok(tx_hash)
    }

    /// Mint NFT by revealing the secret.
    ///
    /// Validates that the commitment is active and that the minimum commitment
    /// time has passed before attempting to mint.
    pub async fn mint_with_secret(&self, secret: H256, token_id: U256) -> Result<H256> {
        let commit = self.get_commitment(token_id).await?;
        if !commit.is_active {
            return Err(anyhow!("No active commitment for this token"));
        }
        if !self.can_mint_now(token_id).await? {
            return Err(anyhow!(
                "Cannot mint yet: minimum commitment time has not passed or commitment has expired"
            ));
        }

        let gas_price = self.get_gas_price().await?;

        let call = self
            .contract
            .method::<_, H256>(MINT_WITH_SECRET, (secret, token_id))?
            .value(commit.price)
            .gas_price(gas_price);

        let pending_tx = call
            .send()
            .await
            .context("Failed to send mint transaction")?;

        let receipt = pending_tx.await?.context("Mint transaction failed")?;
        let tx_hash = receipt.transaction_hash;

        Ok(tx_hash)
    }

    /// Cancels an active commitment.
    ///
    /// Only the seller can cancel before the commitment timeout. After the
    /// timeout period (24 hours), anyone can cancel to clean up expired state.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No active commitment exists for the token ID
    /// - Caller is not the seller and timeout hasn't passed
    pub async fn cancel_commitment(&self, token_id: U256) -> Result<H256> {
        let commit = self.get_commitment(token_id).await?;
        if !commit.is_active {
            return Err(anyhow!("No active commitment to cancel"));
        }

        if commit.seller != self.wallet.address() {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let timeout_time = commit.commit_time.as_u64() + (24 * 60 * 60); // 24 hours
            if current_time < timeout_time {
                return Err(anyhow!("Only seller can cancel before timeout"));
            }
        }

        let gas_price = self.get_gas_price().await?;
        let call = self
            .contract
            .method::<_, H256>(CANCEL_COMMITMENT, token_id)?
            .gas_price(gas_price);

        let pending_tx = call
            .send()
            .await
            .context("Failed to send cancel transaction")?;

        let receipt = pending_tx.await?.context("Cancel transaction failed")?;
        let tx_hash = receipt.transaction_hash;
        info!("Commitment cancelled successfully: {tx_hash:?}");

        Ok(tx_hash)
    }

    /// Retrieves commitment information for a token.
    ///
    /// Returns the full commitment state including seller, buyer, price,
    /// and whether the commitment is still active.
    pub async fn get_commitment(&self, token_id: U256) -> Result<CommitmentInfo> {
        let result: (
            [u8; 32], // secretHash
            Address,  // seller
            Address,  // buyer
            U256,     // price
            U256,     // commitTime
            bool,     // isActive
            String,   // tokenURI
        ) = self
            .contract
            .method(GET_COMMITMENT, token_id)?
            .call()
            .await
            .context("Failed to get commitment")?;

        Ok(CommitmentInfo {
            secret_hash: result.0,
            seller: result.1,
            buyer: result.2,
            price: result.3,
            commit_time: result.4,
            is_active: result.5,
            token_uri: result.6,
        })
    }

    /// Checks if a commitment is still valid (active and not expired).
    pub async fn is_commitment_valid(&self, token_id: U256) -> Result<bool> {
        let valid: bool = self
            .contract
            .method(IS_COMMITMENT_VALID, token_id)?
            .call()
            .await
            .context("Failed to check commitment validity")?;
        Ok(valid)
    }

    /// Checks if the minimum commitment time has passed and minting is allowed.
    pub async fn can_mint_now(&self, token_id: U256) -> Result<bool> {
        let can_mint: bool = self
            .contract
            .method(CAN_MINT_NOW, token_id)?
            .call()
            .await
            .context("Failed to check if can mint now")?;
        Ok(can_mint)
    }

    /// Returns the current network gas price.
    pub async fn get_gas_price(&self) -> Result<U256> {
        self.provider
            .get_gas_price()
            .await
            .context("Failed to get gas price")
    }

    /// Returns the ETH balance of the connected wallet.
    pub async fn get_balance(&self) -> Result<U256> {
        self.provider
            .get_balance(self.wallet.address(), None)
            .await
            .context("Failed to get account balance")
    }

    /// Returns the address of the connected wallet.
    pub fn get_address(&self) -> Address {
        self.wallet.address()
    }
}

/// Commits an NFT for minting on Ethereum.
pub async fn commit_for_mint(args: CommitForMintArgs) -> Result<CommitResult> {
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

/// Mints an NFT on Ethereum by revealing the secret.
///
/// Waits for the minimum commitment time to pass before attempting to mint.
/// The revealed secret can then be used by the seller to claim the locked Bitcoin.
pub async fn mint_with_secret(args: MintWithSecretArgs) -> Result<MintResult> {
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

/// Cancels an NFT commitment on Ethereum.
///
/// Only the seller can cancel before the commitment timeout. After the timeout
/// has passed, anyone can cancel the commitment to clean up expired state.
pub async fn cancel_commitment(args: CancelCommitArgs) -> Result<CancelResult> {
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
