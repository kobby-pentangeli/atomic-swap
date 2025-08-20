//! RPC client for Ethereum

use std::sync::Arc;

use anyhow::Context;
use ethers::abi::{Abi, Token};
use ethers::contract::Contract;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, Filter, H256, Log, U64, U256};
use ethers::utils::keccak256;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::types::{CommitmentInfo, EthereumTx, SwapEvent};

// Contract ABI for encoding/decoding calls and events
const NFT_SECRET_MINT_JSON: &str =
    include_str!("../../agent/eth/artifacts/contracts/NFTSecretMint.sol/NFTSecretMint.json");

// On-chain operations.
const COMMIT_FOR_MINT: &str = "commitForMint";
const MINT_WITH_SECRET: &str = "mintWithSecret";
const CANCEL_COMMITMENT: &str = "cancelCommitment";
const GET_COMMITMENT: &str = "getCommitment";
const IS_COMMITMENT_VALID: &str = "isCommitmentValid";
const CAN_MINT_NOW: &str = "canMintNow";
const HASH_TO_TOKEN_ID: &str = "hashToTokenId";

pub struct EthClient {
    provider: Provider<Http>,
    contract: Contract<SignerMiddleware<Provider<Http>, LocalWallet>>,
    wallet: LocalWallet,
}

impl EthClient {
    pub async fn new(
        rpc_url: &str,
        private_key: &str,
        contract_addr: Address,
    ) -> anyhow::Result<Self> {
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
            .ok_or_else(|| anyhow::anyhow!("Missing ABI"))?
            .to_string();
        let abi = serde_json::from_str::<Abi>(&abi_json)?;
        let contract = Contract::new(contract_addr, abi, Arc::new(client));

        // Test connection
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

    /// Create a commitment for NFT minting
    pub async fn commit_for_mint(
        &self,
        secret_hash: H256,
        token_id: U256,
        price: U256,
        buyer: Option<Address>,
        metadata_uri: String,
    ) -> anyhow::Result<H256> {
        if self.is_token_committed(token_id).await? {
            return Err(anyhow::anyhow!("Token already has an active commitment"));
        }
        if self.is_hash_used(secret_hash).await? {
            return Err(anyhow::anyhow!("Secret hash has already been used"));
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

    /// Mint NFT by revealing the secret
    pub async fn mint_with_secret(&self, secret: H256, token_id: U256) -> anyhow::Result<H256> {
        let commit = self.get_commitment(token_id).await?;
        if !commit.is_active {
            return Err(anyhow::anyhow!("No active commitment for this token"));
        }
        // TODO (kobby-pentangeli): uncomment in prod
        // if !self.can_mint_now(token_id).await? {
        //     return Err(anyhow::anyhow!("Cannot mint now; check timing constraints"));
        // }

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

    /// Cancel a commitment (only by seller or after timeout)
    pub async fn cancel_commitment(&self, token_id: U256) -> anyhow::Result<H256> {
        let commit = self.get_commitment(token_id).await?;
        if !commit.is_active {
            return Err(anyhow::anyhow!("No active commitment to cancel"));
        }

        if commit.seller != self.wallet.address() {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let timeout_time = commit.commit_time.as_u64() + (24 * 60 * 60); // 24 hours
            if current_time < timeout_time {
                return Err(anyhow::anyhow!("Only seller can cancel before timeout"));
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

    /// Get commitment information for a token
    pub async fn get_commitment(&self, token_id: U256) -> anyhow::Result<CommitmentInfo> {
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

    /// Check if a commitment is still valid
    pub async fn is_commitment_valid(&self, token_id: U256) -> anyhow::Result<bool> {
        let valid: bool = self
            .contract
            .method(IS_COMMITMENT_VALID, token_id)?
            .call()
            .await
            .context("Failed to check commitment validity")?;
        Ok(valid)
    }

    /// Check if minimum commitment time has passed
    pub async fn can_mint_now(&self, token_id: U256) -> anyhow::Result<bool> {
        let can_mint: bool = self
            .contract
            .method(CAN_MINT_NOW, token_id)?
            .call()
            .await
            .context("Failed to check if can mint now")?;
        Ok(can_mint)
    }

    /// Get transaction information
    pub async fn get_transaction_info(&self, tx_hash: H256) -> anyhow::Result<EthereumTx> {
        let tx = self
            .provider
            .get_transaction(tx_hash)
            .await
            .context("Failed to get transaction")?;

        let receipt = self.provider.get_transaction_receipt(tx_hash).await?;
        let current_block = self.provider.get_block_number().await?;

        let confirmations = if let (Some(_tx), Some(receipt)) = (tx, receipt.as_ref()) {
            if let Some(block_number) = receipt.block_number {
                Some(current_block.saturating_sub(block_number).as_u64())
            } else {
                Some(0)
            }
        } else {
            None
        };

        Ok(EthereumTx {
            hash: tx_hash,
            block_number: receipt.as_ref().and_then(|r| r.block_number),
            block_hash: receipt.as_ref().and_then(|r| r.block_hash),
            tx_index: receipt.as_ref().map(|r| r.transaction_index),
            confirmations,
            gas_used: receipt.as_ref().map(|r| r.gas_used.unwrap_or_default()),
        })
    }

    /// Monitor for contract events
    pub async fn monitor_events<F>(&self, mut callback: F) -> anyhow::Result<()>
    where
        F: FnMut(SwapEvent) -> anyhow::Result<()>,
    {
        info!("Starting event monitoring for NFT contract");

        let mut last_block = self.provider.get_block_number().await?;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(12)).await; // ~1 block on Ethereum

            match self.provider.get_block_number().await {
                Ok(current_block) => {
                    if current_block > last_block {
                        debug!(
                            "Checking events from block {} to {}",
                            last_block + 1,
                            current_block
                        );

                        if let Err(e) = self
                            .process_events_in_range(last_block + 1, current_block, &mut callback)
                            .await
                        {
                            error!("Error processing events: {}", e);
                        }

                        last_block = current_block;
                    }
                }
                Err(e) => {
                    warn!("Failed to get current block number: {}", e);
                }
            }
        }
    }

    /// Get current gas price
    pub async fn get_gas_price(&self) -> anyhow::Result<U256> {
        self.provider
            .get_gas_price()
            .await
            .context("Failed to get gas price")
    }

    pub async fn get_balance(&self) -> anyhow::Result<U256> {
        self.provider
            .get_balance(self.wallet.address(), None)
            .await
            .context("Failed to get account balance")
    }

    pub fn get_address(&self) -> Address {
        self.wallet.address()
    }

    /// Check if a token already has an active commitment
    async fn is_token_committed(&self, token_id: U256) -> anyhow::Result<bool> {
        let commitment = self.get_commitment(token_id).await?;
        Ok(commitment.is_active)
    }

    /// Check if a secret hash has already been used
    async fn is_hash_used(&self, secret_hash: H256) -> anyhow::Result<bool> {
        // Query the hashToTokenId mapping
        let token_id: U256 = self
            .contract
            .method(HASH_TO_TOKEN_ID, secret_hash)?
            .call()
            .await
            .context("Failed to check hash usage")?;

        // If token_id is 0, hash hasn't been used
        Ok(token_id != U256::zero())
    }

    /// Process events in a block range
    async fn process_events_in_range<F>(
        &self,
        from_block: U64,
        to_block: U64,
        callback: &mut F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(SwapEvent) -> anyhow::Result<()>,
    {
        let contract_address = self.contract.address();

        let filter = Filter::new()
            .address(contract_address)
            .from_block(from_block)
            .to_block(to_block);

        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .context("Failed to get logs")?;

        for log in logs {
            if let Ok(event) = self.parse_log_to_event(&log).await
                && let Err(e) = callback(event)
            {
                error!("Error in event callback: {e}");
            }
        }

        Ok(())
    }

    /// Parse a log entry into a SwapEvent
    async fn parse_log_to_event(&self, log: &Log) -> anyhow::Result<SwapEvent> {
        let event_sig = log
            .topics
            .first()
            .ok_or_else(|| anyhow::anyhow!("Log has no topics"))?;

        // Event signatures for the contract
        let commit_created_sig =
            keccak256("CommitmentCreated(uint256,bytes32,address,address,uint256,string)");
        let secret_revealed_sig = keccak256("SecretRevealed(uint256,bytes32,bytes32,address)");
        let nft_minted_sig = keccak256("NFTMinted(uint256,address,bytes32)");
        let commit_cancelled_sig = keccak256("CommitmentCancelled(uint256,bytes32,address)");

        match event_sig.as_bytes() {
            sig if sig == commit_created_sig => {
                let token_id = U256::from_big_endian(log.topics[1].as_bytes());
                let secret_hash: [u8; 32] = log.topics[2].into();

                let _decoded = ethers::abi::decode(
                    &[
                        ethers::abi::ParamType::Address,   // seller
                        ethers::abi::ParamType::Address,   // buyer
                        ethers::abi::ParamType::Uint(256), // price
                        ethers::abi::ParamType::String,    // metadataURI
                    ],
                    &log.data,
                )?;

                Ok(SwapEvent::EthCommitted {
                    tx_hash: log.transaction_hash.unwrap_or_default().to_string(),
                    token_id: token_id.as_u64(),
                    secret_hash,
                })
            }

            sig if sig == secret_revealed_sig => {
                let token_id = U256::from_big_endian(log.topics[1].as_bytes());
                let _secret_hash: [u8; 32] = log.topics[2].into();

                let decoded = ethers::abi::decode(
                    &[
                        ethers::abi::ParamType::FixedBytes(32), // secret
                        ethers::abi::ParamType::Address,        // revealer
                    ],
                    &log.data,
                )?;

                if let Some(Token::FixedBytes(secret_bytes)) = decoded.first() {
                    let secret: [u8; 32] = secret_bytes
                        .clone()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid secret length"))?;

                    Ok(SwapEvent::SecretRevealed {
                        tx_hash: log.transaction_hash.unwrap_or_default().to_string(),
                        secret,
                        token_id: token_id.as_u64(),
                    })
                } else {
                    Err(anyhow::anyhow!("Failed to decode secret from event"))
                }
            }

            sig if sig == nft_minted_sig => {
                let token_id = U256::from_big_endian(log.topics[1].as_bytes());

                let decoded = ethers::abi::decode(
                    &[
                        ethers::abi::ParamType::Address,        // to
                        ethers::abi::ParamType::FixedBytes(32), // secret
                    ],
                    &log.data,
                )?;

                if let Some(Token::Address(owner)) = decoded.first() {
                    Ok(SwapEvent::NFTMinted {
                        tx_hash: log.transaction_hash.unwrap_or_default().to_string(),
                        token_id: token_id.as_u64(),
                        owner: *owner,
                    })
                } else {
                    Err(anyhow::anyhow!("Failed to decode NFT minted event"))
                }
            }

            sig if sig == commit_cancelled_sig => {
                let token_id = U256::from_big_endian(log.topics[1].as_bytes());
                let secret: [u8; 32] = log.topics[2].into();

                let decoded = ethers::abi::decode(
                    &[ethers::abi::ParamType::Address], // seller
                    &log.data,
                )?;

                if let Some(Token::Address(seller)) = decoded.first() {
                    Ok(SwapEvent::CommitCancelled {
                        token_id: token_id.as_u64(),
                        secret,
                        seller: *seller,
                    })
                } else {
                    Err(anyhow::anyhow!("Failed to decode commit cancelled event"))
                }
            }

            _ => Err(anyhow::anyhow!("Unknown event signature: {event_sig:?}")),
        }
    }
}
