//! RPC client for Ethereum

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use ethers::abi::Abi;
use ethers::contract::Contract;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, H256, U256};
use serde_json::Value;
use tracing::info;

use crate::types::CommitmentInfo;

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

pub struct EthClient {
    provider: Provider<Http>,
    contract: Contract<SignerMiddleware<Provider<Http>, LocalWallet>>,
    wallet: LocalWallet,
}

impl EthClient {
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
    ) -> Result<H256> {
        if self.get_commitment(token_id).await.is_ok() {
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

    /// Mint NFT by revealing the secret
    pub async fn mint_with_secret(&self, secret: H256, token_id: U256) -> Result<H256> {
        let commit = self.get_commitment(token_id).await?;
        if !commit.is_active {
            return Err(anyhow!("No active commitment for this token"));
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

    /// Get commitment information for a token
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

    /// Check if a commitment is still valid
    pub async fn is_commitment_valid(&self, token_id: U256) -> Result<bool> {
        let valid: bool = self
            .contract
            .method(IS_COMMITMENT_VALID, token_id)?
            .call()
            .await
            .context("Failed to check commitment validity")?;
        Ok(valid)
    }

    /// Check if minimum commitment time has passed
    pub async fn can_mint_now(&self, token_id: U256) -> Result<bool> {
        let can_mint: bool = self
            .contract
            .method(CAN_MINT_NOW, token_id)?
            .call()
            .await
            .context("Failed to check if can mint now")?;
        Ok(can_mint)
    }

    /// Get current gas price
    pub async fn get_gas_price(&self) -> Result<U256> {
        self.provider
            .get_gas_price()
            .await
            .context("Failed to get gas price")
    }

    pub async fn get_balance(&self) -> Result<U256> {
        self.provider
            .get_balance(self.wallet.address(), None)
            .await
            .context("Failed to get account balance")
    }

    pub fn get_address(&self) -> Address {
        self.wallet.address()
    }
}
