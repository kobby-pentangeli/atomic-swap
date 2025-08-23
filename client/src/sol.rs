use std::str::FromStr;
use std::sync::Arc;

use anchor_client::solana_sdk::commitment_config::CommitmentConfig;
use anchor_client::solana_sdk::keccak;
use anchor_client::solana_sdk::pubkey::Pubkey;
use anchor_client::solana_sdk::signature::{Keypair, Signature, Signer};
use anchor_client::{Client, Cluster, Program};
use anchor_lang::{solana_program, system_program};
use anchor_spl::associated_token;
use anchor_spl::metadata::mpl_token_metadata;
use anyhow::{Context, Result, anyhow};
use sol_htlc::{Commitment, MAX_NAME_LEN, MAX_SYMBOL_LEN, MAX_URI_LEN};
use tracing::info;

pub struct SolClient {
    payer: Arc<Keypair>,
    program: Program<Arc<Keypair>>,
    program_id: Pubkey,
    program_state_pda: Pubkey,
}

impl SolClient {
    pub async fn new(
        payer: Keypair,
        program_id: &str,
        rpc_url: &str,
        ws_url: &str,
    ) -> Result<Self> {
        let payer = Arc::new(payer);
        let client = Client::new_with_options(
            Cluster::Custom(rpc_url.to_string(), ws_url.to_string()),
            payer.clone(),
            CommitmentConfig::confirmed(),
        );

        let program_id = Pubkey::from_str(program_id).context("Failed to parse program ID")?;
        let program = client.program(program_id)?;
        let (program_state_pda, _) = Pubkey::find_program_address(&[b"program_state"], &program_id);

        // Test connection
        let slot = &program
            .rpc()
            .get_slot()
            .context("Failed to connect to Solana RPC")?;
        info!("Connected to Solana, current slot: {slot}");

        Ok(Self {
            payer,
            program,
            program_id,
            program_state_pda,
        })
    }

    /// Initialize the program state (should be called once by authority)
    pub async fn initialize(&self) -> Result<Signature> {
        let sig = self
            .program
            .request()
            .accounts(sol_htlc::accounts::Initialize {
                program_state: self.program_state_pda,
                authority: self.payer.pubkey(),
                system_program: system_program::ID,
            })
            .args(sol_htlc::instruction::Initialize {})
            .send()
            .context("Failed to initialize program")?;

        info!("Program initialized successfully: {sig}");
        Ok(sig)
    }

    /// Create a commitment for NFT minting
    pub async fn commit_for_mint(
        &self,
        secret_hash: [u8; 32],
        token_id: u64,
        price: u64,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<Signature> {
        if name.len() > MAX_NAME_LEN {
            return Err(anyhow!("Name too long (max 32 chars)"));
        }
        if symbol.len() > MAX_SYMBOL_LEN {
            return Err(anyhow!("Symbol too long (max 10 chars)"));
        }
        if uri.len() > MAX_URI_LEN {
            return Err(anyhow!("URI too long (max 200 chars)"));
        }
        if price == 0 {
            return Err(anyhow!("Price must be greater than 0"));
        }

        if self.get_commitment_by_hash(secret_hash).await.is_ok() {
            return Err(anyhow!("Commitment already exists for this hash"));
        }

        let (commitment, _) =
            Pubkey::find_program_address(&[b"commitment", &secret_hash], &self.program_id);
        let (mint, _) =
            Pubkey::find_program_address(&[b"mint", &token_id.to_le_bytes()], &self.program_id);

        let sig = self
            .program
            .request()
            .accounts(sol_htlc::accounts::CommitForMint {
                commitment,
                mint,
                program_state: self.program_state_pda,
                seller: self.payer.pubkey(),
                token_program: anchor_spl::token::ID,
                system_program: system_program::ID,
                rent: solana_program::sysvar::rent::ID,
            })
            .args(sol_htlc::instruction::CommitForMint {
                hash: secret_hash,
                token_id,
                price,
                name,
                symbol,
                uri,
            })
            .send()
            .context("Failed to create commitment")?;

        info!("Commitment created successfully: {sig}");
        Ok(sig)
    }

    /// Mint NFT by revealing the secret
    pub async fn mint_with_secret(&self, secret: [u8; 32], token_id: u64) -> Result<Signature> {
        let secret_hash = keccak::hash(&secret).to_bytes();

        let commitment = self.get_commitment_by_hash(secret_hash).await?;
        if commitment.is_used {
            return Err(anyhow!("Commitment has already been used"));
        }
        if commitment.token_id != token_id {
            return Err(anyhow!("Token ID mismatch"));
        }

        let (commitment_pda, _) =
            Pubkey::find_program_address(&[b"commitment", &secret_hash], &self.program_id);
        let (mint_pda, _) =
            Pubkey::find_program_address(&[b"mint", &token_id.to_le_bytes()], &self.program_id);
        let token_account = self.get_associated_token_account(&self.payer.pubkey(), &mint_pda);
        let (metadata_pda, _) = Pubkey::find_program_address(
            &[
                b"metadata",
                mpl_token_metadata::ID.as_ref(),
                mint_pda.as_ref(),
            ],
            &mpl_token_metadata::ID,
        );

        let sig = self
            .program
            .request()
            .accounts(sol_htlc::accounts::MintWithSecret {
                commitment: commitment_pda,
                mint: mint_pda,
                token_account,
                metadata: metadata_pda,
                program_state: self.program_state_pda,
                seller_info: commitment.seller,
                buyer: self.payer.pubkey(),
                token_program: anchor_spl::token::ID,
                associated_token_program: associated_token::ID,
                metadata_program: mpl_token_metadata::ID,
                system_program: system_program::ID,
                rent: solana_program::sysvar::rent::ID,
            })
            .args(sol_htlc::instruction::MintWithSecret { secret, token_id })
            .send()
            .context("Failed to mint NFT")?;

        info!("NFT minted successfully: {sig}");
        Ok(sig)
    }

    /// Cancel a commitment
    pub async fn cancel_commitment(&self, secret_hash: [u8; 32]) -> Result<Signature> {
        let commitment = self.get_commitment_by_hash(secret_hash).await?;
        if commitment.seller != self.payer.pubkey() {
            return Err(anyhow!("Only the seller can cancel the commitment"));
        }
        if commitment.is_used {
            return Err(anyhow!("Cannot cancel a used commitment"));
        }

        let (commitment, _) =
            Pubkey::find_program_address(&[b"commitment", &secret_hash], &self.program_id);

        let sig = self
            .program
            .request()
            .accounts(sol_htlc::accounts::CancelCommitment {
                commitment,
                seller: self.payer.pubkey(),
            })
            .args(sol_htlc::instruction::CancelCommitment {})
            .send()
            .context("Failed to cancel commitment")?;

        info!("Commitment cancelled successfully: {sig}");
        Ok(sig)
    }

    /// Get commitment information by hash
    pub async fn get_commitment_by_hash(&self, hash: [u8; 32]) -> Result<Commitment> {
        let (commit_pda, _) =
            Pubkey::find_program_address(&[b"commitment", &hash], &self.program_id);
        let commit_acc = self
            .program
            .account::<Commitment>(commit_pda)
            .context("Failed to fetch commitment account")?;
        Ok(commit_acc)
    }

    /// Get associated token account for a mint and owner
    pub fn get_associated_token_account(&self, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        associated_token::get_associated_token_address(owner, mint)
    }
}
