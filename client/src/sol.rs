//! Solana RPC client for the on-chain sol-htlc program.
//!
//! Supports the full NFT commitment lifecycle:
//!
//! - Initializing the program state
//! - Creating commitments for NFT minting
//! - Minting NFTs by revealing the secret preimage
//! - Cancelling commitments (seller only)

use std::str::FromStr;
use std::sync::Arc;

use anchor_client::solana_sdk::commitment_config::CommitmentConfig;
use anchor_client::solana_sdk::pubkey::Pubkey;
use anchor_client::solana_sdk::signature::{Keypair, Signature, Signer, read_keypair_file};
use anchor_client::{Client, Cluster, Program};
use anchor_lang::{solana_program, system_program};
use anchor_spl::associated_token;
use anchor_spl::metadata::mpl_token_metadata;
use anyhow::{Context, Result, anyhow};
use sol_htlc::{Commitment, MAX_NAME_LEN, MAX_SYMBOL_LEN, MAX_URI_LEN, ProgramState};
use tracing::{debug, info};

use crate::types::{
    CancelCommitArgs, CancelResult, CommitForMintArgs, CommitResult, MintResult, MintWithSecretArgs,
};

/// Solana client for sol-htlc program interactions.
///
/// Wraps an Anchor client and payer keypair to execute transactions
/// against the sol-htlc program.
pub struct SolClient {
    payer: Arc<Keypair>,
    program: Program<Arc<Keypair>>,
    program_id: Pubkey,
    program_state_pda: Pubkey,
}

impl SolClient {
    /// Creates a new Solana client connected to the sol-htlc program.
    ///
    /// # Arguments
    ///
    /// * `payer` - Keypair used to sign and pay for transactions.
    /// * `program_id` - Base58-encoded sol-htlc program ID.
    /// * `rpc_url` - Solana JSON-RPC endpoint URL.
    /// * `ws_url` - Solana WebSocket endpoint URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails or the program ID is invalid.
    pub fn new(payer: Keypair, program_id: &str, rpc_url: &str, ws_url: &str) -> Result<Self> {
        let payer = Arc::new(payer);
        let client = Client::new_with_options(
            Cluster::Custom(rpc_url.to_string(), ws_url.to_string()),
            payer.clone(),
            CommitmentConfig::confirmed(),
        );

        let program_id = Pubkey::from_str(program_id).context("Failed to parse program ID")?;
        let program = client.program(program_id)?;
        let (program_state_pda, _) = Pubkey::find_program_address(&[b"program_state"], &program_id);

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

    /// Initializes the program state account.
    ///
    /// This should be called once after program deployment by the authority.
    /// Subsequent calls will fail if the state is already initialized.
    pub fn initialize(&self) -> Result<Signature> {
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
        Ok(sig)
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
    /// * `price` - Price in lamports required to mint.
    /// * `name` - NFT name (max 32 characters).
    /// * `symbol` - NFT symbol (max 10 characters).
    /// * `uri` - Metadata URI (max 200 characters).
    ///
    /// # Errors
    ///
    /// Returns an error if a commitment already exists for this token ID.
    pub fn commit_for_mint(
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

        if self.get_commitment(token_id).is_ok() {
            return Err(anyhow!("Commitment already exists for this token ID"));
        }

        let (commitment, _) = Pubkey::find_program_address(
            &[b"commitment", &token_id.to_le_bytes()],
            &self.program_id,
        );
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

    /// Mints an NFT by revealing the secret.
    ///
    /// The buyer calls this with the secret preimage to mint the NFT.
    /// The revealed secret can then be used by the seller to claim Bitcoin.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No commitment exists for the token ID
    /// - The commitment has already been used
    /// - The secret doesn't match the commitment hash
    pub fn mint_with_secret(&self, secret: [u8; 32], token_id: u64) -> Result<Signature> {
        let commitment = self.get_commitment(token_id)?;
        if commitment.is_used {
            return Err(anyhow!("Commitment has already been used"));
        }
        if commitment.token_id != token_id {
            return Err(anyhow!("Token ID mismatch"));
        }

        let (commitment_pda, _) = Pubkey::find_program_address(
            &[b"commitment", &token_id.to_le_bytes()],
            &self.program_id,
        );
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

    /// Cancels an active commitment.
    ///
    /// Only the seller who created the commitment can cancel it.
    /// The commitment must not have been used (NFT not yet minted).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The caller is not the seller
    /// - The commitment has already been used
    pub fn cancel_commitment(&self, token_id: u64) -> Result<Signature> {
        let commitment = self.get_commitment(token_id)?;
        if commitment.seller != self.payer.pubkey() {
            return Err(anyhow!("Only the seller can cancel the commitment"));
        }
        if commitment.is_used {
            return Err(anyhow!("Cannot cancel a used commitment"));
        }

        let (commitment, _) = Pubkey::find_program_address(
            &[b"commitment", &token_id.to_le_bytes()],
            &self.program_id,
        );

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

    /// Retrieves commitment information for a token.
    ///
    /// Returns the full commitment state including seller, price, and usage status.
    pub fn get_commitment(&self, token_id: u64) -> Result<Commitment> {
        let (commit_pda, _) = Pubkey::find_program_address(
            &[b"commitment", &token_id.to_le_bytes()],
            &self.program_id,
        );
        let commit_acc = self
            .program
            .account::<Commitment>(commit_pda)
            .context("Failed to fetch commitment account")?;
        Ok(commit_acc)
    }

    /// Derives the associated token account address for a mint and owner.
    pub fn get_associated_token_account(&self, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        associated_token::get_associated_token_address(owner, mint)
    }

    /// Checks if the program state account is initialized.
    pub fn is_initialized(&self) -> bool {
        self.program_state().is_ok()
    }

    /// Returns the public key of the connected payer wallet.
    pub fn pubkey(&self) -> Pubkey {
        self.payer.pubkey()
    }

    /// Returns the sol-htlc program ID.
    pub fn program_id(&self) -> Pubkey {
        self.program_id
    }

    /// Fetches the program state account.
    fn program_state(&self) -> Result<ProgramState> {
        let program_state = self
            .program
            .account::<ProgramState>(self.program_state_pda)
            .context("Failed to fetch program state")?;
        Ok(program_state)
    }
}

/// Commits an NFT for minting on Solana.
pub fn commit_for_mint(args: CommitForMintArgs) -> Result<CommitResult> {
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

/// Mints an NFT on Solana by revealing the secret.
pub fn mint_with_secret(args: MintWithSecretArgs) -> Result<MintResult> {
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

/// Cancels an NFT commitment on Solana.
///
/// Only the seller who created the commitment can cancel it. The commitment
/// must not have been used (NFT not yet minted).
pub fn cancel_commitment(args: CancelCommitArgs) -> Result<CancelResult> {
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
