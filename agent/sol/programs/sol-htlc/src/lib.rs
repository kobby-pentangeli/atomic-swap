//! Hash Time Locked Contract (HTLC) for Solana NFT Minting
//!
//! This program enables cross-chain atomic swaps by allowing sellers to commit
//! to minting an NFT that can only be claimed by revealing a secret. The secret
//! hash mechanism ensures atomicity with Bitcoin HTLCs.
//!
//! # Flow
//!
//! 1. Seller calls [`commit_for_mint`] with a SHA256 hash of a secret
//! 2. Buyer reveals the secret by calling [`mint_with_secret`]
//! 3. The revealed secret can then be used to claim Bitcoin on the other chain
//!
//! # Hash Algorithm
//!
//! This program uses SHA256 (via `sha2::Sha256`) to match Bitcoin's HTLC
//! hash algorithm, ensuring cross-chain compatibility.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_instruction;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::metadata::mpl_token_metadata::types::DataV2;
use anchor_spl::metadata::{create_metadata_accounts_v3, CreateMetadataAccountsV3, Metadata};
use anchor_spl::token::{mint_to, Mint, MintTo, Token, TokenAccount};
use sha2::{Digest, Sha256};

declare_id!("Htp3Lm1W6dRgDjVtS89unkgUHJwijXkkseyaCHHdsZKG");

/// Maximum length of the NFT name in bytes.
pub const MAX_NAME_LEN: usize = 32;

/// Maximum length of the NFT symbol in bytes.
pub const MAX_SYMBOL_LEN: usize = 10;

/// Maximum length of the metadata URI in bytes.
pub const MAX_URI_LEN: usize = 200;

/// Minimum price in lamports (prevents zero-value commitments).
pub const MIN_PRICE: u64 = 1;

#[program]
pub mod sol_htlc {

    use super::*;

    /// Initializes the program state account.
    ///
    /// This must be called once before any commitments can be created.
    /// The caller becomes the program authority.
    ///
    /// # Accounts
    ///
    /// * `program_state` - The PDA that stores global program state
    /// * `authority` - The signer who will become the program authority
    /// * `system_program` - Required for account creation
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let program_state = &mut ctx.accounts.program_state;
        program_state.authority = ctx.accounts.authority.key();
        program_state.total_minted = 0;
        program_state.bump = ctx.bumps.program_state;

        emit!(ProgramInitialized {
            authority: program_state.authority,
        });

        Ok(())
    }

    /// Creates a commitment for future NFT minting.
    ///
    /// The seller provides a SHA256 hash of a secret. A buyer who knows
    /// the secret preimage can later call [`mint_with_secret`] to mint
    /// the NFT and reveal the secret on-chain.
    ///
    /// # Arguments
    ///
    /// * `hash` - SHA256 hash of the secret (32 bytes)
    /// * `token_id` - Unique identifier for this NFT
    /// * `price` - Price in lamports the buyer must pay
    /// * `name` - NFT name (max 32 bytes)
    /// * `symbol` - NFT symbol (max 10 bytes)
    /// * `uri` - Metadata URI (max 200 bytes)
    ///
    /// # Errors
    ///
    /// * [`ErrorCode::CommitmentAlreadyExists`] - Token ID already has a commitment
    /// * [`ErrorCode::InvalidPrice`] - Price is below minimum
    /// * [`ErrorCode::NameTooLong`] - Name exceeds maximum length
    /// * [`ErrorCode::SymbolTooLong`] - Symbol exceeds maximum length
    /// * [`ErrorCode::UriTooLong`] - URI exceeds maximum length
    pub fn commit_for_mint(
        ctx: Context<CommitForMint>,
        hash: [u8; 32],
        token_id: u64,
        price: u64,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<()> {
        require!(name.len() <= MAX_NAME_LEN, ErrorCode::NameTooLong);
        require!(symbol.len() <= MAX_SYMBOL_LEN, ErrorCode::SymbolTooLong);
        require!(uri.len() <= MAX_URI_LEN, ErrorCode::UriTooLong);
        require!(price >= MIN_PRICE, ErrorCode::InvalidPrice);

        let commitment = &mut ctx.accounts.commitment;

        require!(
            commitment.hash == [0u8; 32],
            ErrorCode::CommitmentAlreadyExists
        );

        commitment.hash = hash;
        commitment.token_id = token_id;
        commitment.price = price;
        commitment.seller = ctx.accounts.seller.key();
        commitment.mint = ctx.accounts.mint.key();
        commitment.name = name.clone();
        commitment.symbol = symbol.clone();
        commitment.uri = uri.clone();
        commitment.is_used = false;
        commitment.bump = ctx.bumps.commitment;

        emit!(CommitmentCreated {
            hash,
            token_id,
            price,
            seller: ctx.accounts.seller.key(),
            mint: ctx.accounts.mint.key(),
            name,
            symbol,
            uri,
        });

        Ok(())
    }

    /// Mints an NFT by revealing the secret that matches the commitment hash.
    ///
    /// The buyer provides the secret preimage, which is verified against the
    /// committed hash. Upon successful verification:
    /// 1. Payment is transferred from buyer to seller
    /// 2. The NFT is minted to the buyer's associated token account
    /// 3. Metadata is created for the NFT
    /// 4. The secret is emitted in an event for cross-chain verification
    ///
    /// # Arguments
    ///
    /// * `secret` - The 32-byte secret preimage
    /// * `token_id` - The token ID to mint
    ///
    /// # Errors
    ///
    /// * [`ErrorCode::CommitmentAlreadyUsed`] - Commitment was already fulfilled
    /// * [`ErrorCode::TokenIdMismatch`] - Token ID doesn't match commitment
    /// * [`ErrorCode::InvalidSecret`] - Secret hash doesn't match commitment
    pub fn mint_with_secret(
        ctx: Context<MintWithSecret>,
        secret: [u8; 32],
        token_id: u64,
    ) -> Result<()> {
        let commitment = &mut ctx.accounts.commitment;

        require!(!commitment.is_used, ErrorCode::CommitmentAlreadyUsed);
        require!(commitment.token_id == token_id, ErrorCode::TokenIdMismatch);

        let computed_hash: [u8; 32] = Sha256::digest(secret).into();
        require!(computed_hash == commitment.hash, ErrorCode::InvalidSecret);

        // Transfer payment from buyer to seller
        anchor_lang::solana_program::program::invoke(
            &system_instruction::transfer(
                ctx.accounts.buyer.key,
                &commitment.seller,
                commitment.price,
            ),
            &[
                ctx.accounts.buyer.to_account_info(),
                ctx.accounts.seller_info.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        let program_state = &ctx.accounts.program_state;
        let signer_seeds: &[&[&[u8]]] = &[&[b"program_state", &[program_state.bump]]];

        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.token_account.to_account_info(),
                    authority: ctx.accounts.program_state.to_account_info(),
                },
                signer_seeds,
            ),
            1, // Mint exactly one NFT
        )?;

        create_metadata_accounts_v3(
            CpiContext::new_with_signer(
                ctx.accounts.metadata_program.to_account_info(),
                CreateMetadataAccountsV3 {
                    metadata: ctx.accounts.metadata.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    mint_authority: ctx.accounts.program_state.to_account_info(),
                    update_authority: ctx.accounts.program_state.to_account_info(),
                    payer: ctx.accounts.buyer.to_account_info(),
                    system_program: ctx.accounts.system_program.to_account_info(),
                    rent: ctx.accounts.rent.to_account_info(),
                },
                signer_seeds,
            ),
            DataV2 {
                name: commitment.name.clone(),
                symbol: commitment.symbol.clone(),
                uri: commitment.uri.clone(),
                seller_fee_basis_points: 0,
                creators: None,
                collection: None,
                uses: None,
            },
            false, // Is mutable
            true,  // Update authority is signer
            None,  // Collection details
        )?;

        commitment.is_used = true;
        let program_state = &mut ctx.accounts.program_state;
        program_state.total_minted = program_state
            .total_minted
            .checked_add(1)
            .ok_or(ErrorCode::Overflow)?;

        emit!(SecretRevealed {
            secret,
            hash: commitment.hash,
            token_id,
            buyer: ctx.accounts.buyer.key(),
            seller: commitment.seller,
            mint: ctx.accounts.mint.key(),
            price: commitment.price,
        });

        emit!(NFTMinted {
            token_id,
            buyer: ctx.accounts.buyer.key(),
            secret
        });

        Ok(())
    }

    /// Allows the seller to cancel a commitment that hasn't been used.
    ///
    /// This closes the commitment account and returns the rent to the seller.
    /// Can only be called by the original seller.
    ///
    /// # Errors
    ///
    /// * [`ErrorCode::Unauthorized`] - Caller is not the original seller
    /// * [`ErrorCode::CommitmentAlreadyUsed`] - Commitment was already fulfilled
    pub fn cancel_commitment(ctx: Context<CancelCommitment>) -> Result<()> {
        let commitment = &ctx.accounts.commitment;

        require!(
            commitment.seller == ctx.accounts.seller.key(),
            ErrorCode::Unauthorized
        );
        require!(!commitment.is_used, ErrorCode::CommitmentAlreadyUsed);

        emit!(CommitmentCancelled {
            hash: commitment.hash,
            token_id: commitment.token_id,
            seller: commitment.seller,
        });

        Ok(())
    }
}

/// Global program state stored in a PDA.
///
/// This account tracks the program authority and total NFTs minted.
#[account]
#[derive(Default)]
pub struct ProgramState {
    /// The authority who initialized the program.
    pub authority: Pubkey,
    /// Total number of NFTs minted through this program.
    pub total_minted: u64,
    /// PDA bump seed for this account.
    pub bump: u8,
}

/// Represents a commitment to mint an NFT in exchange for a secret reveal.
///
/// This account is created by the seller and stores all the information
/// needed to mint the NFT once the buyer reveals the secret.
#[account]
#[derive(Default)]
pub struct Commitment {
    /// SHA256 hash of the secret required to mint.
    pub hash: [u8; 32],
    /// Unique identifier for this NFT.
    pub token_id: u64,
    /// Price in lamports the buyer must pay.
    pub price: u64,
    /// Address of the seller who created this commitment.
    pub seller: Pubkey,
    /// Address of the mint account for this NFT.
    pub mint: Pubkey,
    /// Name of the NFT.
    pub name: String,
    /// Symbol of the NFT.
    pub symbol: String,
    /// Metadata URI for the NFT.
    pub uri: String,
    /// Whether this commitment has been fulfilled.
    pub is_used: bool,
    /// PDA bump seed for this account.
    pub bump: u8,
}

/// Accounts required for program initialization.
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The program state PDA to be initialized.
    #[account(
        init,
        payer = authority,
        space = 8 + std::mem::size_of::<ProgramState>(),
        seeds = [b"program_state"],
        bump
    )]
    pub program_state: Account<'info, ProgramState>,

    /// The authority initializing the program (pays for account creation).
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The system program for account creation.
    pub system_program: Program<'info, System>,
}

/// Accounts required for creating a mint commitment.
#[derive(Accounts)]
#[instruction(hash: [u8; 32], token_id: u64)]
pub struct CommitForMint<'info> {
    /// The commitment PDA to store the commitment data.
    #[account(
        init,
        payer = seller,
        space = 8 + 32 + 8 + 8 + 32 + 32 +
                (4 + MAX_NAME_LEN) + (4 + MAX_SYMBOL_LEN) + (4 + MAX_URI_LEN) + 1 + 1,
        seeds = [b"commitment", token_id.to_le_bytes().as_ref()],
        bump
    )]
    pub commitment: Account<'info, Commitment>,

    /// The mint account for the NFT (0 decimals for NFT).
    #[account(
        init,
        payer = seller,
        mint::decimals = 0,
        mint::authority = program_state,
        mint::freeze_authority = program_state,
        seeds = [b"mint", token_id.to_le_bytes().as_ref()],
        bump
    )]
    pub mint: Account<'info, Mint>,

    /// The global program state PDA.
    #[account(
        seeds = [b"program_state"],
        bump = program_state.bump
    )]
    pub program_state: Account<'info, ProgramState>,

    /// The seller creating the commitment (pays for account creation).
    #[account(mut)]
    pub seller: Signer<'info>,

    /// SPL Token program.
    pub token_program: Program<'info, Token>,
    /// System program for account creation.
    pub system_program: Program<'info, System>,
    /// Rent sysvar.
    pub rent: Sysvar<'info, Rent>,
}

/// Accounts required for minting an NFT with secret reveal.
#[derive(Accounts)]
#[instruction(secret: [u8; 32], token_id: u64)]
pub struct MintWithSecret<'info> {
    /// The commitment being fulfilled.
    #[account(
        mut,
        seeds = [b"commitment", token_id.to_le_bytes().as_ref()],
        bump = commitment.bump
    )]
    pub commitment: Account<'info, Commitment>,

    /// The mint account for the NFT.
    #[account(
        mut,
        seeds = [b"mint", token_id.to_le_bytes().as_ref()],
        bump
    )]
    pub mint: Account<'info, Mint>,

    /// The buyer's associated token account (created if needed).
    #[account(
        init_if_needed,
        payer = buyer,
        associated_token::mint = mint,
        associated_token::authority = buyer
    )]
    pub token_account: Account<'info, TokenAccount>,

    /// The metadata account for the NFT.
    /// CHECK: PDA derived from metadata program and mint.
    #[account(
        mut,
        seeds = [
            b"metadata",
            metadata_program.key().as_ref(),
            mint.key().as_ref(),
        ],
        bump,
        seeds::program = metadata_program.key()
    )]
    pub metadata: UncheckedAccount<'info>,

    /// The global program state PDA.
    #[account(
        mut,
        seeds = [b"program_state"],
        bump = program_state.bump
    )]
    pub program_state: Account<'info, ProgramState>,

    /// The seller who receives payment.
    /// CHECK: Validated through commitment account's seller field.
    #[account(mut)]
    pub seller_info: UncheckedAccount<'info>,

    /// The buyer revealing the secret and receiving the NFT.
    #[account(mut)]
    pub buyer: Signer<'info>,

    /// SPL Token program.
    pub token_program: Program<'info, Token>,
    /// Associated Token program.
    pub associated_token_program: Program<'info, AssociatedToken>,
    /// Metaplex Token Metadata program.
    pub metadata_program: Program<'info, Metadata>,
    /// System program.
    pub system_program: Program<'info, System>,
    /// Rent sysvar.
    pub rent: Sysvar<'info, Rent>,
}

/// Accounts required for cancelling a commitment.
#[derive(Accounts)]
pub struct CancelCommitment<'info> {
    /// The commitment to cancel (will be closed and rent returned).
    #[account(
        mut,
        close = seller,
        has_one = seller
    )]
    pub commitment: Account<'info, Commitment>,

    /// The seller who created the commitment.
    #[account(mut)]
    pub seller: Signer<'info>,
}

/// Emitted when the program is initialized.
#[event]
pub struct ProgramInitialized {
    /// The authority who initialized the program.
    pub authority: Pubkey,
}

/// Emitted when a new commitment is created.
#[event]
pub struct CommitmentCreated {
    /// The SHA256 hash of the secret.
    pub hash: [u8; 32],
    /// The token ID for the NFT.
    pub token_id: u64,
    /// The price in lamports.
    pub price: u64,
    /// The seller's address.
    pub seller: Pubkey,
    /// The mint account address.
    pub mint: Pubkey,
    /// The NFT name.
    pub name: String,
    /// The NFT symbol.
    pub symbol: String,
    /// The metadata URI.
    pub uri: String,
}

/// Emitted when a secret is revealed during minting.
///
/// This event is critical for cross-chain verification as it contains
/// the revealed secret that can be used to claim Bitcoin.
#[event]
pub struct SecretRevealed {
    /// The revealed secret preimage.
    pub secret: [u8; 32],
    /// The hash that was committed.
    pub hash: [u8; 32],
    /// The token ID that was minted.
    pub token_id: u64,
    /// The buyer who revealed the secret.
    pub buyer: Pubkey,
    /// The seller who receives payment.
    pub seller: Pubkey,
    /// The mint account address.
    pub mint: Pubkey,
    /// The price paid in lamports.
    pub price: u64,
}

/// Emitted when an NFT is successfully minted.
#[event]
pub struct NFTMinted {
    /// The token ID that was minted.
    pub token_id: u64,
    /// The buyer who received the NFT.
    pub buyer: Pubkey,
    /// The secret used for minting.
    pub secret: [u8; 32],
}

/// Emitted when a commitment is cancelled.
#[event]
pub struct CommitmentCancelled {
    /// The hash of the cancelled commitment.
    pub hash: [u8; 32],
    /// The token ID that was released.
    pub token_id: u64,
    /// The seller who cancelled.
    pub seller: Pubkey,
}

/// Program error codes.
#[error_code]
pub enum ErrorCode {
    /// A commitment already exists for this token ID.
    #[msg("Commitment already exists for this hash")]
    CommitmentAlreadyExists,
    /// The commitment has already been fulfilled.
    #[msg("Commitment has already been used")]
    CommitmentAlreadyUsed,
    /// The provided secret does not hash to the expected value.
    #[msg("Invalid secret provided")]
    InvalidSecret,
    /// The token ID does not match the commitment.
    #[msg("Token ID mismatch")]
    TokenIdMismatch,
    /// The caller is not authorized to perform this action.
    #[msg("Unauthorized")]
    Unauthorized,
    /// The price is below the minimum allowed.
    #[msg("Invalid price")]
    InvalidPrice,
    /// The NFT name exceeds the maximum length.
    #[msg("Name too long")]
    NameTooLong,
    /// The NFT symbol exceeds the maximum length.
    #[msg("Symbol too long")]
    SymbolTooLong,
    /// The metadata URI exceeds the maximum length.
    #[msg("URI too long")]
    UriTooLong,
    /// An arithmetic overflow occurred.
    #[msg("Arithmetic overflow")]
    Overflow,
}
