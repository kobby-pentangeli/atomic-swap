//! Hash Time Locked Contract (HTLC) for Solana NFT minting.
//!
//! The NFT-chain side of a cross-chain atomic swap. A seller commits to mint a
//! token behind the SHA-256 hash of a secret; a buyer who knows the preimage
//! reveals it to mint the NFT (after locking Bitcoin in the matching HTLC); the
//! seller then reuses that now-public secret to claim the Bitcoin. The reveal is
//! the cross-chain hinge: the same preimage satisfies `OP_SHA256` on Bitcoin.
//!
//! # Hash algorithm
//!
//! SHA-256 (`sha2::Sha256`) matches Bitcoin's `OP_SHA256` and Ethereum's
//! `sha256(secret)`, keeping the preimage consistent across all three chains.
//!
//! # Lifecycle
//!
//! 1. [`sol_htlc::commit_for_mint`] records a commitment keyed by `token_id`. No
//!    mint exists yet, so a cancelled commitment strands nothing.
//! 2. [`sol_htlc::mint_with_secret`] verifies the preimage, mints exactly one
//!    token, attaches metadata, and seals it as a Metaplex master edition so
//!    supply is provably one, then closes the commitment.
//! 3. [`sol_htlc::cancel_commitment`] lets the seller reclaim the commitment rent
//!    before a mint.

use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::metadata::mpl_token_metadata::types::DataV2;
use anchor_spl::metadata::{
    create_master_edition_v3, create_metadata_accounts_v3, CreateMasterEditionV3,
    CreateMetadataAccountsV3, Metadata,
};
use anchor_spl::token::{mint_to, Mint, MintTo, Token, TokenAccount};
use sha2::{Digest, Sha256};

declare_id!("2geXhC16Hc9Q9QBP4DQZx2xxUumXHLS5ugYqXwSB4jXo");

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

    /// Initializes the program-state PDA once, recording the caller as authority.
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

    /// Records a commitment to mint `token_id` behind `hash`.
    ///
    /// No mint account is created here; the mint is created at the reveal so a
    /// cancellation cannot strand a mint PDA or its rent. Binding `buyer` to a
    /// specific key restricts who may mint; `None` leaves the mint open to anyone.
    ///
    /// # Arguments
    ///
    /// * `hash` - SHA-256 hash of the secret (32 bytes).
    /// * `token_id` - Unique identifier for this NFT.
    /// * `price` - Price in lamports the buyer pays the seller.
    /// * `name` - NFT name (at most [`MAX_NAME_LEN`] bytes).
    /// * `symbol` - NFT symbol (at most [`MAX_SYMBOL_LEN`] bytes).
    /// * `uri` - Metadata URI (at most [`MAX_URI_LEN`] bytes).
    /// * `buyer` - Authorized minter, or `None` for an open mint.
    pub fn commit_for_mint(
        ctx: Context<CommitForMint>,
        hash: [u8; 32],
        token_id: u64,
        price: u64,
        name: String,
        symbol: String,
        uri: String,
        buyer: Option<Pubkey>,
    ) -> Result<()> {
        require!(name.len() <= MAX_NAME_LEN, ErrorCode::NameTooLong);
        require!(symbol.len() <= MAX_SYMBOL_LEN, ErrorCode::SymbolTooLong);
        require!(uri.len() <= MAX_URI_LEN, ErrorCode::UriTooLong);
        require!(price >= MIN_PRICE, ErrorCode::InvalidPrice);

        let commitment = &mut ctx.accounts.commitment;
        commitment.hash = hash;
        commitment.token_id = token_id;
        commitment.price = price;
        commitment.seller = ctx.accounts.seller.key();
        commitment.buyer = buyer;
        commitment.name = name.clone();
        commitment.symbol = symbol.clone();
        commitment.uri = uri.clone();
        commitment.bump = ctx.bumps.commitment;

        emit!(CommitmentCreated {
            hash,
            token_id,
            price,
            seller: ctx.accounts.seller.key(),
            buyer,
            name,
            symbol,
            uri,
        });

        Ok(())
    }

    /// Reveals the secret and mints the committed token to the buyer.
    ///
    /// Verifies the preimage against the commitment hash, enforces the optional
    /// buyer binding, transfers the price to the seller, mints exactly one token,
    /// attaches metadata, and seals it as a Metaplex master edition (`max_supply`
    /// 0) so the mint and freeze authorities pass to the edition PDA and supply is
    /// provably one. The commitment is closed and its rent returned to the seller;
    /// the persistent mint PDA then bars re-minting the same `token_id`.
    ///
    /// # Arguments
    ///
    /// * `secret` - The 32-byte secret preimage.
    /// * `token_id` - The token ID to mint (binds the commitment and mint PDAs).
    pub fn mint_with_secret(
        ctx: Context<MintWithSecret>,
        secret: [u8; 32],
        token_id: u64,
    ) -> Result<()> {
        let commitment = &ctx.accounts.commitment;

        if let Some(authorized) = commitment.buyer {
            require_keys_eq!(
                ctx.accounts.buyer.key(),
                authorized,
                ErrorCode::UnauthorizedBuyer
            );
        }

        let computed_hash: [u8; 32] = Sha256::digest(secret).into();
        require!(computed_hash == commitment.hash, ErrorCode::InvalidSecret);

        transfer(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                Transfer {
                    from: ctx.accounts.buyer.to_account_info(),
                    to: ctx.accounts.seller_info.to_account_info(),
                },
            ),
            commitment.price,
        )?;

        let signer_seeds: &[&[&[u8]]] = &[&[b"program_state", &[ctx.accounts.program_state.bump]]];

        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.key(),
                MintTo {
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.token_account.to_account_info(),
                    authority: ctx.accounts.program_state.to_account_info(),
                },
                signer_seeds,
            ),
            1,
        )?;

        create_metadata_accounts_v3(
            CpiContext::new_with_signer(
                ctx.accounts.metadata_program.key(),
                CreateMetadataAccountsV3 {
                    metadata: ctx.accounts.metadata.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    mint_authority: ctx.accounts.program_state.to_account_info(),
                    payer: ctx.accounts.buyer.to_account_info(),
                    update_authority: ctx.accounts.program_state.to_account_info(),
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
            false,
            true,
            None,
        )?;

        create_master_edition_v3(
            CpiContext::new_with_signer(
                ctx.accounts.metadata_program.key(),
                CreateMasterEditionV3 {
                    edition: ctx.accounts.master_edition.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    update_authority: ctx.accounts.program_state.to_account_info(),
                    mint_authority: ctx.accounts.program_state.to_account_info(),
                    payer: ctx.accounts.buyer.to_account_info(),
                    metadata: ctx.accounts.metadata.to_account_info(),
                    token_program: ctx.accounts.token_program.to_account_info(),
                    system_program: ctx.accounts.system_program.to_account_info(),
                    rent: ctx.accounts.rent.to_account_info(),
                },
                signer_seeds,
            ),
            Some(0),
        )?;

        let program_state = &mut ctx.accounts.program_state;
        program_state.total_minted = program_state
            .total_minted
            .checked_add(1)
            .ok_or(ErrorCode::Overflow)?;

        let commitment = &ctx.accounts.commitment;
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
            secret,
        });

        Ok(())
    }

    /// Closes an unfulfilled commitment, returning its rent to the seller.
    ///
    /// Only the original seller may cancel. No mint exists before the reveal, so
    /// cancellation always fully recovers the committed state.
    pub fn cancel_commitment(ctx: Context<CancelCommitment>) -> Result<()> {
        let commitment = &ctx.accounts.commitment;

        emit!(CommitmentCancelled {
            hash: commitment.hash,
            token_id: commitment.token_id,
            seller: commitment.seller,
        });

        Ok(())
    }
}

/// Global program state stored in a PDA.
#[account]
#[derive(InitSpace)]
pub struct ProgramState {
    /// The authority who initialized the program.
    pub authority: Pubkey,
    /// Total number of NFTs minted through this program.
    pub total_minted: u64,
    /// PDA bump seed for this account.
    pub bump: u8,
}

/// A seller's pending commitment to mint a token behind a secret hash.
///
/// Exists only while pending: it is closed on mint or cancel, so its presence is
/// exactly the set of open commitments.
#[account]
#[derive(InitSpace)]
pub struct Commitment {
    /// SHA-256 hash of the secret required to mint.
    pub hash: [u8; 32],
    /// Unique identifier for this NFT.
    pub token_id: u64,
    /// Price in lamports the buyer must pay.
    pub price: u64,
    /// Address of the seller who created this commitment.
    pub seller: Pubkey,
    /// Authorized minter, or `None` for an open mint.
    pub buyer: Option<Pubkey>,
    /// Name of the NFT.
    #[max_len(MAX_NAME_LEN)]
    pub name: String,
    /// Symbol of the NFT.
    #[max_len(MAX_SYMBOL_LEN)]
    pub symbol: String,
    /// Metadata URI for the NFT.
    #[max_len(MAX_URI_LEN)]
    pub uri: String,
    /// PDA bump seed for this account.
    pub bump: u8,
}

/// Accounts for program initialization.
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The program-state PDA to initialize.
    #[account(
        init,
        payer = authority,
        space = 8 + ProgramState::INIT_SPACE,
        seeds = [b"program_state"],
        bump
    )]
    pub program_state: Account<'info, ProgramState>,

    /// The authority initializing the program (pays for account creation).
    #[account(mut)]
    pub authority: Signer<'info>,

    /// System program for account creation.
    pub system_program: Program<'info, System>,
}

/// Accounts for creating a mint commitment.
#[derive(Accounts)]
#[instruction(hash: [u8; 32], token_id: u64)]
pub struct CommitForMint<'info> {
    /// The commitment PDA storing the commitment data.
    #[account(
        init,
        payer = seller,
        space = 8 + Commitment::INIT_SPACE,
        seeds = [b"commitment", token_id.to_le_bytes().as_ref()],
        bump
    )]
    pub commitment: Account<'info, Commitment>,

    /// The seller creating the commitment (pays for account creation).
    #[account(mut)]
    pub seller: Signer<'info>,

    /// System program for account creation.
    pub system_program: Program<'info, System>,
}

/// Accounts for minting an NFT by revealing the secret.
#[derive(Accounts)]
#[instruction(secret: [u8; 32], token_id: u64)]
pub struct MintWithSecret<'info> {
    /// The commitment being fulfilled; closed to the seller on success.
    #[account(
        mut,
        close = seller_info,
        seeds = [b"commitment", token_id.to_le_bytes().as_ref()],
        bump = commitment.bump
    )]
    pub commitment: Account<'info, Commitment>,

    /// The NFT mint.
    #[account(
        init,
        payer = buyer,
        mint::decimals = 0,
        mint::authority = program_state,
        mint::freeze_authority = program_state,
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

    /// The Metaplex metadata account for the NFT.
    /// CHECK: PDA derived and written by the Token Metadata program via CPI.
    #[account(
        mut,
        seeds = [b"metadata", metadata_program.key().as_ref(), mint.key().as_ref()],
        bump,
        seeds::program = metadata_program.key()
    )]
    pub metadata: UncheckedAccount<'info>,

    /// The master-edition account that enforces non-fungibility.
    /// CHECK: PDA derived and written by the Token Metadata program via CPI.
    #[account(
        mut,
        seeds = [
            b"metadata",
            metadata_program.key().as_ref(),
            mint.key().as_ref(),
            b"edition",
        ],
        bump,
        seeds::program = metadata_program.key()
    )]
    pub master_edition: UncheckedAccount<'info>,

    /// The global program-state PDA (mint authority and mint counter).
    #[account(
        mut,
        seeds = [b"program_state"],
        bump = program_state.bump
    )]
    pub program_state: Account<'info, ProgramState>,

    /// The seller, who receives payment and the closed commitment's rent.
    /// CHECK: constrained to equal the commitment's recorded seller.
    #[account(mut, constraint = seller_info.key() == commitment.seller @ ErrorCode::Unauthorized)]
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

/// Accounts for cancelling a commitment.
#[derive(Accounts)]
pub struct CancelCommitment<'info> {
    /// The commitment to cancel; closed and rent returned to the seller.
    #[account(mut, close = seller, has_one = seller @ ErrorCode::Unauthorized)]
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
    /// The SHA-256 hash of the secret.
    pub hash: [u8; 32],
    /// The token ID for the NFT.
    pub token_id: u64,
    /// The price in lamports.
    pub price: u64,
    /// The seller's address.
    pub seller: Pubkey,
    /// The authorized minter, or `None` for an open mint.
    pub buyer: Option<Pubkey>,
    /// The NFT name.
    pub name: String,
    /// The NFT symbol.
    pub symbol: String,
    /// The metadata URI.
    pub uri: String,
}

/// Emitted when a secret is revealed during minting.
///
/// Carries the revealed preimage used to claim Bitcoin on the other chain.
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
    /// The provided secret does not hash to the committed value.
    #[msg("Invalid secret provided")]
    InvalidSecret,
    /// The caller is not authorized to perform this action.
    #[msg("Unauthorized")]
    Unauthorized,
    /// The caller is not the commitment's authorized buyer.
    #[msg("Caller is not the authorized buyer")]
    UnauthorizedBuyer,
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
