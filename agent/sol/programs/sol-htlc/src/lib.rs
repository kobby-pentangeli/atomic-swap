//! Hash Time Locked Contract (HTLC) for Solana

#![allow(unexpected_cfgs)]
// TODO (kobby-pentangeli):
// remove once future `Anchor` versions fix warnings
#![allow(deprecated)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{keccak, system_instruction};
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::metadata::mpl_token_metadata::types::DataV2;
use anchor_spl::metadata::{create_metadata_accounts_v3, CreateMetadataAccountsV3, Metadata};
use anchor_spl::token::{mint_to, Mint, MintTo, Token, TokenAccount};

declare_id!("Dut9qhBMYA4nGejGPD2hb9ine7dR2z7LqYrZvrz6zENR");

const MAX_NAME_LEN: usize = 32;
const MAX_SYMBOL_LEN: usize = 10;
const MAX_URI_LEN: usize = 200;
const MIN_PRICE: u64 = 1; // in lamports

#[program]
pub mod sol_htlc {

    use super::*;

    /// Initializes the program state
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

    /// Creates a commitment for future NFT minting
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

    /// Mints NFT by revealing the secret that matches the commitment hash
    pub fn mint_with_secret(
        ctx: Context<MintWithSecret>,
        secret: [u8; 32],
        token_id: u64,
    ) -> Result<()> {
        let commitment = &mut ctx.accounts.commitment;

        require!(!commitment.is_used, ErrorCode::CommitmentAlreadyUsed);
        require!(commitment.token_id == token_id, ErrorCode::TokenIdMismatch);

        let computed_hash = keccak::hash(&secret);
        require!(computed_hash.0 == commitment.hash, ErrorCode::InvalidSecret);

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

    /// Allows seller to cancel a commitment that hasn't been used
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

#[account]
#[derive(Default)]
pub struct ProgramState {
    pub authority: Pubkey,
    pub total_minted: u64,
    pub bump: u8,
}

#[account]
#[derive(Default)]
pub struct Commitment {
    pub hash: [u8; 32],
    pub token_id: u64,
    pub price: u64,
    pub seller: Pubkey,
    pub mint: Pubkey,
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub is_used: bool,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + std::mem::size_of::<ProgramState>(),
        seeds = [b"program_state"],
        bump
    )]
    pub program_state: Account<'info, ProgramState>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(hash: [u8; 32], token_id: u64)]
pub struct CommitForMint<'info> {
    #[account(
        init,
        payer = seller,
        space = 8 + 32 + 8 + 8 + 32 + 32 +
                (4 + MAX_NAME_LEN) + (4 + MAX_SYMBOL_LEN) + (4 + MAX_URI_LEN) + 1 + 1,
        seeds = [b"commitment", hash.as_ref()],
        bump
    )]
    pub commitment: Account<'info, Commitment>,

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

    #[account(
        seeds = [b"program_state"],
        bump = program_state.bump
    )]
    pub program_state: Account<'info, ProgramState>,

    #[account(mut)]
    pub seller: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(secret: [u8; 32], token_id: u64)]
pub struct MintWithSecret<'info> {
    #[account(
        mut,
        seeds = [b"commitment", keccak::hash(&secret).to_bytes().as_ref()],
        bump = commitment.bump
    )]
    pub commitment: Account<'info, Commitment>,

    #[account(
        mut,
        seeds = [b"mint", token_id.to_le_bytes().as_ref()],
        bump
    )]
    pub mint: Account<'info, Mint>,

    #[account(
        init_if_needed,
        payer = buyer,
        associated_token::mint = mint,
        associated_token::authority = buyer
    )]
    pub token_account: Account<'info, TokenAccount>,

    /// CHECK: PDA derived from metadata program and mint
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

    #[account(
        mut,
        seeds = [b"program_state"],
        bump = program_state.bump
    )]
    pub program_state: Account<'info, ProgramState>,

    /// CHECK: Validated through commitment account
    #[account(mut)]
    pub seller_info: UncheckedAccount<'info>,

    #[account(mut)]
    pub buyer: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub metadata_program: Program<'info, Metadata>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct CancelCommitment<'info> {
    #[account(
        mut,
        close = seller,
        has_one = seller
    )]
    pub commitment: Account<'info, Commitment>,

    #[account(mut)]
    pub seller: Signer<'info>,
}

#[event]
pub struct ProgramInitialized {
    pub authority: Pubkey,
}

#[event]
pub struct CommitmentCreated {
    pub hash: [u8; 32],
    pub token_id: u64,
    pub price: u64,
    pub seller: Pubkey,
    pub mint: Pubkey,
    pub name: String,
    pub symbol: String,
    pub uri: String,
}

#[event]
pub struct SecretRevealed {
    pub secret: [u8; 32],
    pub hash: [u8; 32],
    pub token_id: u64,
    pub buyer: Pubkey,
    pub seller: Pubkey,
    pub mint: Pubkey,
    pub price: u64,
}

#[event]
pub struct NFTMinted {
    pub token_id: u64,
    pub buyer: Pubkey,
    pub secret: [u8; 32],
}

#[event]
pub struct CommitmentCancelled {
    pub hash: [u8; 32],
    pub token_id: u64,
    pub seller: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Commitment already exists for this hash")]
    CommitmentAlreadyExists,
    #[msg("Commitment has already been used")]
    CommitmentAlreadyUsed,
    #[msg("Invalid secret provided")]
    InvalidSecret,
    #[msg("Token ID mismatch")]
    TokenIdMismatch,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Invalid price")]
    InvalidPrice,
    #[msg("Name too long")]
    NameTooLong,
    #[msg("Symbol too long")]
    SymbolTooLong,
    #[msg("URI too long")]
    UriTooLong,
    #[msg("Arithmetic overflow")]
    Overflow,
}
