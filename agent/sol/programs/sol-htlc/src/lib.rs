//! Hash Time Locked Contract (HTLC) for Solana

// TODO (kobby-pentangeli):
// remove once future `Anchor` versions fix warnings
#![allow(unexpected_cfgs)]
#![allow(deprecated)]

use anchor_lang::prelude::*;

declare_id!("Dut9qhBMYA4nGejGPD2hb9ine7dR2z7LqYrZvrz6zENR");

#[program]
pub mod sol_htlc {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
