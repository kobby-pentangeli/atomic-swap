//! End-to-end swap matrix.
//!
//! Each test stands up real local chains and drives the real client, so they are
//! `#[ignore]`d: the default `cargo test` compiles them, and they
//! run on demand with `--ignored`. They serialize through
//! the harness's swap lock, so `--test-threads` need not be set.
//!
//! Coverage: the happy path on each NFT chain for open and bound mints (the core
//! atomicity claim), the two recovery paths (buyer refund after timeout, seller
//! cancel then buyer refund), and the defection paths (unsafe timelock, premature
//! refund, wrong secret, bound-mint wrong caller, mint replay).

use anyhow::{Result, ensure};
use e2e::{AtomicSwap, NftChain, SAFE_TIMEOUT};

/// Drive the full swap and assert the BTC settles to the seller via the secret
/// revealed on the NFT chain (and, on Ethereum, that the buyer owns the token).
fn successful_swap(chain: NftChain, bound: bool) -> Result<()> {
    let swap = AtomicSwap::setup(chain)?;
    let seller_before = swap.seller_btc_sats()?;

    let lock = swap.lock_btc(SAFE_TIMEOUT)?;
    swap.commit(&lock.secret_hash, bound)?;
    swap.advance_for_mint()?;
    let mint = swap.mint()?;

    let claim = swap.claim_btc(&mint.secret_revealed, &lock)?;
    ensure!(!claim.txid.is_empty(), "claim produced no txid");

    let seller_after = swap.seller_btc_sats()?;
    ensure!(
        seller_after > seller_before,
        "seller did not receive the locked Bitcoin ({seller_before} -> {seller_after})"
    );

    if let Some(expected_owner) = swap.expected_nft_owner() {
        ensure!(
            swap.eth_token_owner()? == Some(expected_owner.clone()),
            "minted NFT is not owned by the buyer"
        );
    }
    Ok(())
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn eth_successful_swap_open_mint() -> Result<()> {
    successful_swap(NftChain::Ethereum, false)
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn eth_successful_swap_bound_buyer() -> Result<()> {
    successful_swap(NftChain::Ethereum, true)
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn sol_successful_swap_open_mint() -> Result<()> {
    successful_swap(NftChain::Solana, false)
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn sol_successful_swap_bound_buyer() -> Result<()> {
    successful_swap(NftChain::Solana, true)
}

/// Buyer commits to the swap but never reveals; after the timeout the Bitcoin
/// returns to the buyer and the seller receives nothing.
fn refund_after_timeout(chain: NftChain) -> Result<()> {
    let swap = AtomicSwap::setup(chain)?;
    let lock = swap.lock_btc(SAFE_TIMEOUT)?;
    swap.commit(&lock.secret_hash, false)?;

    let refund = swap.refund_btc(&lock)?;
    ensure!(!refund.txid.is_empty(), "refund produced no txid");
    ensure!(
        swap.seller_btc_sats()? == 0,
        "seller must not receive Bitcoin on a refund"
    );
    Ok(())
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn eth_buyer_refund_after_timeout() -> Result<()> {
    refund_after_timeout(NftChain::Ethereum)
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn sol_buyer_refund_after_timeout() -> Result<()> {
    refund_after_timeout(NftChain::Solana)
}

/// Seller cancels the commitment, then the buyer reclaims the Bitcoin after the
/// timeout. No funds are stranded on either chain.
fn cancel_then_refund(chain: NftChain) -> Result<()> {
    let swap = AtomicSwap::setup(chain)?;
    let lock = swap.lock_btc(SAFE_TIMEOUT)?;
    swap.commit(&lock.secret_hash, false)?;
    swap.cancel()?;

    let refund = swap.refund_btc(&lock)?;
    ensure!(!refund.txid.is_empty(), "refund produced no txid");
    ensure!(
        swap.seller_btc_sats()? == 0,
        "seller must not receive Bitcoin after cancelling"
    );
    Ok(())
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn eth_seller_cancel_then_buyer_refund() -> Result<()> {
    cancel_then_refund(NftChain::Ethereum)
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn sol_seller_cancel_then_buyer_refund() -> Result<()> {
    cancel_then_refund(NftChain::Solana)
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn timelock_unsafe_window_rejected() -> Result<()> {
    let swap = AtomicSwap::setup(NftChain::Ethereum)?;
    // A window below the safe minimum would let the buyer reveal-and-refund out
    // from under the seller; the client must refuse it at lock time.
    let err = swap.expect_lock_rejected(SAFE_TIMEOUT / 2)?;
    ensure!(!err.is_empty(), "rejection carried no explanation");
    Ok(())
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn premature_refund_rejected() -> Result<()> {
    let swap = AtomicSwap::setup(NftChain::Ethereum)?;
    let _lock = swap.lock_btc(SAFE_TIMEOUT)?;
    // The refund locktime has not been reached, so the node rejects the spend.
    swap.expect_refund_premature()?;
    Ok(())
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn wrong_secret_claim_rejected() -> Result<()> {
    let swap = AtomicSwap::setup(NftChain::Ethereum)?;
    let lock = swap.lock_btc(SAFE_TIMEOUT)?;
    // A claim with a non-matching preimage fails the hashlock and is refused.
    swap.expect_claim_wrong_secret(&lock)?;
    ensure!(
        swap.seller_btc_sats()? == 0,
        "seller must not obtain Bitcoin with a wrong secret"
    );
    Ok(())
}

/// A bound mint must reject any caller other than the authorized buyer.
fn bound_mint_rejects_other_caller(chain: NftChain) -> Result<()> {
    let swap = AtomicSwap::setup(chain)?;
    let lock = swap.lock_btc(SAFE_TIMEOUT)?;
    swap.commit(&lock.secret_hash, true)?;
    swap.advance_for_mint()?;
    swap.expect_mint_rejected_for_wrong_caller()?;
    Ok(())
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn eth_bound_mint_rejects_other_caller() -> Result<()> {
    bound_mint_rejects_other_caller(NftChain::Ethereum)
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn sol_bound_mint_rejects_other_caller() -> Result<()> {
    bound_mint_rejects_other_caller(NftChain::Solana)
}

/// Once minted, the same token cannot be minted again (replay protection).
fn mint_replay_rejected(chain: NftChain) -> Result<()> {
    let swap = AtomicSwap::setup(chain)?;
    let lock = swap.lock_btc(SAFE_TIMEOUT)?;
    swap.commit(&lock.secret_hash, false)?;
    swap.advance_for_mint()?;
    swap.mint()?;
    swap.expect_mint_replay_rejected()?;
    Ok(())
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn eth_mint_replay_rejected() -> Result<()> {
    mint_replay_rejected(NftChain::Ethereum)
}

#[test]
#[ignore = "spins up local chains; run with --ignored"]
fn sol_mint_replay_rejected() -> Result<()> {
    mint_replay_rejected(NftChain::Solana)
}
