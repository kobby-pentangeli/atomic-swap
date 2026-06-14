//! The two-timelock ordering invariant that makes the swap atomic.
//!
//! A hash-timelocked swap is only safe if the party who acts second always holds
//! a strictly longer window than the party who acts first. Here the buyer locks
//! Bitcoin behind a hashlock with a block-height refund deadline, and the seller
//! commits an NFT behind the same hash with a wall-clock reveal deadline. When
//! the buyer reveals the secret to mint the NFT, the seller reuses that now-public
//! preimage to claim the Bitcoin; for that to always be possible the Bitcoin
//! refund must unlock strictly *after* the NFT reveal deadline, with margin for
//! the seller to confirm the claim. Otherwise a buyer could reveal-and-mint and
//! still refund the Bitcoin, walking away with both assets.
//!
//! The two deadlines live in different domains---Bitcoin in block height, the NFT
//! chains in wall-clock seconds---so the relationship is enforced by converting
//! the Bitcoin window to wall-clock at an assumed block interval and requiring it
//! to dominate the reveal window. The Bitcoin refund window must be at least
//! twice the reveal window: the first reveal-window's worth of time absorbs the
//! delay between the lock and the seller's commitment, and the second guarantees
//! that, once the secret is revealed at the latest possible moment, the seller
//! has ample time to confirm a Bitcoin claim before the refund unlocks.
//!
//! The conversion assumes Bitcoin's block interval stays near its ten-minute
//! target over the (roughly two-day) life of a swap; the doubling is the safety
//! margin that absorbs block-time variance on top of the commit delay and the
//! seller's settlement time. Operators wanting more headroom raise the Bitcoin
//! window further; the validators below only enforce the safe minimum.

use anyhow::{Result, anyhow};

/// NFT-chain reveal window in seconds: the maximum time a buyer has to reveal the
/// secret and mint after a commitment is created. Matches the on-chain reveal
/// deadline enforced by both the Ethereum contract (`COMMITMENT_TIMEOUT`) and the
/// Solana program (`COMMITMENT_TIMEOUT_SECS`).
pub const COMMITMENT_TIMEOUT_SECS: i64 = 24 * 60 * 60;

/// Assumed Bitcoin block interval used to convert a block-height refund window
/// into wall-clock seconds. Bitcoin targets ten-minute blocks.
pub const BTC_BLOCK_INTERVAL_SECS: i64 = 10 * 60;

/// Time budgeted for the seller to observe the revealed secret and confirm a
/// Bitcoin claim (roughly six confirmations) before the buyer's refund unlocks.
pub const SETTLEMENT_MARGIN_SECS: i64 = 60 * 60;

/// Smallest Bitcoin refund window, in blocks, that keeps the swap atomic: twice
/// the reveal window valued at the assumed block interval. Derived as
/// `2 * COMMITMENT_TIMEOUT_SECS / BTC_BLOCK_INTERVAL_SECS`.
pub const MIN_BTC_WINDOW_BLOCKS: u32 = 288;

/// Rejects a Bitcoin refund window too short to keep the swap atomic.
///
/// # Errors
///
/// Returns an error naming the safe minimum when `timeout_blocks` is below
/// [`MIN_BTC_WINDOW_BLOCKS`].
pub fn validate_btc_lock_window(timeout_blocks: u32) -> Result<()> {
    if timeout_blocks < MIN_BTC_WINDOW_BLOCKS {
        let hours = i64::from(MIN_BTC_WINDOW_BLOCKS) * BTC_BLOCK_INTERVAL_SECS / 3600;
        return Err(anyhow!(
            "Bitcoin refund window of {timeout_blocks} blocks is unsafe: it must be at least \
             {MIN_BTC_WINDOW_BLOCKS} blocks (~{hours}h at {}s/block) so the seller can always \
             claim Bitcoin after the secret is revealed and before the buyer can refund. \
             Increase the timeout.",
            BTC_BLOCK_INTERVAL_SECS,
        ));
    }
    Ok(())
}

/// Estimates the wall-clock time at which a Bitcoin refund window unlocks, given
/// the moment the funds were locked. Reported to the buyer so they can pass it to
/// the seller, who verifies the ordering before committing the NFT.
///
/// # Errors
///
/// Returns an error if the window or the resulting deadline overflows `i64`.
pub fn btc_refund_deadline_unix(locked_at_unix: i64, timeout_blocks: u32) -> Result<i64> {
    i64::from(timeout_blocks)
        .checked_mul(BTC_BLOCK_INTERVAL_SECS)
        .and_then(|window| locked_at_unix.checked_add(window))
        .ok_or_else(|| anyhow!("Bitcoin refund deadline overflows"))
}

/// Rejects committing an NFT when the buyer's Bitcoin refund would unlock before
/// the seller could safely claim: the new commitment's reveal deadline plus the
/// settlement margin must fall at or before the Bitcoin refund deadline.
///
/// # Errors
///
/// Returns an error when the ordering is unsafe, or if the arithmetic overflows.
pub fn validate_commit_window(now_unix: i64, btc_refund_deadline_unix: i64) -> Result<()> {
    let latest_safe_reveal = btc_refund_deadline_unix
        .checked_sub(SETTLEMENT_MARGIN_SECS)
        .ok_or_else(|| anyhow!("settlement margin underflows"))?;
    let reveal_deadline = now_unix
        .checked_add(COMMITMENT_TIMEOUT_SECS)
        .ok_or_else(|| anyhow!("reveal deadline overflows"))?;
    if reveal_deadline > latest_safe_reveal {
        return Err(anyhow!(
            "Unsafe timelock ordering: this commitment's reveal deadline would fall too close to \
             (or after) the buyer's Bitcoin refund, so the seller could not reliably claim before \
             a refund. The buyer must lock Bitcoin with a longer window, or the seller must commit \
             sooner after the lock."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_window_matches_derivation() {
        assert_eq!(
            i64::from(MIN_BTC_WINDOW_BLOCKS),
            2 * COMMITMENT_TIMEOUT_SECS / BTC_BLOCK_INTERVAL_SECS
        );
    }

    #[test]
    fn rejects_short_btc_window() {
        assert!(validate_btc_lock_window(MIN_BTC_WINDOW_BLOCKS - 1).is_err());
        assert!(validate_btc_lock_window(0).is_err());
    }

    #[test]
    fn accepts_safe_btc_window() {
        assert!(validate_btc_lock_window(MIN_BTC_WINDOW_BLOCKS).is_ok());
        assert!(validate_btc_lock_window(MIN_BTC_WINDOW_BLOCKS * 4).is_ok());
    }

    #[test]
    fn refund_deadline_adds_window() {
        let locked_at = 1_000_000;
        let deadline = btc_refund_deadline_unix(locked_at, MIN_BTC_WINDOW_BLOCKS).unwrap();
        assert_eq!(
            deadline,
            locked_at + i64::from(MIN_BTC_WINDOW_BLOCKS) * BTC_BLOCK_INTERVAL_SECS
        );
    }

    #[test]
    fn accepts_commit_within_safe_ordering() {
        let now = 1_000_000;
        let deadline = btc_refund_deadline_unix(now, MIN_BTC_WINDOW_BLOCKS).unwrap();
        assert!(validate_commit_window(now, deadline).is_ok());
    }

    #[test]
    fn rejects_commit_without_settlement_margin() {
        let now = 1_000_000;
        let deadline = now + COMMITMENT_TIMEOUT_SECS;
        assert!(validate_commit_window(now, deadline).is_err());
    }
}
