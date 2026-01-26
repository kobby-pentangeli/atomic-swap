use anyhow::{Result, anyhow};
use bitcoin::{Amount, TxOut};
use bitcoincore_rpc::{Client as RpcClient, RpcApi};

/// Dust threshold for Bitcoin outputs.
pub(super) const DUST_THRESHOLD: Amount = Amount::from_sat(546);

/// Default fee rate fallback (sat/vB) when estimation fails.
const FALLBACK_FEE_RATE: f64 = 10.0;

/// Get the current network fee rate in sat/vB.
///
/// Attempts to get a smart fee estimate for 6-block confirmation.
/// Falls back to a default rate if estimation fails.
pub fn get_fee_rate(rpc: &RpcClient) -> Result<f64> {
    rpc.estimate_smart_fee(6, None)
        .ok()
        .and_then(|result| result.fee_rate)
        .map(|rate| rate.to_btc() * 100_000_000.0)
        .or_else(|| {
            tracing::warn!("Fee estimation failed, using fallback rate");
            Some(FALLBACK_FEE_RATE)
        })
        .ok_or_else(|| anyhow!("Fee rate unavailable"))
}

/// Estimate fee for HTLC funding transaction.
pub fn estimate_fee_for_htlc_funding(
    rpc: &RpcClient,
    inputs: usize,
    outputs: usize,
) -> Result<Amount> {
    get_fee_rate(rpc).map(|rate| {
        let vbytes = 11 + (inputs * 68) + (outputs * 43);
        Amount::from_sat((vbytes as f64 * rate).ceil() as u64)
    })
}

/// Estimate fee for HTLC claim transaction.
pub fn estimate_fee_for_htlc_claim(rpc: &RpcClient) -> Result<Amount> {
    get_fee_rate(rpc).map(|rate| {
        let vbytes = 11 + 150 + 31; // HTLC claim includes script + secret
        Amount::from_sat((vbytes as f64 * rate).ceil() as u64)
    })
}

/// Estimate fee for HTLC timeout transaction.
pub fn estimate_fee_for_htlc_timeout(rpc: &RpcClient) -> Result<Amount> {
    get_fee_rate(rpc).map(|rate| {
        let vbytes = 11 + 120 + 31; // HTLC timeout is smaller than claim
        Amount::from_sat((vbytes as f64 * rate).ceil() as u64)
    })
}

/// Calculate claim amount after fees.
pub fn calculate_claim_amount(rpc: &RpcClient, output: &TxOut) -> Result<(Amount, Amount)> {
    let fee = estimate_fee_for_htlc_claim(rpc)?;
    validate_amount_after_fee(output.value, fee)
}

/// Calculate timeout refund amount after fees.
pub fn calculate_timeout_amount(rpc: &RpcClient, output: &TxOut) -> Result<(Amount, Amount)> {
    let fee = estimate_fee_for_htlc_timeout(rpc)?;
    validate_amount_after_fee(output.value, fee)
}

/// Verify that amount is sufficient after fee deduction.
fn validate_amount_after_fee(amount: Amount, fee: Amount) -> Result<(Amount, Amount)> {
    let net_amount = amount
        .checked_sub(fee)
        .ok_or_else(|| anyhow!("Amount {amount} insufficient to cover fee {fee}"))?;

    if net_amount <= DUST_THRESHOLD {
        return Err(anyhow!(
            "Amount {net_amount} below dust threshold after {fee} fee",
        ));
    }

    Ok((net_amount, fee))
}
