use anyhow::{Result, anyhow};
use bitcoin::transaction::{InputWeightPrediction, predict_weight};
use bitcoin::{Amount, FeeRate};
use bitcoincore_rpc::{Client as RpcClient, RpcApi};
use btc_htlc::{Contract as BtcContract, HtlcCondition};

/// Dust threshold for Bitcoin outputs.
pub(super) const DUST_THRESHOLD: Amount = Amount::from_sat(546);

/// Confirmation target, in blocks, for the smart-fee estimate.
const CONFIRMATION_TARGET: u16 = 6;

/// Conservative fee rate used when the node cannot produce an estimate (e.g. on
/// regtest, which has no fee history).
const FALLBACK_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(10);

/// Current network fee rate.
///
/// `estimatesmartfee` reports BTC per 1000 vbytes, which is satoshis per kvB once
/// taken as an integer; one vbyte is four weight units, so dividing by four
/// yields satoshis per kilo-weight-unit, the unit [`FeeRate`] stores. Falls back
/// to [`FALLBACK_FEE_RATE`] when no estimate is available.
pub fn fee_rate(rpc: &RpcClient) -> FeeRate {
    rpc.estimate_smart_fee(CONFIRMATION_TARGET, None)
        .ok()
        .and_then(|estimate| estimate.fee_rate)
        .map(|per_kvb| FeeRate::from_sat_per_kwu(per_kvb.to_sat().div_ceil(4)))
        .filter(|rate| *rate > FeeRate::ZERO)
        .unwrap_or_else(|| {
            tracing::warn!("Fee estimation unavailable, using fallback rate");
            FALLBACK_FEE_RATE
        })
}

/// Absolute fee for a P2WPKH-funded transaction with the given inputs and output
/// scripts, derived from the predicted segwit weight.
pub fn funding_fee(
    rate: FeeRate,
    num_inputs: usize,
    output_script_lens: &[usize],
) -> Result<Amount> {
    let weight = predict_weight(
        std::iter::repeat_n(InputWeightPrediction::P2WPKH_MAX, num_inputs),
        output_script_lens.iter().copied(),
    );
    rate.checked_mul_by_weight(weight)
        .ok_or_else(|| anyhow!("Funding fee calculation overflowed"))
}

/// Absolute fee for spending a single HTLC output under `cond` to an output with
/// `dst_script_len`-byte script, derived from the contract's own witness
/// prediction so the estimate tracks the real spend.
pub fn htlc_spend_fee(
    rate: FeeRate,
    contract: &BtcContract,
    cond: &HtlcCondition,
    dst_script_len: usize,
) -> Result<Amount> {
    let weight = predict_weight([contract.predict_input_weight(cond)], [dst_script_len]);
    rate.checked_mul_by_weight(weight)
        .ok_or_else(|| anyhow!("Spend fee calculation overflowed"))
}

/// Deducts `fee` from `value`, rejecting results that cannot cover the fee or
/// that fall to or below the dust threshold.
pub fn net_after_fee(value: Amount, fee: Amount) -> Result<Amount> {
    let net = value
        .checked_sub(fee)
        .ok_or_else(|| anyhow!("Amount {value} insufficient to cover fee {fee}"))?;

    (net > DUST_THRESHOLD)
        .then_some(net)
        .ok_or_else(|| anyhow!("Amount {net} below dust threshold after {fee} fee"))
}
