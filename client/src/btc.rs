//! Bitcoin RPC client for HTLC-based atomic swaps.
//!
//! Provides an interface for interacting with a Bitcoin node to perform
//! on-chain operations, including locking funds, claiming
//! with secret reveal, and reclaiming after timeout expiry.

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow};
use bitcoin::key::Keypair;
use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness, absolute, consensus, transaction,
};
use bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use btc_htlc::{Contract as BtcContract, HtlcCondition};
use tracing::{debug, info};

mod fee;
mod signer;

use signer::BtcTxSigner;

use crate::types::UtxoInfo;

/// Bitcoin RPC client with HTLC support.
///
/// Provides methods for creating, claiming, and recovering HTLC transactions.
pub struct BtcClient {
    rpc: RpcClient,
    network: Network,
    signer: BtcTxSigner,
    own_address: Address,
}

impl BtcClient {
    /// Create a new Bitcoin client.
    ///
    /// Establishes connection to the Bitcoin node and verifies connectivity
    /// before returning the client instance.
    ///
    /// # Arguments
    ///
    /// * `rpc_url` - URL of the Bitcoin RPC endpoint.
    /// * `auth` - Authentication credentials for RPC.
    /// * `network` - Bitcoin network (mainnet, testnet, regtest, signet).
    /// * `keypair` - Keypair for signing transactions.
    ///
    /// # Errors
    ///
    /// Returns an error if connection to the node fails or the node is
    /// on a different network than expected.
    pub fn new(rpc_url: &str, auth: Auth, network: Network, keypair: Keypair) -> Result<Self> {
        let rpc = RpcClient::new(rpc_url, auth).context("Failed to create Bitcoin RPC client")?;

        let info = rpc
            .get_blockchain_info()
            .context("Failed to connect to Bitcoin node")?;
        info!(
            "Connected to Bitcoin {network}. {} blocks processed",
            info.blocks
        );

        let signer = BtcTxSigner::new(keypair);
        let own_address = signer
            .compressed_public_key()
            .map(|pk| Address::p2wpkh(&pk, network))?;

        debug!("Own address: {own_address}");

        Ok(Self {
            rpc,
            network,
            signer,
            own_address,
        })
    }

    /// Lock funds in an HTLC contract.
    ///
    /// Creates and broadcasts a transaction that sends the specified amount
    /// to the contract address. The funds can be claimed by the counterparty
    /// with the secret or recovered after timeout.
    ///
    /// # Arguments
    ///
    /// * `contract` - The HTLC contract defining claim/timeout conditions.
    /// * `amount` - Amount to lock in the contract.
    ///
    /// # Returns
    ///
    /// The transaction ID of the funding transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Insufficient funds available
    /// - Transaction construction fails
    /// - Broadcast fails
    pub fn lock_funds(&self, contract: &BtcContract, amount: Amount) -> Result<Txid> {
        let address = contract.address();
        info!("Funding contract at {address} with {} BTC", amount.to_btc());

        let htlc_script = address.script_pubkey();
        let change_script = self.get_new_address()?.script_pubkey();
        let output_lens = [htlc_script.len(), change_script.len()];

        let rate = fee::fee_rate(&self.rpc);
        let (utxos, total_input, fee) = self.select_funding_utxos(amount, rate, &output_lens)?;

        let inputs = utxos
            .iter()
            .map(|utxo| TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect::<Vec<TxIn>>();

        let change_amount = total_input
            .checked_sub(amount)
            .and_then(|rem| rem.checked_sub(fee))
            .ok_or_else(|| anyhow!("Insufficient funds after fee calculation"))?;

        let mut outputs = vec![TxOut {
            value: amount,
            script_pubkey: htlc_script,
        }];
        if change_amount > fee::DUST_THRESHOLD {
            outputs.push(TxOut {
                value: change_amount,
                script_pubkey: change_script,
            });
        }

        let unsigned_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        let signed_tx = self.signer.sign_transaction(&unsigned_tx, &utxos)?;

        let lock_txid = self
            .rpc
            .send_raw_transaction(&signed_tx)
            .context("Failed to broadcast funding transaction")?;

        info!("Contract funded successfully: {lock_txid}");
        debug!(
            "Transaction hex: {}",
            consensus::encode::serialize_hex(&signed_tx)
        );

        Ok(lock_txid)
    }

    /// Claim funds from an HTLC by revealing the secret.
    ///
    /// Creates and broadcasts a transaction that spends the HTLC output
    /// using the secret preimage. This is typically called by the seller
    /// after the buyer has revealed the secret on another chain.
    ///
    /// # Arguments
    ///
    /// * `contract` - The HTLC contract.
    /// * `secret` - The 32-byte secret preimage.
    /// * `txid` - Transaction ID of the funding transaction.
    /// * `vout` - Output index in the funding transaction.
    /// * `dst` - Optional destination address (defaults to own address).
    ///
    /// # Returns
    ///
    /// The transaction ID of the claim transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Secret does not match the contract hash
    /// - Funding transaction output not found or mismatched
    /// - Amount is insufficient after fees
    pub fn claim_funds(
        &self,
        contract: &BtcContract,
        secret: &[u8; 32],
        txid: Txid,
        vout: u32,
        dst: Option<Address>,
    ) -> Result<Txid> {
        info!("Claiming funds from {txid}:{vout}");
        if !contract.verify_secret(secret) {
            return Err(anyhow!("Secret does not match contract hash"));
        }

        let output = self.get_and_verify_htlc_output(contract, txid, vout)?;
        let dest_addr = self.resolve_destination(dst)?;
        let dest_script = dest_addr.script_pubkey();

        let rate = fee::fee_rate(&self.rpc);
        let fee = fee::htlc_spend_fee(
            rate,
            contract,
            &HtlcCondition::Reveal { secret: *secret },
            dest_script.len(),
        )?;
        let claim_amount = fee::net_after_fee(output.value, fee)?;

        let unsigned_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: claim_amount,
                script_pubkey: dest_script,
            }],
        };

        let utxo = UtxoInfo {
            outpoint: OutPoint { txid, vout },
            tx_out: output,
        };

        let signed_tx =
            self.signer
                .sign_claim_transaction(&unsigned_tx, &[utxo], contract, secret)?;

        let claim_txid = self
            .rpc
            .send_raw_transaction(&signed_tx)
            .context("Failed to broadcast claim transaction")?;

        info!("Funds claimed successfully: {claim_txid}");
        info!(
            "Claimed {} BTC (fee: {} sats) to {dest_addr}",
            claim_amount.to_btc(),
            fee.to_sat()
        );

        Ok(claim_txid)
    }

    /// Reclaim funds from an HTLC after timeout expiry.
    ///
    /// Creates and broadcasts a transaction that spends the HTLC output
    /// using the timeout path. This is used by the buyer to recover funds
    /// if the swap was not completed.
    ///
    /// # Arguments
    ///
    /// * `contract` - The HTLC contract.
    /// * `txid` - Transaction ID of the funding transaction.
    /// * `vout` - Output index in the funding transaction.
    /// * `dst` - Optional destination address (defaults to own address).
    ///
    /// # Returns
    ///
    /// The transaction ID of the reclaim transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Timeout has not yet been reached
    /// - Funding transaction output not found or mismatched
    /// - Amount is insufficient after fees
    pub fn refund_timeout(
        &self,
        contract: &BtcContract,
        txid: Txid,
        vout: u32,
        dst: Option<Address>,
    ) -> Result<Txid> {
        info!("Refunding {txid}:{vout} via timeout path");
        let cur_height = self.rpc.get_block_count()?;
        let timeout_height = u64::from(contract.timeout);

        if cur_height < timeout_height {
            return Err(anyhow!(
                "Timeout not reached: current height {cur_height}, required {timeout_height}",
            ));
        }

        let output = self.get_and_verify_htlc_output(contract, txid, vout)?;
        let dest_addr = self.resolve_destination(dst)?;
        let dest_script = dest_addr.script_pubkey();

        let rate = fee::fee_rate(&self.rpc);
        let fee = fee::htlc_spend_fee(rate, contract, &HtlcCondition::Timeout, dest_script.len())?;
        let refund_amount = fee::net_after_fee(output.value, fee)?;
        let lock_time =
            absolute::LockTime::from_height(contract.timeout).context("Invalid timeout height")?;

        let unsigned_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: refund_amount,
                script_pubkey: dest_script,
            }],
        };

        let utxo = UtxoInfo {
            outpoint: OutPoint { txid, vout },
            tx_out: output,
        };

        let signed_tx = self
            .signer
            .sign_timeout_transaction(&unsigned_tx, &[utxo], contract)?;

        let refund_txid = self
            .rpc
            .send_raw_transaction(&signed_tx)
            .context("Failed to broadcast refund transaction")?;

        info!("BTC refunded successfully: {refund_txid}");
        info!(
            "Refunded {} BTC (fee: {} sats) to {dest_addr}",
            refund_amount.to_btc(),
            fee.to_sat()
        );

        Ok(refund_txid)
    }

    /// Returns the current best-block height.
    ///
    /// Used at lock time to convert a relative timeout window into the absolute
    /// block height committed in the HTLC script.
    pub fn block_height(&self) -> Result<u64> {
        self.rpc
            .get_block_count()
            .context("Failed to read current block height")
    }

    /// List the wallet's spendable UTXOs at the client's own address.
    fn list_spendable_utxos(&self) -> Result<Vec<UtxoInfo>> {
        let addresses = [&self.own_address];
        let target_scripts = addresses
            .iter()
            .map(|addr| addr.script_pubkey())
            .collect::<HashSet<_>>();

        let unspent = self
            .rpc
            .list_unspent(None, None, Some(&addresses), None, None)
            .context("Failed to list unspent outputs")?;

        Ok(unspent
            .into_iter()
            .filter(|utxo| utxo.spendable && target_scripts.contains(&utxo.script_pub_key))
            .map(|utxo| UtxoInfo {
                outpoint: OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                },
                tx_out: TxOut {
                    value: utxo.amount,
                    script_pubkey: utxo.script_pub_key,
                },
            })
            .collect())
    }

    /// Select UTXOs covering `amount` plus the funding fee, where the fee is
    /// derived from the segwit weight of the selected input set and the given
    /// output scripts. Returns the selection, its total value, and the fee, all
    /// consistent with one another so change is computed against the same fee.
    fn select_funding_utxos(
        &self,
        amount: Amount,
        rate: FeeRate,
        output_lens: &[usize],
    ) -> Result<(Vec<UtxoInfo>, Amount, Amount)> {
        let target = |selected: &[UtxoInfo]| -> Result<Amount> {
            let fee = fee::funding_fee(rate, selected.len(), output_lens)?;
            amount
                .checked_add(fee)
                .ok_or_else(|| anyhow!("Funding target overflowed"))
        };

        let (selected, total) = self.list_spendable_utxos()?.into_iter().try_fold(
            (Vec::new(), Amount::ZERO),
            |(mut selected, total), utxo| -> Result<(Vec<UtxoInfo>, Amount)> {
                if total >= target(&selected)? {
                    Ok((selected, total))
                } else {
                    let new_total = total
                        .checked_add(utxo.tx_out.value)
                        .ok_or_else(|| anyhow!("UTXO total overflowed"))?;
                    selected.push(utxo);
                    Ok((selected, new_total))
                }
            },
        )?;

        let fee = fee::funding_fee(rate, selected.len(), output_lens)?;
        let required = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("Funding target overflowed"))?;
        (total >= required).then_some(()).ok_or_else(|| {
            anyhow!(
                "Insufficient funds: need {} BTC including fee, have {} BTC",
                required.to_btc(),
                total.to_btc()
            )
        })?;

        info!(
            "Selected {} UTXOs totaling {} BTC",
            selected.len(),
            total.to_btc()
        );

        Ok((selected, total, fee))
    }

    /// Get and verify the HTLC output from a transaction.
    fn get_and_verify_htlc_output(
        &self,
        contract: &BtcContract,
        txid: Txid,
        vout: u32,
    ) -> Result<TxOut> {
        let tx = self
            .rpc
            .get_raw_transaction(&txid, None)
            .context("Failed to get transaction")?;

        let output = tx
            .output
            .get(vout as usize)
            .cloned()
            .ok_or_else(|| anyhow!("Output {vout} not found in transaction {txid}"))?;

        let expected_script = contract.address().script_pubkey();
        if output.script_pubkey != expected_script {
            return Err(anyhow!(
                "Script mismatch at {txid}:{vout}: expected contract script"
            ));
        }

        Ok(output)
    }

    /// Resolve destination address, defaulting to own address.
    fn resolve_destination(&self, dst: Option<Address>) -> Result<Address> {
        dst.map(Ok).unwrap_or_else(|| {
            self.signer
                .compressed_public_key()
                .map(|pk| Address::p2wpkh(&pk, self.network))
        })
    }

    /// Get a new address from the wallet.
    fn get_new_address(&self) -> Result<Address> {
        self.rpc
            .get_new_address(None, None)?
            .require_network(self.network)
            .map_err(|e| anyhow!("Address network mismatch: {e}"))
    }
}
