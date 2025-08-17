use anyhow::Context;
use bitcoin::key::Keypair;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute, consensus, transaction,
};
use bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use btc_htlc::Contract as BtcContract;
use tracing::{debug, error, info, warn};

use crate::types::{BitcoinTx, UtxoInfo};

mod signer;

use signer::BtcTxSigner;

pub struct BtcClient {
    rpc: RpcClient,
    network: Network,
    signer: BtcTxSigner,
}

impl BtcClient {
    pub fn new(
        rpc_url: &str,
        auth: Auth,
        network: Network,
        keypair: Keypair,
    ) -> anyhow::Result<Self> {
        let rpc = RpcClient::new(rpc_url, auth).context("Failed to create Bitcoin RPC client")?;

        // connection test
        let _info = rpc
            .get_blockchain_info()
            .context("Failed to connect to Bitcoin node")?;
        info!("Connected to Bitcoin {network}");

        Ok(Self {
            rpc,
            network,
            signer: BtcTxSigner::new(keypair),
        })
    }

    pub async fn lock_funds(&self, contract: &BtcContract, amount: Amount) -> anyhow::Result<Txid> {
        let address = contract.address();
        info!("Funding contract at {address} with {} BTC", amount.to_btc());

        let utxos = self.get_spendable_utxos(amount + Amount::from_sat(10000))?; // +fee buffer
        if utxos.is_empty() {
            return Err(anyhow::anyhow!("Insufficient funds"));
        }

        let total_input = utxos.iter().map(|utxo| utxo.tx_out.value).sum::<Amount>();

        let inputs = utxos
            .iter()
            .map(|utxo| TxIn {
                previous_output: OutPoint {
                    txid: utxo.outpoint.txid,
                    vout: utxo.outpoint.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect::<Vec<TxIn>>();

        // TODO (kobby-pentangeli): Robust fee estimation
        let estimated_fee = self.estimate_fee(inputs.len(), 2)?;
        let change_amount = total_input - amount - estimated_fee;

        let mut outputs = vec![TxOut {
            value: amount,
            script_pubkey: address.script_pubkey(),
        }];

        if change_amount > Amount::from_sat(546) {
            // Dust limit
            let change_address = self.get_new_address()?;
            outputs.push(TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            });
        }

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        self.signer.sign_transaction(&tx, &utxos)?;

        let txid = self
            .rpc
            .send_raw_transaction(&tx)
            .context("Failed to broadcast transaction")?;
        info!("Contract funded successfully: {txid}");
        debug!("Transaction: {}", consensus::encode::serialize_hex(&tx));

        Ok(txid)
    }

    pub async fn claim_funds(&self) -> anyhow::Result<Txid> {
        todo!()
    }

    /// Reclaim HTLC funds after timeout (buyer recovery)
    pub async fn reclaim_htlc_timeout(&self) -> anyhow::Result<Txid> {
        todo!()
    }

    /// Get transaction information
    pub fn get_transaction_info(&self, txid: &Txid) -> anyhow::Result<BitcoinTx> {
        let tx_info = self
            .rpc
            .get_raw_transaction_info(txid, None)
            .context("Failed to get transaction info")?;

        Ok(BitcoinTx {
            txid: *txid,
            confirmations: tx_info.confirmations.unwrap_or(0),
            block_hash: tx_info.blockhash,
            block_time: tx_info.blocktime,
        })
    }

    /// Check if HTLC has timed out
    pub fn is_htlc_expired(
        &self,
        contract: &BtcContract,
        htlc_txid: &Txid,
    ) -> anyhow::Result<bool> {
        let tx_info = self.get_transaction_info(htlc_txid)?;
        let current_height = self.rpc.get_block_count()?;

        if let Some(conf_height) = tx_info.block_height() {
            let blocks_passed = current_height.saturating_sub(conf_height);
            Ok(blocks_passed >= contract.timeout as u64)
        } else {
            Ok(false) // Not confirmed yet
        }
    }

    /// Monitor for new blocks
    pub async fn monitor_blocks<F>(&self, mut callback: F) -> anyhow::Result<()>
    where
        F: FnMut(u64) -> anyhow::Result<()>,
    {
        let mut last_height = self.rpc.get_block_count()?;
        info!("Starting block monitoring at height {}", last_height);

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

            match self.rpc.get_block_count() {
                Ok(current_height) => {
                    if current_height > last_height {
                        debug!("New block detected: {}", current_height);
                        if let Err(e) = callback(current_height) {
                            error!("Block callback error: {}", e);
                        }
                        last_height = current_height;
                    }
                }
                Err(e) => {
                    warn!("Failed to get block count: {e}");
                }
            }
        }
    }

    /// Get current network fee rate (sat/vB)
    pub fn get_fee_rate(&self) -> anyhow::Result<f64> {
        // Try to get smart fee estimate for 6 blocks
        match self.rpc.estimate_smart_fee(6, None) {
            Ok(fee_result) => {
                if let Some(fee_rate) = fee_result.fee_rate {
                    Ok(fee_rate.to_btc() * 100_000_000.0) // Convert BTC/kB to sat/B
                } else {
                    warn!("No fee estimate available, using fallback");
                    Ok(10.0) // Fallback fee rate
                }
            }
            Err(_) => {
                warn!("Smart fee estimation failed, using fallback");
                Ok(10.0)
            }
        }
    }

    /// Get spendable UTXOs with at least the specified amount
    fn get_spendable_utxos(&self, min_amount: Amount) -> anyhow::Result<Vec<UtxoInfo>> {
        let unspent = self
            .rpc
            .list_unspent(None, None, None, None, None)
            .context("Failed to list unspent outputs")?;

        let mut utxos = Vec::new();
        let mut total = Amount::ZERO;

        // Sort by amount descending to use larger UTXOs first
        let mut sorted_unspent = unspent;
        sorted_unspent.sort_by(|a, b| b.amount.cmp(&a.amount));

        for utxo in sorted_unspent {
            if utxo.spendable {
                utxos.push(UtxoInfo {
                    outpoint: OutPoint {
                        txid: utxo.txid,
                        vout: utxo.vout,
                    },
                    tx_out: TxOut {
                        value: utxo.amount,
                        script_pubkey: utxo.script_pub_key,
                    },
                });
                total += utxo.amount;

                if total >= min_amount {
                    break;
                }
            }
        }

        if total < min_amount {
            return Err(anyhow::anyhow!(
                "Insufficient funds: need {}, have {}",
                min_amount.to_btc(),
                total.to_btc()
            ));
        }

        Ok(utxos)
    }

    /// Estimate transaction fee
    fn estimate_fee(&self, inputs: usize, outputs: usize) -> anyhow::Result<Amount> {
        let fee_rate = self.get_fee_rate()?;

        // Estimate transaction size (simplified)
        // P2WPKH input: ~68 vbytes, P2WPKH output: ~31 vbytes, overhead: ~11 vbytes
        let estimated_vbytes = 11 + (inputs * 68) + (outputs * 31);
        let fee_sats = (estimated_vbytes as f64 * fee_rate).ceil() as u64;

        Ok(Amount::from_sat(fee_sats))
    }

    /// Get a new address from the wallet
    fn get_new_address(&self) -> anyhow::Result<Address> {
        let addr = self
            .rpc
            .get_new_address(None, None)?
            .require_network(self.network)?;
        Ok(addr)
    }
}
