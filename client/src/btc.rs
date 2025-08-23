//! RPC client for Bitcoin

use anyhow::Context;
use bitcoin::address::NetworkChecked;
use bitcoin::key::Keypair;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute, consensus, transaction,
};
use bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use btc_htlc::Contract as BtcContract;
use tracing::{debug, info, warn};

use crate::types::UtxoInfo;

mod signer;
pub mod utils;

use signer::BtcTxSigner;

pub struct BtcClient {
    rpc: RpcClient,
    network: Network,
    signer: BtcTxSigner,
    own_address: Address,
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
        let info = rpc
            .get_blockchain_info()
            .context("Failed to connect to Bitcoin node")?;
        info!(
            "Connected to Bitcoin {network}. {} blocks processed",
            info.blocks
        );

        let signer = BtcTxSigner::new(keypair);
        let pubkey = signer.get_public_key()?;
        let own_address = Address::p2wpkh(&pubkey, network);

        debug!("Own address: {own_address}");

        Ok(Self {
            rpc,
            network,
            signer,
            own_address,
        })
    }

    pub async fn lock_funds(&self, contract: &BtcContract, amt: Amount) -> anyhow::Result<Txid> {
        let address = contract.address();
        info!("Funding contract at {address} with {} BTC", amt.to_btc());

        let utxos = self.get_spendable_utxos(amt + Amount::from_sat(1000), &[&self.own_address])?; // +fee buffer
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
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect::<Vec<TxIn>>();

        let fee = self.estimate_fee_for_htlc_funding(inputs.len(), 2)?;
        let change_amt = total_input - amt - fee;

        let mut outputs = vec![TxOut {
            value: amt,
            script_pubkey: address.script_pubkey(),
        }];

        if change_amt > Amount::from_sat(546) {
            // Dust limit
            let change_addr = self.get_new_address()?;
            outputs.push(TxOut {
                value: change_amt,
                script_pubkey: change_addr.script_pubkey(),
            });
        }

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        };
        let signed_tx = self.signer.sign_transaction(&tx, &utxos)?;
        let txid = self
            .rpc
            .send_raw_transaction(&signed_tx)
            .context("Failed to broadcast transaction")?;
        info!("Contract funded successfully: {txid}");
        info!(
            "Transaction: {}",
            consensus::encode::serialize_hex(&signed_tx)
        );

        Ok(txid)
    }

    pub async fn claim_funds(
        &self,
        contract: &BtcContract,
        secret: &[u8; 32],
        txid: Txid,
        vout: u32,
        destination: Option<Address>,
    ) -> anyhow::Result<Txid> {
        info!("Claiming funds for {txid}:{vout} with secret");

        if !contract.verify_secret(secret) {
            return Err(anyhow::anyhow!("Secret does not match contract hash"));
        }

        let tx = self
            .rpc
            .get_raw_transaction(&txid, None)
            .context("Failed to get fund-lock transaction")?;
        let output = tx
            .output
            .get(vout as usize)
            .context("Lock tx output not found")?;

        if output.script_pubkey != contract.address().script_pubkey() {
            return Err(anyhow::anyhow!("Lock transaction output script mismatch"));
        }

        let dest_addr = match destination {
            Some(addr) => addr,
            None => {
                let pubkey = self.signer.get_public_key()?;
                Address::p2wpkh(&pubkey, self.network)
            }
        };

        let fee = self.estimate_fee_for_htlc_claim()?;
        if output.value <= fee {
            return Err(anyhow::anyhow!("amount insufficient to cover fee"));
        }
        let amt = output.value - fee;
        if amt <= Amount::from_sat(546) {
            return Err(anyhow::anyhow!("amount too small after fee"));
        }

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: amt,
                script_pubkey: dest_addr.script_pubkey(),
            }],
        };

        let utxo = UtxoInfo {
            outpoint: OutPoint { txid, vout },
            tx_out: output.clone(),
        };
        let signed_tx = self
            .signer
            .sign_claim_transaction(&tx, &[utxo], contract, secret)?;
        let txid = self
            .rpc
            .send_raw_transaction(&signed_tx)
            .context("Failed to broadcast claim transaction")?;

        info!("Funds claimed successfully: {txid}",);
        info!("Claimed {} BTC to {dest_addr}", amt.to_btc());

        Ok(txid)
    }

    /// Reclaim funds after timeout (buyer recovery)
    pub async fn reclaim_funds_timeout(
        &self,
        contract: &BtcContract,
        txid: Txid,
        vout: u32,
        destination: Option<Address>,
    ) -> anyhow::Result<Txid> {
        info!("Reclaiming {txid}:{vout} after timeout");

        let current_height = self.rpc.get_block_count()?;
        if current_height < contract.timeout as u64 {
            return Err(anyhow::anyhow!(
                "timeout not reached. current height: {} timeout height: {}",
                current_height,
                contract.timeout
            ));
        }

        let tx = self
            .rpc
            .get_raw_transaction(&txid, None)
            .context("Failed to get transaction")?;
        let output = tx
            .output
            .get(vout as usize)
            .context("HTLC output not found")?;

        if output.script_pubkey != contract.address().script_pubkey() {
            return Err(anyhow::anyhow!("Output script mismatch"));
        }

        let dest_address = match destination {
            Some(addr) => addr,
            None => {
                let pubkey = self.signer.get_public_key()?;
                Address::p2wpkh(&pubkey, self.network)
            }
        };

        let fee = self.estimate_fee_for_htlc_timeout()?;
        if output.value <= fee {
            return Err(anyhow::anyhow!("amount insufficient to cover fee"));
        }
        let amt = output.value - fee;

        if amt <= Amount::from_sat(546) {
            return Err(anyhow::anyhow!("amount too small after fee"));
        }

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_height(contract.timeout)
                .context("Invalid timeout height")?,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(0),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: amt,
                script_pubkey: dest_address.script_pubkey(),
            }],
        };

        let utxo = UtxoInfo {
            outpoint: OutPoint { txid, vout },
            tx_out: output.clone(),
        };
        let signed_tx = self
            .signer
            .sign_timeout_transaction(&tx, &[utxo], contract)?;

        let txid = self
            .rpc
            .send_raw_transaction(&signed_tx)
            .context("Failed to broadcast reclaim transaction")?;

        info!("Funds reclaimed successfully: {txid}");

        Ok(txid)
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
    fn get_spendable_utxos(
        &self,
        min_amount: Amount,
        addresses: &[&Address<NetworkChecked>],
    ) -> anyhow::Result<Vec<UtxoInfo>> {
        let unspent = self
            .rpc
            .list_unspent(None, None, Some(addresses), None, None)
            .context("Failed to list unspent outputs")?;

        let targets: std::collections::HashSet<ScriptBuf> =
            addresses.iter().map(|addr| addr.script_pubkey()).collect();

        let mut utxos = Vec::new();
        let mut total = Amount::ZERO;

        // Sort by amount descending to use larger UTXOs first
        let mut sorted_unspent = unspent;
        sorted_unspent.sort_by(|a, b| b.amount.cmp(&a.amount));

        for utxo in sorted_unspent {
            if utxo.spendable && targets.contains(&utxo.script_pub_key) {
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

        info!(
            "Selected {} UTXOs totaling {} BTC",
            utxos.len(),
            total.to_btc()
        );
        Ok(utxos)
    }
    fn estimate_fee_for_htlc_funding(
        &self,
        inputs: usize,
        outputs: usize,
    ) -> anyhow::Result<Amount> {
        let fee_rate = self.get_fee_rate()?;
        // Standard P2WPKH inputs, P2WSH output
        let estimated_vbytes = 11 + (inputs * 68) + (outputs * 43); // P2WSH output is larger
        let fee_sats = (estimated_vbytes as f64 * fee_rate).ceil() as u64;
        Ok(Amount::from_sat(fee_sats))
    }

    fn estimate_fee_for_htlc_claim(&self) -> anyhow::Result<Amount> {
        let fee_rate = self.get_fee_rate()?;
        // P2WSH input with HTLC script (reveal path) + P2WPKH output
        let estimated_vbytes = 11 + 150 + 31; // HTLC claim is larger due to script + secret
        let fee_sats = (estimated_vbytes as f64 * fee_rate).ceil() as u64;
        Ok(Amount::from_sat(fee_sats))
    }

    fn estimate_fee_for_htlc_timeout(&self) -> anyhow::Result<Amount> {
        let fee_rate = self.get_fee_rate()?;
        // P2WSH input with HTLC script (timeout path) + P2WPKH output
        let estimated_vbytes = 11 + 120 + 31; // HTLC timeout is smaller than claim
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
