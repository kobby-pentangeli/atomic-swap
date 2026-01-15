//! Bitcoin transaction signing for HTLC operations.
//!
//! This module provides transaction signing capabilities for both standard
//! P2WPKH/P2TR transactions and HTLC-specific transactions (claim and timeout paths).
//!
//! # Supported Script Types
//!
//! - **P2WPKH**: Native SegWit pay-to-witness-public-key-hash
//! - **P2TR**: Pay-to-taproot (key path spending)
//! - **P2WSH**: Pay-to-witness-script-hash (for HTLC contracts)

use anyhow::{Context, Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::{All, Message};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{
    CompressedPublicKey, EcdsaSighashType, PublicKey, TapSighashType, Transaction, Witness,
};
use btc_htlc::{Contract as BtcContract, HtlcCondition};

use super::utils::UtxoInfo;

/// Bitcoin transaction signer with support for multiple script types.
///
/// Handles ECDSA signing for SegWit v0 (P2WPKH, P2WSH) and Schnorr
/// signing for SegWit v1 (P2TR) transactions.
pub struct BtcTxSigner {
    keypair: Keypair,
    secp: Secp256k1<All>,
}

impl BtcTxSigner {
    /// Create a new transaction signer with the given keypair.
    #[must_use]
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            secp: Secp256k1::new(),
        }
    }

    /// Get the compressed public key for address generation.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key cannot be compressed.
    pub fn compressed_public_key(&self) -> Result<CompressedPublicKey> {
        PublicKey::from(self.keypair.public_key())
            .try_into()
            .map_err(|e| anyhow!("Failed to compress public key: {e}"))
    }

    /// Sign a standard transaction with multiple inputs.
    ///
    /// Automatically detects the script type of each input and applies
    /// the appropriate signing algorithm (ECDSA or Schnorr).
    ///
    /// # Arguments
    ///
    /// * `tx` - The unsigned transaction to sign.
    /// * `inputs` - UTXO information for each input.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Input count doesn't match UTXO count
    /// - An unsupported script type is encountered
    /// - Signing fails
    pub fn sign_transaction(&self, tx: &Transaction, inputs: &[UtxoInfo]) -> Result<Transaction> {
        self.validate_input_count(tx, inputs)?;

        let mut cache = SighashCache::new(tx.clone());

        inputs
            .iter()
            .enumerate()
            .try_for_each(|(index, input)| self.sign_input(&mut cache, inputs, index, input))?;

        Ok(cache.into_transaction())
    }

    /// Sign a claim transaction (revealing the secret to spend HTLC).
    ///
    /// Creates the witness that proves knowledge of the secret preimage,
    /// allowing the counterparty to claim the locked funds.
    ///
    /// # Arguments
    ///
    /// * `tx` - The unsigned claim transaction.
    /// * `inputs` - UTXO information (must be exactly one HTLC output).
    /// * `contract` - The HTLC contract.
    /// * `secret` - The 32-byte secret preimage.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails or the input is not a valid HTLC.
    pub fn sign_claim_transaction(
        &self,
        tx: &Transaction,
        inputs: &[UtxoInfo],
        contract: &BtcContract,
        secret: &[u8; 32],
    ) -> Result<Transaction> {
        self.sign_htlc_transaction(
            tx,
            inputs,
            contract,
            HtlcCondition::Reveal { secret: *secret },
        )
    }

    /// Sign a timeout transaction (reclaiming funds after expiry).
    ///
    /// Creates the witness for the timeout spending path, allowing
    /// the original sender to reclaim funds after the locktime expires.
    ///
    /// # Arguments
    ///
    /// * `tx` - The unsigned timeout transaction.
    /// * `inputs` - UTXO information (must be exactly one HTLC output).
    /// * `contract` - The HTLC contract.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Transaction locktime is insufficient
    /// - Signing fails
    /// - Input is not a valid HTLC
    pub fn sign_timeout_transaction(
        &self,
        tx: &Transaction,
        inputs: &[UtxoInfo],
        contract: &BtcContract,
    ) -> Result<Transaction> {
        self.sign_htlc_transaction(tx, inputs, contract, HtlcCondition::Timeout)
    }

    /// Verify that input count matches UTXO count.
    fn validate_input_count(&self, tx: &Transaction, inputs: &[UtxoInfo]) -> Result<()> {
        (tx.input.len() == inputs.len())
            .then_some(())
            .ok_or_else(|| {
                anyhow!(
                    "Input count mismatch: transaction has {}, provided {}",
                    tx.input.len(),
                    inputs.len()
                )
            })
    }

    /// Sign a single input based on its script type.
    fn sign_input(
        &self,
        cache: &mut SighashCache<Transaction>,
        inputs: &[UtxoInfo],
        index: usize,
        input: &UtxoInfo,
    ) -> Result<()> {
        let script = &input.tx_out.script_pubkey;

        match () {
            _ if script.is_p2wpkh() => self.sign_p2wpkh_input(cache, input, index),
            _ if script.is_p2tr() => self.sign_p2tr_input(cache, inputs, index),
            _ if script.is_p2wsh() => Err(anyhow!(
                "P2WSH requires HTLC-specific signing at input {index}"
            )),
            _ => Err(anyhow!("Unsupported script type at input {index}")),
        }
    }

    /// Sign HTLC transaction (claim or timeout path).
    fn sign_htlc_transaction(
        &self,
        tx: &Transaction,
        inputs: &[UtxoInfo],
        contract: &BtcContract,
        condition: HtlcCondition,
    ) -> Result<Transaction> {
        (tx.input.len() == 1 && inputs.len() == 1)
            .then_some(())
            .ok_or_else(|| {
                anyhow!(
                    "HTLC transaction must have exactly one input, got {} tx inputs and {} UTXOs",
                    tx.input.len(),
                    inputs.len()
                )
            })?;

        let input = &inputs[0];
        input
            .tx_out
            .script_pubkey
            .is_p2wsh()
            .then_some(())
            .ok_or_else(|| anyhow!("HTLC input must be P2WSH"))?;

        if let HtlcCondition::Timeout = condition {
            let lt = LockTime::from_height(contract.timeout)
                .map_err(|_| anyhow!("Invalid timeout height: {}", contract.timeout))?;

            (tx.lock_time >= lt).then_some(()).ok_or_else(|| {
                anyhow!(
                    "Transaction locktime {} is insufficient for timeout (requires {})",
                    tx.lock_time,
                    lt
                )
            })?;
        }

        let mut cache = SighashCache::new(tx.clone());
        let signature = self.create_htlc_signature(&mut cache, input, contract)?;

        let witness = contract
            .create_witness(condition, signature)
            .map_err(|e| anyhow!("Failed to create HTLC witness: {e}"))?;
        self.apply_witness(&mut cache, 0, witness)?;

        Ok(cache.into_transaction())
    }

    /// Create ECDSA signature for HTLC spending.
    fn create_htlc_signature(
        &self,
        cache: &mut SighashCache<Transaction>,
        input: &UtxoInfo,
        contract: &BtcContract,
    ) -> Result<Vec<u8>> {
        let sighash = cache
            .p2wsh_signature_hash(
                0,
                &contract.script,
                input.tx_out.value,
                EcdsaSighashType::All,
            )
            .context("Failed to compute P2WSH sighash")?;

        let message = Message::from(sighash);
        let signature = self.secp.sign_ecdsa(&message, &self.keypair.secret_key());
        let mut sig_bytes = signature.serialize_der().to_vec();
        sig_bytes.push(EcdsaSighashType::All as u8);

        Ok(sig_bytes)
    }

    /// Apply witness to transaction input.
    fn apply_witness(
        &self,
        cache: &mut SighashCache<Transaction>,
        index: usize,
        witness: Witness,
    ) -> Result<()> {
        *cache
            .witness_mut(index)
            .ok_or_else(|| anyhow!("Failed to get witness for input {index}"))? = witness;
        Ok(())
    }

    /// Sign a P2WPKH input.
    fn sign_p2wpkh_input(
        &self,
        cache: &mut SighashCache<Transaction>,
        input: &UtxoInfo,
        index: usize,
    ) -> Result<()> {
        let sighash = cache
            .p2wpkh_signature_hash(
                index,
                &input.tx_out.script_pubkey,
                input.tx_out.value,
                EcdsaSighashType::All,
            )
            .context("Failed to compute P2WPKH sighash")?;

        let message = Message::from(sighash);
        let signature = self.secp.sign_ecdsa(&message, &self.keypair.secret_key());
        let signature = bitcoin::ecdsa::Signature::sighash_all(signature);

        let compressed_pk = self
            .compressed_public_key()
            .context("Failed to get compressed public key")?;

        let witness = Witness::p2wpkh(&signature, &compressed_pk.0);
        self.apply_witness(cache, index, witness)
    }

    /// Sign a P2TR input (key path spending).
    fn sign_p2tr_input(
        &self,
        cache: &mut SighashCache<Transaction>,
        inputs: &[UtxoInfo],
        index: usize,
    ) -> Result<()> {
        let prevouts = inputs.iter().map(|u| &u.tx_out).collect::<Vec<_>>();
        let prevouts = Prevouts::All(&prevouts);

        let sighash = cache
            .taproot_key_spend_signature_hash(index, &prevouts, TapSighashType::Default)
            .context("Failed to compute taproot sighash")?;

        let message = Message::from(sighash);
        let signature = self.secp.sign_schnorr_no_aux_rand(&message, &self.keypair);

        let taproot_sig = bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        };

        let mut witness = Witness::new();
        witness.push(taproot_sig.to_vec());
        self.apply_witness(cache, index, witness)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::Secp256k1;

    use super::*;

    fn test_keypair() -> Keypair {
        let secp = Secp256k1::new();
        Keypair::new(&secp, &mut rand::thread_rng())
    }

    #[test]
    fn compressed_public_key() {
        let signer = BtcTxSigner::new(test_keypair());
        assert!(signer.compressed_public_key().is_ok());
    }

    #[test]
    fn input_count_validation() {
        let signer = BtcTxSigner::new(test_keypair());
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let result = signer.validate_input_count(&tx, &[]);
        assert!(result.is_ok());
    }
}
