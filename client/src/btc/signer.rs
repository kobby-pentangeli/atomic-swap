use anyhow::{Context, Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::{All, Message};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{
    CompressedPublicKey, EcdsaSighashType, PublicKey, Script, TapSighashType, Transaction, TxOut,
    Witness,
};
use btc_htlc::{Contract as BtcContract, HtlcCondition};

use super::UtxoInfo;

pub struct BtcTxSigner {
    keypair: Keypair,
    secp: Secp256k1<All>,
}

impl BtcTxSigner {
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            secp: Secp256k1::new(),
        }
    }

    /// Get the compressed public key for address generation
    pub fn get_public_key(&self) -> Result<CompressedPublicKey> {
        let btc_pubkey = PublicKey::from(self.keypair.public_key());
        CompressedPublicKey::try_from(btc_pubkey).map_err(|e| anyhow!("{e}"))
    }

    /// Sign a standard transaction with multiple inputs
    pub fn sign_transaction(
        &self,
        transaction: &Transaction,
        inputs: &[UtxoInfo],
    ) -> Result<Transaction> {
        if transaction.input.len() != inputs.len() {
            return Err(anyhow!(
                "Input count mismatch: transaction has {}, provided {}",
                transaction.input.len(),
                inputs.len()
            ));
        }

        let mut cache = SighashCache::new(transaction.clone());
        for (index, input) in inputs.iter().enumerate() {
            match &input.tx_out.script_pubkey {
                s if s.is_p2wpkh() || s.is_p2wsh() => {
                    self.sign_ecdsa(input, index, s, &mut cache)?
                }
                s if s.is_p2tr() => self.sign_schnorr(
                    &inputs.iter().map(|v| &v.tx_out).collect::<Vec<_>>(),
                    index,
                    &mut cache,
                )?,
                _ => {
                    return Err(anyhow::anyhow!("Unsupported script type at input {index}"));
                }
            }
        }

        Ok(cache.into_transaction())
    }

    /// Sign the reveal transaction (seller claims with secret)
    pub fn sign_claim_transaction(
        &self,
        transaction: &Transaction,
        inputs: &[UtxoInfo],
        contract: &BtcContract,
        secret: &[u8; 32],
    ) -> Result<Transaction> {
        self.sign_htlc_tx(
            transaction,
            inputs,
            contract,
            HtlcCondition::Reveal { secret: *secret },
        )
    }

    /// Sign the timeout (buyer recovery) transaction
    pub fn sign_timeout_transaction(
        &self,
        transaction: &Transaction,
        inputs: &[UtxoInfo],
        contract: &BtcContract,
    ) -> Result<Transaction> {
        self.sign_htlc_tx(transaction, inputs, contract, HtlcCondition::Timeout)
    }

    fn sign_htlc_tx(
        &self,
        transaction: &Transaction,
        inputs: &[UtxoInfo],
        contract: &BtcContract,
        condition: HtlcCondition,
    ) -> Result<Transaction> {
        if transaction.input.len() != 1 || inputs.len() != 1 {
            return Err(anyhow!(
                "HTLC transaction must have exactly one input, got {} inputs and {} UTXOs",
                transaction.input.len(),
                inputs.len()
            ));
        }

        let input = &inputs[0];
        if !input.tx_out.script_pubkey.is_p2wsh() {
            return Err(anyhow!("Input must be P2WSH"));
        }

        if matches!(condition, HtlcCondition::Timeout) {
            let expected_locktime = LockTime::from_height(contract.timeout)
                .map_err(|_| anyhow!("Invalid timeout height: {}", contract.timeout))?;

            if transaction.lock_time < expected_locktime {
                return Err(anyhow!(
                    "Transaction nLockTime {} is insufficient for timeout (requires {})",
                    transaction.lock_time,
                    expected_locktime
                ));
            }
        }

        let mut cache = SighashCache::new(transaction.clone());
        let sighash = cache.p2wsh_signature_hash(
            0,
            &contract.script,
            input.tx_out.value,
            EcdsaSighashType::All,
        )?;

        let message = Message::from(sighash);
        let signature = self.secp.sign_ecdsa(&message, &self.keypair.secret_key());
        let mut signature_bytes = signature.serialize_der().to_vec();
        signature_bytes.push(EcdsaSighashType::All as u8);

        let witness = contract
            .create_witness(condition, signature_bytes)
            .map_err(|e| anyhow!("Failed to create HTLC witness: {e}"))?;

        *cache
            .witness_mut(0)
            .ok_or_else(|| anyhow!("Failed to get witness for input 0"))? = witness;

        Ok(cache.into_transaction())
    }

    fn sign_ecdsa(
        &self,
        input: &UtxoInfo,
        index: usize,
        script_pubkey: &Script,
        sighash_cache: &mut SighashCache<Transaction>,
    ) -> Result<()> {
        if script_pubkey.is_p2wpkh() {
            let sighash = sighash_cache.p2wpkh_signature_hash(
                index,
                script_pubkey,
                input.tx_out.value,
                EcdsaSighashType::All,
            )?;

            let message = Message::from(sighash);
            let signature = self.secp.sign_ecdsa(&message, &self.keypair.secret_key());
            let signature = bitcoin::ecdsa::Signature::sighash_all(signature);

            let compressed_pubkey = self
                .get_public_key()
                .context("Failed to get compressed public key")?;
            let witness = Witness::p2wpkh(&signature, &compressed_pubkey.0);
            *sighash_cache
                .witness_mut(index)
                .ok_or(anyhow!("Input not found: {index}"))? = witness;
        } else if script_pubkey.is_p2wsh() {
            // For P2WSH, we need the actual script, not the script_pubkey
            // This is handled in the HTLC-specific signing method
            return Err(anyhow!(
                "P2WSH signing requires the actual script, use HTLC-specific signing"
            ));
        } else {
            return Err(anyhow!("Unsupported script type"));
        }

        Ok(())
    }

    fn sign_schnorr(
        &self,
        prev_outs: &[&TxOut],
        index: usize,
        sighash_cache: &mut SighashCache<Transaction>,
    ) -> Result<()> {
        let prevouts = Prevouts::All(prev_outs);
        let sighash = sighash_cache.taproot_key_spend_signature_hash(
            index,
            &prevouts,
            TapSighashType::Default,
        )?;

        let msg = Message::from(sighash);
        let signature = self.secp.sign_schnorr_no_aux_rand(&msg, &self.keypair);
        let signature = bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        };

        let mut witness = Witness::new();
        witness.push(signature.to_vec());
        *sighash_cache.witness_mut(index).unwrap() = witness;

        Ok(())
    }
}
