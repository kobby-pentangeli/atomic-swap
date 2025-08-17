use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::{All, Message};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Script, TapSighashType, Transaction, TxOut, Witness};

// use btc_htlc::{Contract as BtcContract, HtlcCondition};
use crate::types::UtxoInfo;

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

    /// Sign a standard transaction with multiple inputs
    pub fn sign_transaction(
        &self,
        transaction: &Transaction,
        inputs: &[UtxoInfo],
    ) -> anyhow::Result<Transaction> {
        if transaction.input.len() != inputs.len() {
            return Err(anyhow::anyhow!("Invalid inputs"));
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
                _ => return Err(anyhow::anyhow!("Invalid script type")),
            }
        }

        Ok(cache.into_transaction())
    }

    fn sign_ecdsa(
        &self,
        input: &UtxoInfo,
        index: usize,
        script_pubkey: &Script,
        sighash_cache: &mut SighashCache<Transaction>,
    ) -> anyhow::Result<()> {
        let sighash = sighash_cache.p2wpkh_signature_hash(
            index,
            script_pubkey,
            input.tx_out.value,
            bitcoin::EcdsaSighashType::All,
        )?;
        let message = Message::from(sighash);

        let signature = self.secp.sign_ecdsa(&message, &self.keypair.secret_key());
        let signature = bitcoin::ecdsa::Signature::sighash_all(signature);

        let witness = Witness::p2wpkh(&signature, &self.keypair.public_key());
        *sighash_cache
            .witness_mut(index)
            .ok_or(anyhow::anyhow!("Input not found: {index}"))? = witness;

        Ok(())
    }

    fn sign_schnorr(
        &self,
        prev_outs: &[&TxOut],
        index: usize,
        sighash_cache: &mut SighashCache<Transaction>,
    ) -> anyhow::Result<()> {
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
