//! Hash Time Locked Contract (HTLC) implementation for Bitcoin.
//!
//! This crate provides a P2WSH (Pay-to-Witness-Script-Hash) HTLC implementation
//! that enables atomic swaps between Bitcoin and other blockchains. The HTLC
//! allows funds to be claimed in two ways:
//!
//! 1. **Reveal path**: The seller can claim funds by revealing the secret
//!    (preimage of the hash)
//! 2. **Timeout path**: The buyer can reclaim funds after a specified
//!    block height (using OP_CHECKLOCKTIMEVERIFY)
//!
//! # Example
//!
//! ```rust,ignore
//! use btc_htlc::{Contract, HtlcParams, generate_random_secret, hash_secret};
//!
//! let secret = generate_random_secret();
//! let secret_hash = hash_secret(&secret);
//!
//! let params = HtlcParams {
//!     secret_hash,
//!     seller: seller_pubkey,
//!     buyer: buyer_pubkey,
//!     timeout: current_height + 144, // ~24 hours
//!     network: Network::Bitcoin,
//! };
//!
//! let contract = Contract::new(params);
//! let address = contract.address();
//! ```

use bitcoin::opcodes::all::*;
use bitcoin::script::Builder as ScriptBuilder;
use bitcoin::transaction::InputWeightPrediction;
use bitcoin::{Address, Network, PublicKey, ScriptBuf, Witness};
use sha2::{Digest, Sha256};

/// Result type for HTLC operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Maximum length of a DER-encoded ECDSA signature including its sighash flag
/// byte. Used to predict the spending witness weight conservatively so fee
/// estimation never under-pays.
const MAX_ECDSA_SIG_LEN: usize = 73;

/// Errors that can occur during HTLC operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The provided secret does not hash to the expected value.
    #[error("invalid secret provided")]
    InvalidSecret,
    /// The provided public key is invalid.
    #[error("Invalid public key")]
    InvalidPublicKey,
    /// Failed to generate the HTLC script.
    #[error("Script generation failed")]
    ScriptGenerationFailed,
    /// Failed to generate the P2WSH address.
    #[error("Address generation failed")]
    AddressGenerationFailed,
    /// Failed to create the witness for spending.
    #[error("Witness creation failed: {0}")]
    WitnessCreation(String),
}

/// Context for a Bitcoin HTLC (Hash Time Locked Contract)
#[derive(Debug, Clone)]
pub struct Contract {
    /// SHA256 digest of the secret that unlocks the funds
    pub secret_hash: [u8; 32],
    /// Public key of the seller (who can claim with the secret)
    pub seller: PublicKey,
    /// Public key of the buyer (who can reclaim after timeout)
    pub buyer: PublicKey,
    /// Absolute timeout in blocks (using `nLockTime`)
    pub timeout: u32,
    /// The actual script
    pub script: ScriptBuf,
    /// The Bitcoin network
    pub network: Network,
}

/// Parameters for creating a valid contract
#[derive(Debug)]
pub struct HtlcParams {
    pub secret_hash: [u8; 32],
    pub seller: PublicKey,
    pub buyer: PublicKey,
    /// Timeout as absolute block height
    pub timeout: u32,
    pub network: Network,
}

/// Spending conditions
#[derive(Debug)]
pub enum HtlcCondition {
    /// Seller spends by revealing the secret
    Reveal { secret: [u8; 32] },
    /// Buyer reclaims after timeout
    Timeout,
}

impl Contract {
    /// Initialize the contract from specified params.
    pub fn new(params: HtlcParams) -> Self {
        let script = Self::build_script(
            params.secret_hash,
            params.seller,
            params.buyer,
            params.timeout,
        );
        Self {
            secret_hash: params.secret_hash,
            seller: params.seller,
            buyer: params.buyer,
            timeout: params.timeout,
            script,
            network: params.network,
        }
    }

    /// Build the script that locks the funds.
    ///
    /// Script logic:
    /// ```txt
    /// OP_IF
    ///     OP_SHA256 <secret_hash> OP_EQUALVERIFY <seller_pubkey> OP_CHECKSIG
    /// OP_ELSE
    ///     <timeout_height> OP_CLTV OP_DROP <buyer_pubkey> OP_CHECKSIG
    /// OP_ENDIF
    /// ```
    fn build_script(
        secret_hash: [u8; 32],
        seller: PublicKey,
        buyer: PublicKey,
        timeout: u32,
    ) -> ScriptBuf {
        ScriptBuilder::new()
            // Hash path (IF branch)
            .push_opcode(OP_IF)
            .push_opcode(OP_SHA256)
            .push_slice(secret_hash)
            .push_opcode(OP_EQUALVERIFY)
            .push_key(&seller)
            .push_opcode(OP_CHECKSIG)
            // Timeout path (ELSE branch)
            .push_opcode(OP_ELSE)
            .push_int(timeout as i64)
            .push_opcode(OP_CLTV) // OP_CHECKLOCKTIMEVERIFY
            .push_opcode(OP_DROP)
            .push_key(&buyer)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .into_script()
    }

    /// Generate a P2WSH (Pay-to-Witness-Script-Hash) address for this contract.
    ///
    /// # Returns
    ///
    /// Bitcoin address where funds can be sent and locked.
    pub fn address(&self) -> Address {
        Address::p2wsh(&self.script, self.network)
    }

    /// Compute the SHA256 of the provided `secret` bytes and compare with our `secret_hash`.
    pub fn verify_secret(&self, secret: &[u8; 32]) -> bool {
        let computed = Sha256::digest(secret);
        self.secret_hash == *computed
    }

    /// Generate a witness for spending the funds.
    ///
    /// # Arguments
    ///
    /// * `cond`: How to spend
    /// * `sig`: DER-encoded signature
    ///
    /// # Returns
    ///
    /// Witness stack for the transaction input.
    pub fn create_witness(&self, cond: HtlcCondition, sig: Vec<u8>) -> Result<Witness> {
        if sig.is_empty() {
            return Err(Error::WitnessCreation(
                "Signature cannot be empty".to_string(),
            ));
        }

        let mut witness = Witness::new();

        match cond {
            HtlcCondition::Reveal { secret } => {
                if !self.verify_secret(&secret) {
                    return Err(Error::InvalidSecret);
                }

                // Witness stack for reveal path: <signature> <secret> <1> <script>
                witness.push(sig);
                witness.push(&secret[..]);
                witness.push([0x01]); // TRUE for OP_IF
                witness.push(self.script.as_bytes());
            }
            HtlcCondition::Timeout => {
                // Witness stack for timeout path: <signature> <0> <script>
                witness.push(sig);
                witness.push([]); // FALSE for OP_IF (goes to ELSE)
                witness.push(self.script.as_bytes());
            }
        }
        Ok(witness)
    }

    /// Predicts the spending input's weight contribution under `cond`.
    ///
    /// The witness element lengths mirror the stack produced by
    /// [`Contract::create_witness`], making this the single source of witness
    /// sizing for fee estimation. The redeem script is committed in the witness,
    /// so its length is included.
    pub fn predict_input_weight(&self, cond: &HtlcCondition) -> InputWeightPrediction {
        let script_len = self.script.len();
        match cond {
            // Stack: <signature> <secret> <1> <redeem-script>
            HtlcCondition::Reveal { secret } => {
                InputWeightPrediction::new(0, [MAX_ECDSA_SIG_LEN, secret.len(), 1, script_len])
            }
            // Stack: <signature> <> <redeem-script>; the empty element selects the ELSE branch.
            HtlcCondition::Timeout => {
                InputWeightPrediction::new(0, [MAX_ECDSA_SIG_LEN, 0, script_len])
            }
        }
    }

    /// Get the script hash (for P2WSH addresses)
    pub fn script_hash(&self) -> [u8; 32] {
        Sha256::digest(self.script.as_bytes()).into()
    }
}

/// Generate a cryptographically secure random secret
pub fn generate_random_secret() -> [u8; 32] {
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

/// Generate a cryptographically secure random secret as hex string
pub fn generate_random_secret_hex() -> String {
    hex::encode(generate_random_secret())
}

/// Compute the SHA256 digest of the given preimage (`secret`) bytes.
pub fn hash_secret(secret: &[u8]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

/// Convert hex string to 32-byte array
pub fn hex_to_secret(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    let bytes = hex::decode(hex_str).map_err(|e| anyhow::anyhow!("Invalid hex string: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "Secret must be exactly 32 bytes (64 hex characters), got {} bytes",
            bytes.len()
        ));
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use bitcoin::PrivateKey;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    use super::*;

    fn create_test_keypair() -> (PrivateKey, PublicKey) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let private_key = PrivateKey::new(secret_key, Network::Regtest);
        let public_key = private_key.public_key(&secp);
        (private_key, public_key)
    }

    #[test]
    fn hex_secret_conversion() {
        let original_secret = generate_random_secret();
        let hex_secret = hex::encode(original_secret);
        let parsed_secret = hex_to_secret(&hex_secret).unwrap();
        assert_eq!(original_secret, parsed_secret);
    }

    #[test]
    fn hex_with_prefix() {
        let hex_secret = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let secret = hex_to_secret(hex_secret).unwrap();
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn invalid_length() {
        let short_hex = "0123456789abcdef"; // Only 16 hex chars = 8 bytes
        assert!(hex_to_secret(short_hex).is_err());
    }

    #[test]
    fn create_contract() {
        let (_, seller_pk) = create_test_keypair();
        let (_, buyer_pk) = create_test_keypair();
        let secret = generate_random_secret();
        let secret_hash = hash_secret(&secret);

        let params = HtlcParams {
            secret_hash,
            seller: seller_pk,
            buyer: buyer_pk,
            timeout: 800144, // ~24 hours from 800000
            network: Network::Regtest,
        };

        let contract = Contract::new(params);

        assert_eq!(contract.secret_hash, secret_hash);
        assert_eq!(contract.seller, seller_pk);
        assert_eq!(contract.buyer, buyer_pk);
        assert!(contract.verify_secret(&secret));
    }

    #[test]
    fn validate_secret() {
        let (_, seller_pk) = create_test_keypair();
        let (_, buyer_pk) = create_test_keypair();
        let secret = generate_random_secret();
        let secret_hash = hash_secret(&secret);

        let params = HtlcParams {
            secret_hash,
            seller: seller_pk,
            buyer: buyer_pk,
            timeout: 800144,
            network: Network::Regtest,
        };

        let contract = Contract::new(params);
        assert!(contract.verify_secret(&secret));

        let wrong_secret = generate_random_secret();
        assert!(!contract.verify_secret(&wrong_secret));
    }

    #[test]
    fn predict_input_weight() {
        let (_, seller_pk) = create_test_keypair();
        let (_, buyer_pk) = create_test_keypair();
        let secret = generate_random_secret();
        let secret_hash = hash_secret(&secret);

        let params = HtlcParams {
            secret_hash,
            seller: seller_pk,
            buyer: buyer_pk,
            timeout: 800144,
            network: Network::Testnet,
        };

        let contract = Contract::new(params);

        let reveal = contract
            .predict_input_weight(&HtlcCondition::Reveal { secret })
            .weight();
        let timeout = contract
            .predict_input_weight(&HtlcCondition::Timeout)
            .weight();

        // The reveal stack additionally carries the 32-byte secret.
        assert!(reveal > timeout);
    }

    #[test]
    fn create_witness_reveal_path() {
        let (_, seller_pk) = create_test_keypair();
        let (_, buyer_pk) = create_test_keypair();
        let secret = generate_random_secret();
        let secret_hash = hash_secret(&secret);

        let contract = Contract::new(HtlcParams {
            secret_hash,
            seller: seller_pk,
            buyer: buyer_pk,
            timeout: 800144,
            network: Network::Regtest,
        });

        let dummy_sig = vec![0x30, 0x44, 0x02, 0x20]; // Partial DER prefix

        let witness = contract
            .create_witness(HtlcCondition::Reveal { secret }, dummy_sig.clone())
            .unwrap();

        // Witness should have 4 elements: signature, secret, TRUE (0x01), script
        assert_eq!(witness.len(), 4);
        assert_eq!(witness.nth(1).unwrap(), &secret[..]);
        assert_eq!(witness.nth(2).unwrap(), &[0x01]);
    }

    #[test]
    fn create_witness_timeout_path() {
        let (_, seller_pk) = create_test_keypair();
        let (_, buyer_pk) = create_test_keypair();
        let secret = generate_random_secret();
        let secret_hash = hash_secret(&secret);

        let contract = Contract::new(HtlcParams {
            secret_hash,
            seller: seller_pk,
            buyer: buyer_pk,
            timeout: 800144,
            network: Network::Regtest,
        });

        let dummy_sig = vec![0x30, 0x44, 0x02, 0x20];

        let witness = contract
            .create_witness(HtlcCondition::Timeout, dummy_sig)
            .unwrap();

        // Witness should have 3 elements: signature, FALSE (empty), script
        assert_eq!(witness.len(), 3);
        assert!(witness.nth(1).unwrap().is_empty());
    }

    /// Script-execution tests that run the locking script through the consensus
    /// interpreter (`bitcoinconsensus`) for both spend paths and their failure
    /// modes.
    mod consensus {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::Message;
        use bitcoin::sighash::SighashCache;
        use bitcoin::transaction::Version;
        use bitcoin::{
            Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
            Txid, Witness,
        };

        use super::*;

        /// Absolute block height encoded as the contract timeout under test.
        const TIMEOUT_HEIGHT: u32 = 200;
        /// Value locked in the funding output.
        const FUND_VALUE: Amount = Amount::from_sat(100_000);
        /// Value of the spending output; the difference stands in for the fee.
        const SPEND_VALUE: Amount = Amount::from_sat(99_000);

        fn htlc(secret_hash: [u8; 32], seller: PublicKey, buyer: PublicKey) -> Contract {
            Contract::new(HtlcParams {
                secret_hash,
                seller,
                buyer,
                timeout: TIMEOUT_HEIGHT,
                network: Network::Regtest,
            })
        }

        /// Builds the funding output and an unsigned single-input spend of it.
        fn unsigned_spend(
            contract: &Contract,
            lock_time: LockTime,
            sequence: Sequence,
        ) -> (Transaction, TxOut) {
            let funding = TxOut {
                value: FUND_VALUE,
                script_pubkey: contract.address().script_pubkey(),
            };
            let tx = Transaction {
                version: Version::TWO,
                lock_time,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::all_zeros(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: SPEND_VALUE,
                    script_pubkey: contract.address().script_pubkey(),
                }],
            };
            (tx, funding)
        }

        /// Signs the single input against the P2WSH sighash and appends the
        /// `SIGHASH_ALL` flag, matching the client's signing path.
        fn sign(contract: &Contract, tx: &Transaction, value: Amount, key: &SecretKey) -> Vec<u8> {
            let secp = Secp256k1::new();
            let sighash = SighashCache::new(tx)
                .p2wsh_signature_hash(0, &contract.script, value, EcdsaSighashType::All)
                .expect("p2wsh sighash");
            let mut sig = secp
                .sign_ecdsa(&Message::from(sighash), key)
                .serialize_der()
                .to_vec();
            sig.push(EcdsaSighashType::All as u8);
            sig
        }

        #[test]
        fn reveal_path_accepts_valid_secret() {
            let (seller, seller_pk) = create_test_keypair();
            let (_, buyer_pk) = create_test_keypair();
            let secret = generate_random_secret();
            let contract = htlc(hash_secret(&secret), seller_pk, buyer_pk);

            let (mut tx, funding) = unsigned_spend(&contract, LockTime::ZERO, Sequence::MAX);
            let sig = sign(&contract, &tx, funding.value, &seller.inner);
            tx.input[0].witness = contract
                .create_witness(HtlcCondition::Reveal { secret }, sig)
                .unwrap();

            tx.verify(|_| Some(funding.clone()))
                .expect("reveal spend with the correct secret must verify");
        }

        #[test]
        fn timeout_path_accepts_at_locktime() {
            let (_, seller_pk) = create_test_keypair();
            let (buyer, buyer_pk) = create_test_keypair();
            let secret = generate_random_secret();
            let contract = htlc(hash_secret(&secret), seller_pk, buyer_pk);

            // OP_CLTV requires a non-final sequence and nLockTime at or past the height.
            let (mut tx, funding) = unsigned_spend(
                &contract,
                LockTime::from_height(TIMEOUT_HEIGHT).unwrap(),
                Sequence::ENABLE_LOCKTIME_NO_RBF,
            );
            let sig = sign(&contract, &tx, funding.value, &buyer.inner);
            tx.input[0].witness = contract
                .create_witness(HtlcCondition::Timeout, sig)
                .unwrap();

            tx.verify(|_| Some(funding.clone()))
                .expect("timeout spend at the locktime height must verify");
        }

        #[test]
        fn timeout_path_rejects_before_locktime() {
            let (_, seller_pk) = create_test_keypair();
            let (buyer, buyer_pk) = create_test_keypair();
            let secret = generate_random_secret();
            let contract = htlc(hash_secret(&secret), seller_pk, buyer_pk);

            let (mut tx, funding) = unsigned_spend(
                &contract,
                LockTime::from_height(TIMEOUT_HEIGHT - 1).unwrap(),
                Sequence::ENABLE_LOCKTIME_NO_RBF,
            );
            let sig = sign(&contract, &tx, funding.value, &buyer.inner);
            tx.input[0].witness = contract
                .create_witness(HtlcCondition::Timeout, sig)
                .unwrap();

            assert!(
                tx.verify(|_| Some(funding.clone())).is_err(),
                "a timeout spend below the locktime height must be rejected"
            );
        }

        #[test]
        fn reveal_path_rejects_wrong_secret() {
            let (seller, seller_pk) = create_test_keypair();
            let (_, buyer_pk) = create_test_keypair();
            let secret = generate_random_secret();
            let contract = htlc(hash_secret(&secret), seller_pk, buyer_pk);

            let (mut tx, funding) = unsigned_spend(&contract, LockTime::ZERO, Sequence::MAX);
            let sig = sign(&contract, &tx, funding.value, &seller.inner);

            // create_witness rejects a wrong preimage, so assemble the stack
            // directly to prove the script itself enforces the hash lock.
            let wrong = generate_random_secret();
            let mut witness = Witness::new();
            witness.push(sig);
            witness.push(&wrong[..]);
            witness.push([0x01]);
            witness.push(contract.script.as_bytes());
            tx.input[0].witness = witness;

            assert!(
                tx.verify(|_| Some(funding.clone())).is_err(),
                "a reveal spend with the wrong secret must be rejected"
            );
        }

        #[test]
        fn reveal_path_rejects_tampered_script() {
            let (seller, seller_pk) = create_test_keypair();
            let (_, buyer_pk) = create_test_keypair();
            let secret = generate_random_secret();
            let contract = htlc(hash_secret(&secret), seller_pk, buyer_pk);

            let (mut tx, funding) = unsigned_spend(&contract, LockTime::ZERO, Sequence::MAX);
            let sig = sign(&contract, &tx, funding.value, &seller.inner);

            // A witness script that does not hash to the committed P2WSH program.
            let mut witness = Witness::new();
            witness.push(sig);
            witness.push(&secret[..]);
            witness.push([0x01]);
            witness.push([0xde, 0xad, 0xbe, 0xef]);
            tx.input[0].witness = witness;

            assert!(
                tx.verify(|_| Some(funding.clone())).is_err(),
                "a reveal spend committing a tampered script must be rejected"
            );
        }
    }
}
