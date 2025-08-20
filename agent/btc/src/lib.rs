//! Hash Time Locked Contract (HTLC) for Bitcoin

use bitcoin::opcodes::all::*;
use bitcoin::script::Builder as ScriptBuilder;
use bitcoin::{Address, Network, PublicKey, ScriptBuf, Witness};
use sha2::{Digest, Sha256};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid secret provided")]
    InvalidSecret,
    #[error("Invalid timeout value: {0}")]
    InvalidTimeout(u16),
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Script generation failed")]
    ScriptGenerationFailed,
    #[error("Address generation failed")]
    AddressGenerationFailed,
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
    /// Absolute timeout in blocks (using nLockTime)
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

    /// Estimates the witness size for fee calculation
    pub fn witness_size(&self, cond: &HtlcCondition) -> usize {
        const SIGNATURE_SIZE: usize = 73; // Max DER signature size + SIGHASH flag
        const SECRET_SIZE: usize = 32;
        const CONTROL_BYTE_SIZE: usize = 1;

        let script_size = self.script.len();

        match cond {
            HtlcCondition::Reveal { .. } => {
                // <signature> <secret> <1> <script>
                SIGNATURE_SIZE + SECRET_SIZE + CONTROL_BYTE_SIZE + script_size + 4 // +4 for length prefixes
            }
            HtlcCondition::Timeout => {
                // <signature> <0> <script>
                SIGNATURE_SIZE + 1 + script_size + 3 // +3 for length prefixes, +1 for empty byte
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

pub fn generate_secret_from_preimage(p: &[u8]) -> [u8; 32] {
    Sha256::digest(p).into()
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
    use bitcoin::secp256k1::Secp256k1;

    use super::*;

    fn create_test_keypair() -> (PrivateKey, PublicKey) {
        let secp = Secp256k1::new();
        let private_key = PrivateKey::generate(Network::Regtest);
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
        let secret_hash = generate_secret_from_preimage(&secret);

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
        let secret_hash = generate_secret_from_preimage(&secret);

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
    fn estimate_witness_size() {
        let (_, seller_pk) = create_test_keypair();
        let (_, buyer_pk) = create_test_keypair();
        let secret = generate_random_secret();
        let secret_hash = generate_secret_from_preimage(&secret);

        let params = HtlcParams {
            secret_hash,
            seller: seller_pk,
            buyer: buyer_pk,
            timeout: 800144,
            network: Network::Testnet,
        };

        let contract = Contract::new(params);

        let reveal_size = contract.witness_size(&HtlcCondition::Reveal { secret });
        let timeout_size = contract.witness_size(&HtlcCondition::Timeout);

        assert!(reveal_size > timeout_size);
        assert!(reveal_size > 100);
    }
}
