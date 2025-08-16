use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder as ScriptBuilder;
use bitcoin::{Address, Network, PublicKey, ScriptBuf, Witness};
use rand::Rng as _;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid secret provided")]
    InvalidSecret,
}

/// Context for a Bitcoin HTLC (Hash Time Locked Contract)
#[derive(Debug, Clone)]
pub struct Contract {
    /// SHA256 digest of the secret that unlocks the funds
    pub secret_hash: sha256::Hash,
    /// Public key of the seller (who can claim with the secret)
    pub seller: PublicKey,
    /// Public key of the buyer (who can reclaim after timeout)
    pub buyer: PublicKey,
    /// Relative timeout in blocks
    pub timeout: u16,
    /// The actual script
    pub script: ScriptBuf,
    /// The Bitcoin network
    pub network: Network,
}

/// Parameters for creating a valid contract
#[derive(Debug)]
pub struct HtlcParams {
    pub secret_hash: sha256::Hash,
    pub seller: PublicKey,
    pub buyer: PublicKey,
    pub timeout: u16,
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
    /// ```
    /// OP_IF
    ///     OP_SHA256 <secret_hash> OP_EQUALVERIFY
    ///     <seller> OP_CHECKSIG
    /// OP_ELSE
    ///     <timeout> OP_CSV (OP_CHECKSEQUENCEVERIFY) OP_DROP
    ///     <buyer> OP_CHECKSIG
    /// OP_ENDIF
    /// ```
    fn build_script(
        secret_hash: sha256::Hash,
        seller: PublicKey,
        buyer: PublicKey,
        timeout: u16,
    ) -> ScriptBuf {
        ScriptBuilder::new()
            .push_opcode(OP_IF)
            .push_opcode(OP_SHA256)
            .push_slice(secret_hash.as_byte_array())
            .push_opcode(OP_EQUALVERIFY)
            .push_key(&seller)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_int(timeout as i64)
            .push_opcode(OP_CSV)
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
        sha256::Hash::hash(secret) == self.secret_hash
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
        let mut witness = Witness::new();

        match cond {
            HtlcCondition::Reveal { secret } => {
                if !self.verify_secret(&secret) {
                    return Err(Error::InvalidSecret);
                }
                // Witness stack for secret reveal:
                // <[sig]> <[secret]> <[1]> <[script]>
                witness.push(sig);
                witness.push(&secret[..]);
                witness.push([1]); // TRUE for IF branch
            }
            HtlcCondition::Timeout => {
                // Witness stack for timeout:
                // <[sig]> <[0]> <[script]>
                witness.push(sig);
                witness.push([0]); // FALSE/empty for ELSE branch
            }
        }

        witness.push(self.script.as_bytes());
        Ok(witness)
    }

    /// Estimates the witness size for fee calculation
    pub fn witness_size(&self, cond: &HtlcCondition) -> usize {
        match cond {
            HtlcCondition::Reveal { .. } => {
                // signature (~72) + secret (32) + TRUE (1) + script len (variable)
                72 + 32 + 1 + self.script.len()
            }
            HtlcCondition::Timeout => {
                // signature + false/empty + script len
                72 + 1 + self.script.len()
            }
        }
    }
}

/// Generate a random secret/hash pair.
pub fn generate_secret() -> ([u8; 32], sha256::Hash) {
    let mut rng = rand::rng();
    let secret = rng.random::<[u8; 32]>();
    let hash = sha256::Hash::hash(&secret);
    (secret, hash)
}

pub fn generate_secret_from_preimage(p: Vec<u8>) -> sha256::Hash {
    sha256::Hash::hash(&p)
}
