use clvm_zk_core::chialisp::compile_chialisp_template_hash_default;
use clvm_zk_core::coin_commitment::SerialCommitment;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;

/// errors that can happen in the protocol
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Invalid spend secret: {0}")]
    InvalidSpendSecret(String),
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
    #[error("Invalid nullifier: {0}")]
    InvalidNullifier(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// a private coin that can be spent with zk proofs
///
/// the coin contains only public data. secrets (serial_number, serial_randomness)
/// are stored separately in CoinSecrets and must be provided when spending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateCoin {
    /// hash of the chialisp program that controls spending conditions
    pub puzzle_hash: [u8; 32],

    /// coin value
    pub amount: u64,

    /// commitment that binds this coin to specific spending secrets
    pub serial_commitment: SerialCommitment,
}

impl PrivateCoin {
    pub fn new(
        puzzle_hash: [u8; 32],
        amount: u64,
        serial_commitment: SerialCommitment,
    ) -> Self {
        Self {
            puzzle_hash,
            amount,
            serial_commitment,
        }
    }

    pub fn from_program(
        puzzle_code: &str,
        amount: u64,
        serial_commitment: SerialCommitment,
    ) -> Self {
        let puzzle_hash = compile_chialisp_template_hash_default(puzzle_code)
            .expect("Failed to compile template hash");
        Self::new(puzzle_hash, amount, serial_commitment)
    }

    /// create coin with random secrets (WARNING: secrets discarded, coin is unspendable)
    pub fn new_random(puzzle_hash: [u8; 32], amount: u64) -> Self {
        let (coin, _secrets) = Self::new_with_secrets(puzzle_hash, amount);
        coin
    }

    /// create coin with random secrets (returns CoinSecrets for spending)
    pub fn new_with_secrets(
        puzzle_hash: [u8; 32],
        amount: u64,
    ) -> (Self, clvm_zk_core::coin_commitment::CoinSecrets) {
        let mut serial_number = [0u8; 32];
        let mut serial_randomness = [0u8; 32];

        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut serial_number);
        rng.fill_bytes(&mut serial_randomness);

        let serial_commitment = SerialCommitment::compute(
            &serial_number,
            &serial_randomness,
            crate::crypto_utils::hash_data_default,
        );

        let coin = Self::new(puzzle_hash, amount, serial_commitment);
        let secrets = clvm_zk_core::coin_commitment::CoinSecrets::new(serial_number, serial_randomness);

        (coin, secrets)
    }

    pub fn new_random_from_program(puzzle_code: &str, amount: u64) -> Self {
        let mut serial_number = [0u8; 32];
        let mut serial_randomness = [0u8; 32];

        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut serial_number);
        rng.fill_bytes(&mut serial_randomness);

        let serial_commitment = SerialCommitment::compute(
            &serial_number,
            &serial_randomness,
            crate::crypto_utils::hash_data_default,
        );

        Self::from_program(puzzle_code, amount, serial_commitment)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.puzzle_hash == [0u8; 32] {
            return Err(ProtocolError::InvalidSpendSecret(
                "Puzzle hash cannot be all zeros".to_string(),
            ));
        }

        if self.serial_commitment.as_bytes() == &[0u8; 32] {
            return Err(ProtocolError::InvalidSpendSecret(
                "Serial commitment cannot be all zeros".to_string(),
            ));
        }

        Ok(())
    }
}

impl fmt::Display for PrivateCoin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrivateCoin {{ amount: {}, serial_commitment: {}..., puzzle: {}... }}",
            self.amount,
            &hex::encode(self.serial_commitment.as_bytes())[..16],
            &hex::encode(self.puzzle_hash)[..16]
        )
    }
}

/// complete spend bundle with zk proof and public outputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateSpendBundle {
    /// zk proof that validates the spend
    pub zk_proof: Vec<u8>,

    /// nullifier for the coin being spent (prevents double-spending)
    pub nullifier: [u8; 32],

    /// public output conditions from running the puzzle (clvm-encoded)
    pub public_conditions: Vec<u8>,
}

impl PrivateSpendBundle {
    pub fn new(zk_proof: Vec<u8>, nullifier: [u8; 32], public_conditions: Vec<u8>) -> Self {
        Self {
            zk_proof,
            nullifier,
            public_conditions,
        }
    }

    pub fn nullifier_hex(&self) -> String {
        hex::encode(self.nullifier)
    }

    pub fn proof_size(&self) -> usize {
        self.zk_proof.len()
    }

    pub fn conditions_size(&self) -> usize {
        self.public_conditions.len()
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.zk_proof.is_empty() {
            return Err(ProtocolError::ProofGenerationFailed(
                "ZK proof cannot be empty".to_string(),
            ));
        }

        if self.nullifier == [0u8; 32] {
            return Err(ProtocolError::InvalidNullifier(
                "Nullifier cannot be all zeros".to_string(),
            ));
        }

        Ok(())
    }
}

impl fmt::Display for PrivateSpendBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrivateSpendBundle {{ nullifier: {}, proof_size: {} bytes, conditions_size: {} bytes }}",
            &self.nullifier_hex()[..16], // Show first 16 chars
            self.proof_size(),
            self.conditions_size()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_coin_creation() {
        let puzzle_hash = [0x13; 32];
        let amount = 1000;

        let coin = PrivateCoin::new_random(puzzle_hash, amount);

        assert_eq!(coin.puzzle_hash, puzzle_hash);
        assert_eq!(coin.amount, amount);
        assert_ne!(coin.serial_commitment.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_private_coin_from_program() {
        let puzzle_code = "(mod (a b) (+ a b))";
        let amount = 1000;

        let coin = PrivateCoin::new_random_from_program(puzzle_code, amount);

        assert_eq!(coin.amount, amount);

        let expected_hash = clvm_zk_core::chialisp::compile_chialisp_template_hash_default(puzzle_code).unwrap();
        assert_eq!(coin.puzzle_hash, expected_hash);
    }

    #[test]
    fn test_nullifier_unique_with_secrets() {
        let puzzle_hash = [0x33; 32];
        let (coin1, secrets1) = PrivateCoin::new_with_secrets(puzzle_hash, 100);
        let (coin2, secrets2) = PrivateCoin::new_with_secrets(puzzle_hash, 100);

        assert_ne!(secrets1.nullifier(), secrets2.nullifier());
        assert_eq!(coin1.puzzle_hash, coin2.puzzle_hash);
    }

    #[test]
    fn test_random_coin_creation() {
        let puzzle_hash = [0x42; 32];
        let (coin1, secrets1) = PrivateCoin::new_with_secrets(puzzle_hash, 100);
        let (coin2, secrets2) = PrivateCoin::new_with_secrets(puzzle_hash, 100);

        // Random coins should have different nullifiers
        assert_ne!(secrets1.nullifier(), secrets2.nullifier());
        assert_eq!(coin1.puzzle_hash, coin2.puzzle_hash); // Same puzzle
    }

    #[test]
    fn test_random_coin_from_program() {
        let puzzle_code = "(mod (a b) (+ a b))";
        let coin1 = PrivateCoin::new_random_from_program(puzzle_code, 100);
        let coin2 = PrivateCoin::new_random_from_program(puzzle_code, 100);

        assert_eq!(coin1.puzzle_hash, coin2.puzzle_hash);
        assert_ne!(coin1.serial_commitment, coin2.serial_commitment);
    }

    #[test]
    fn test_coin_validation() {
        let valid_coin = PrivateCoin::new_random([0x13; 32], 100);
        assert!(valid_coin.validate().is_ok());

        let another_coin = PrivateCoin::new_random([0x42; 32], 200);
        assert!(another_coin.validate().is_ok());
    }

    #[test]
    fn test_spend_bundle_creation() {
        let proof = vec![0x01, 0x02, 0x03];
        let nullifier = [0x42; 32];
        let conditions = vec![0x04, 0x05, 0x06];

        let bundle = PrivateSpendBundle::new(proof.clone(), nullifier, conditions.clone());

        assert_eq!(bundle.zk_proof, proof);
        assert_eq!(bundle.nullifier, nullifier);
        assert_eq!(bundle.public_conditions, conditions);
    }

    #[test]
    fn test_spend_bundle_validation() {
        let valid_bundle = PrivateSpendBundle::new(vec![0x01, 0x02], [0x42; 32], vec![0x03]);
        assert!(valid_bundle.validate().is_ok());

        let invalid_bundle = PrivateSpendBundle::new(vec![], [0x42; 32], vec![0x03]);
        assert!(invalid_bundle.validate().is_err());

        let invalid_bundle = PrivateSpendBundle::new(vec![0x01], [0x00; 32], vec![0x03]);
        assert!(invalid_bundle.validate().is_err());
    }
}
