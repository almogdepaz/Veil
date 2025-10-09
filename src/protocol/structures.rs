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
/// each coin has a secret that makes a unique nullifier to prevent double-spending
/// while keeping everything private.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateCoin {
    /// secret that makes the nullifier for this coin
    /// never reveal this publicly - it stays hidden in zk proofs
    pub spend_secret: [u8; 32],

    /// hash of the chialisp program that controls how to spend this coin
    /// lets you identify the program without showing the actual code
    pub puzzle_hash: [u8; 32],

    /// how much this coin is worth
    pub amount: u64,
}

impl PrivateCoin {
    /// make a new private coin
    pub fn new(spend_secret: [u8; 32], puzzle_hash: [u8; 32], amount: u64) -> Self {
        Self {
            spend_secret,
            puzzle_hash,
            amount,
        }
    }

    /// make a new private coin from chialisp code
    /// hashes the program to create the puzzle_hash
    pub fn from_program(spend_secret: [u8; 32], puzzle_code: &str, amount: u64) -> Self {
        use sha2::{Digest, Sha256};
        let puzzle_hash = Sha256::digest(puzzle_code.as_bytes()).into();
        Self::new(spend_secret, puzzle_hash, amount)
    }

    /// make a new private coin with random spend secret
    ///
    /// note: the randomness should be cryptographically secure in production
    pub fn new_random(puzzle_hash: [u8; 32], amount: u64) -> Self {
        use rand::RngCore;
        let mut spend_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut spend_secret);

        Self::new(spend_secret, puzzle_hash, amount)
    }

    /// make a new private coin with random spend secret from program code
    pub fn new_random_from_program(puzzle_code: &str, amount: u64) -> Self {
        use rand::RngCore;
        let mut spend_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut spend_secret);

        Self::from_program(spend_secret, puzzle_code, amount)
    }

    /// get the nullifier for this coin (prevents double spending)
    ///
    /// uses the hardened v1.0 algorithm:
    /// nullifier = SHA256("clvm_zk_nullifier_v1.0" || spend_secret || puzzle_hash)
    ///
    /// what this gives you:
    /// - same inputs always make the same nullifier
    /// - each spend_secret makes a different nullifier
    /// - you can't figure out the spend_secret from the nullifier
    /// - sha256 prevents collisions
    /// - puzzle_hash binding prevents reuse across different puzzles
    pub fn nullifier(&self) -> [u8; 32] {
        crate::crypto_utils::generate_nullifier(&self.spend_secret, &self.puzzle_hash)
    }

    /// get nullifier as hex string for printing/debugging
    pub fn nullifier_hex(&self) -> String {
        hex::encode(self.nullifier())
    }

    /// check that this coin has a valid spend secret
    pub fn validate(&self) -> Result<(), ProtocolError> {
        // make sure spend secret isn't all zeros (weak secret)
        if self.spend_secret == [0u8; 32] {
            return Err(ProtocolError::InvalidSpendSecret(
                "Spend secret cannot be all zeros".to_string(),
            ));
        }

        // make sure puzzle hash isn't all zeros
        if self.puzzle_hash == [0u8; 32] {
            return Err(ProtocolError::InvalidSpendSecret(
                "Puzzle hash cannot be all zeros".to_string(),
            ));
        }

        Ok(())
    }
}

impl fmt::Display for PrivateCoin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrivateCoin {{ amount: {}, nullifier: {}, puzzle: \"{}...\" }}",
            self.amount,
            &self.nullifier_hex()[..16], // show first 16 chars of nullifier
            &hex::encode(self.puzzle_hash)[..16]  // show first 16 chars of puzzle hash
        )
    }
}

/// complete spend bundle with zk proof and public outputs
///
/// this is what you get when you spend a private coin - it has everything
/// needed for the l1 blockchain to validate the spend without revealing secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateSpendBundle {
    /// the zk proof that validates the spend
    /// proves that:
    /// 1. the spender knew the spend_secret for the nullifier
    /// 2. the puzzle ran correctly with the given parameters
    /// 3. the public_conditions are the correct output
    pub zk_proof: Vec<u8>,

    /// the nullifier for the coin being spent
    /// this is public and prevents double-spending
    pub nullifier: [u8; 32],

    /// the public output conditions from running the puzzle
    /// has the clvm-encoded results (e.g., CREATE_COIN, RESERVE_FEE)
    /// that the l1 blockchain should process
    pub public_conditions: Vec<u8>,
}

impl PrivateSpendBundle {
    /// make a new spend bundle
    pub fn new(zk_proof: Vec<u8>, nullifier: [u8; 32], public_conditions: Vec<u8>) -> Self {
        Self {
            zk_proof,
            nullifier,
            public_conditions,
        }
    }

    /// Get a hex representation of the nullifier
    pub fn nullifier_hex(&self) -> String {
        hex::encode(self.nullifier)
    }

    /// Get the size of the ZK proof in bytes
    pub fn proof_size(&self) -> usize {
        self.zk_proof.len()
    }

    /// Get the size of the public conditions in bytes
    pub fn conditions_size(&self) -> usize {
        self.public_conditions.len()
    }

    /// Validate the spend bundle structure
    pub fn validate(&self) -> Result<(), ProtocolError> {
        // Ensure proof is not empty
        if self.zk_proof.is_empty() {
            return Err(ProtocolError::ProofGenerationFailed(
                "ZK proof cannot be empty".to_string(),
            ));
        }

        // Ensure nullifier is not all zeros
        if self.nullifier == [0u8; 32] {
            return Err(ProtocolError::InvalidNullifier(
                "Nullifier cannot be all zeros".to_string(),
            ));
        }

        // Public conditions can be empty (valid for some puzzles)
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
        let spend_secret = [0x42; 32];
        let puzzle_hash = [0x13; 32];
        let amount = 1000;

        let coin = PrivateCoin::new(spend_secret, puzzle_hash, amount);

        assert_eq!(coin.spend_secret, spend_secret);
        assert_eq!(coin.puzzle_hash, puzzle_hash);
        assert_eq!(coin.amount, amount);
    }

    #[test]
    fn test_private_coin_from_program() {
        let spend_secret = [0x42; 32];
        let puzzle_code = "(+ a b)";
        let amount = 1000;

        let coin = PrivateCoin::from_program(spend_secret, puzzle_code, amount);

        assert_eq!(coin.spend_secret, spend_secret);
        assert_eq!(coin.amount, amount);

        // Verify puzzle hash is computed correctly
        use sha2::{Digest, Sha256};
        let expected_hash = Sha256::digest(puzzle_code.as_bytes());
        assert_eq!(coin.puzzle_hash, expected_hash.as_slice());
    }

    #[test]
    fn test_nullifier_deterministic() {
        let spend_secret = [0x12; 32];
        let puzzle_hash = [0x11; 32];
        let coin1 = PrivateCoin::new(spend_secret, puzzle_hash, 100);
        let coin2 = PrivateCoin::new(spend_secret, puzzle_hash, 200);

        // Same spend_secret AND puzzle_hash should produce same nullifier regardless of amount
        assert_eq!(coin1.nullifier(), coin2.nullifier());

        // Different puzzle_hash should produce different nullifier (cross-puzzle replay protection)
        let coin3 = PrivateCoin::new(spend_secret, [0x22; 32], 100);
        assert_ne!(coin1.nullifier(), coin3.nullifier());
    }

    #[test]
    fn test_nullifier_unique() {
        let coin1 = PrivateCoin::new([0x11; 32], [0x33; 32], 100);
        let coin2 = PrivateCoin::new([0x22; 32], [0x33; 32], 100);

        // Different spend_secrets should produce different nullifiers
        assert_ne!(coin1.nullifier(), coin2.nullifier());
    }

    #[test]
    fn test_nullifier_hex() {
        let coin = PrivateCoin::new([0x42; 32], [0x13; 32], 100);
        let hex = coin.nullifier_hex();

        // Should be 64 hex characters (32 bytes * 2)
        assert_eq!(hex.len(), 64);
        // Should be valid hex
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_random_coin_creation() {
        let puzzle_hash = [0x42; 32];
        let coin1 = PrivateCoin::new_random(puzzle_hash, 100);
        let coin2 = PrivateCoin::new_random(puzzle_hash, 100);

        // Random coins should have different secrets and nullifiers
        assert_ne!(coin1.spend_secret, coin2.spend_secret);
        assert_ne!(coin1.nullifier(), coin2.nullifier());
        assert_eq!(coin1.puzzle_hash, coin2.puzzle_hash); // Same puzzle
    }

    #[test]
    fn test_random_coin_from_program() {
        let puzzle_code = "(+ a b)";
        let coin1 = PrivateCoin::new_random_from_program(puzzle_code, 100);
        let coin2 = PrivateCoin::new_random_from_program(puzzle_code, 100);

        // Random coins should have different secrets and nullifiers but same puzzle hash
        assert_ne!(coin1.spend_secret, coin2.spend_secret);
        assert_ne!(coin1.nullifier(), coin2.nullifier());
        assert_eq!(coin1.puzzle_hash, coin2.puzzle_hash);
    }

    #[test]
    fn test_coin_validation() {
        // Valid coin
        let valid_coin = PrivateCoin::new([0x42; 32], [0x13; 32], 100);
        assert!(valid_coin.validate().is_ok());

        // Invalid: all-zero spend secret
        let invalid_coin = PrivateCoin::new([0x00; 32], [0x13; 32], 100);
        assert!(invalid_coin.validate().is_err());

        // Invalid: all-zero puzzle hash
        let invalid_coin = PrivateCoin::new([0x42; 32], [0x00; 32], 100);
        assert!(invalid_coin.validate().is_err());
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
        // Valid bundle
        let valid_bundle = PrivateSpendBundle::new(vec![0x01, 0x02], [0x42; 32], vec![0x03]);
        assert!(valid_bundle.validate().is_ok());

        // Invalid: empty proof
        let invalid_bundle = PrivateSpendBundle::new(vec![], [0x42; 32], vec![0x03]);
        assert!(invalid_bundle.validate().is_err());

        // Invalid: zero nullifier
        let invalid_bundle = PrivateSpendBundle::new(vec![0x01], [0x00; 32], vec![0x03]);
        assert!(invalid_bundle.validate().is_err());
    }
}
