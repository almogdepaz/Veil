//! coin commitment structures for nullifier-based privacy
//!
//! - serial_commitment: hides the serial_number and randomness used for spending
//! - coin_commitment: commits to the full coin (amount, puzzle, serial_commitment)
//! - nullifier: the serial_number, revealed only when spending to prevent double-spends

extern crate alloc;

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// commitment to a serial number with blinding randomness
///
/// binds a coin to specific values that must be revealed when spending
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialCommitment(pub [u8; 32]);

impl SerialCommitment {
    /// create commitment from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SerialCommitment(bytes)
    }

    /// get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// compute commitment: hash(domain || serial_number || serial_randomness)
    pub fn compute(
        serial_number: &[u8; 32],
        serial_randomness: &[u8; 32],
        hasher: fn(&[u8]) -> [u8; 32],
    ) -> Self {
        const DOMAIN: &[u8] = b"clvm_zk_serial_v1.0";

        let mut data = Vec::with_capacity(DOMAIN.len() + 64);
        data.extend_from_slice(DOMAIN);
        data.extend_from_slice(serial_number);
        data.extend_from_slice(serial_randomness);

        SerialCommitment(hasher(&data))
    }

    /// verify that a commitment matches given serial_number and serial_randomness
    pub fn verify(
        &self,
        serial_number: &[u8; 32],
        serial_randomness: &[u8; 32],
        hasher: fn(&[u8]) -> [u8; 32],
    ) -> bool {
        let computed = Self::compute(serial_number, serial_randomness, hasher);
        computed == *self
    }
}

/// commitment to full coin data
///
/// used as a leaf in the global merkle tree to prove coin existence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinCommitment(pub [u8; 32]);

impl CoinCommitment {
    /// create commitment from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        CoinCommitment(bytes)
    }

    /// get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// compute commitment: hash(domain || amount || puzzle_hash || serial_commitment)
    pub fn compute(
        amount: u64,
        puzzle_hash: &[u8; 32],
        serial_commitment: &SerialCommitment,
        hasher: fn(&[u8]) -> [u8; 32],
    ) -> Self {
        const DOMAIN: &[u8] = b"clvm_zk_coin_v1.0";

        let mut data = Vec::with_capacity(DOMAIN.len() + 8 + 64);
        data.extend_from_slice(DOMAIN);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(puzzle_hash);
        data.extend_from_slice(serial_commitment.as_bytes());

        CoinCommitment(hasher(&data))
    }
}

/// wallet storage for coin secrets
///
/// stores the private information needed to spend a coin.
/// CRITICAL: losing these values = permanent loss of funds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinSecrets {
    /// the serial number - becomes the nullifier when spending
    pub serial_number: [u8; 32],

    /// randomness used to blind the serial commitment
    pub serial_randomness: [u8; 32],
}

impl CoinSecrets {
    /// create new coin secrets with explicit values
    pub fn new(serial_number: [u8; 32], serial_randomness: [u8; 32]) -> Self {
        CoinSecrets {
            serial_number,
            serial_randomness,
        }
    }

    /// create from 64-byte value (first 32 bytes = serial_number, last 32 = randomness)
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        let mut serial_number = [0u8; 32];
        let mut serial_randomness = [0u8; 32];
        serial_number.copy_from_slice(&bytes[..32]);
        serial_randomness.copy_from_slice(&bytes[32..]);
        Self::new(serial_number, serial_randomness)
    }

    /// compute the serial commitment for these secrets
    pub fn serial_commitment(&self, hasher: fn(&[u8]) -> [u8; 32]) -> SerialCommitment {
        SerialCommitment::compute(&self.serial_number, &self.serial_randomness, hasher)
    }

    /// get the nullifier (serial_number, revealed when spending)
    pub fn nullifier(&self) -> [u8; 32] {
        self.serial_number
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hasher(data: &[u8]) -> [u8; 32] {
        // simple xor-based test hasher
        let mut result = [0u8; 32];
        for (i, byte) in data.iter().enumerate() {
            result[i % 32] ^= byte;
        }
        result
    }

    #[test]
    fn test_serial_commitment_compute() {
        let serial_number = [1u8; 32];
        let serial_randomness = [2u8; 32];

        let commitment = SerialCommitment::compute(&serial_number, &serial_randomness, test_hasher);

        // verify it produces consistent output
        let commitment2 =
            SerialCommitment::compute(&serial_number, &serial_randomness, test_hasher);
        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_serial_commitment_verify() {
        let serial_number = [1u8; 32];
        let serial_randomness = [2u8; 32];

        let commitment = SerialCommitment::compute(&serial_number, &serial_randomness, test_hasher);

        // correct values verify
        assert!(commitment.verify(&serial_number, &serial_randomness, test_hasher));

        // wrong serial_number fails
        let wrong_serial = [99u8; 32];
        assert!(!commitment.verify(&wrong_serial, &serial_randomness, test_hasher));

        // wrong randomness fails
        let wrong_randomness = [99u8; 32];
        assert!(!commitment.verify(&serial_number, &wrong_randomness, test_hasher));
    }

    #[test]
    fn test_different_serials_different_commitments() {
        let serial_randomness = [2u8; 32];

        let serial1 = [1u8; 32];
        let serial2 = [3u8; 32];

        let commitment1 = SerialCommitment::compute(&serial1, &serial_randomness, test_hasher);
        let commitment2 = SerialCommitment::compute(&serial2, &serial_randomness, test_hasher);

        assert_ne!(commitment1, commitment2);
    }

    #[test]
    fn test_different_randomness_different_commitments() {
        let serial_number = [1u8; 32];

        let randomness1 = [2u8; 32];
        let randomness2 = [3u8; 32];

        let commitment1 = SerialCommitment::compute(&serial_number, &randomness1, test_hasher);
        let commitment2 = SerialCommitment::compute(&serial_number, &randomness2, test_hasher);

        assert_ne!(commitment1, commitment2);
    }

    #[test]
    fn test_coin_commitment_compute() {
        let amount = 1000u64;
        let puzzle_hash = [5u8; 32];
        let serial_commitment = SerialCommitment([6u8; 32]);

        let commitment =
            CoinCommitment::compute(amount, &puzzle_hash, &serial_commitment, test_hasher);

        // verify consistent
        let commitment2 =
            CoinCommitment::compute(amount, &puzzle_hash, &serial_commitment, test_hasher);
        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_different_amounts_different_commitments() {
        let puzzle_hash = [5u8; 32];
        let serial_commitment = SerialCommitment([6u8; 32]);

        let commitment1 =
            CoinCommitment::compute(1000, &puzzle_hash, &serial_commitment, test_hasher);
        let commitment2 =
            CoinCommitment::compute(2000, &puzzle_hash, &serial_commitment, test_hasher);

        assert_ne!(commitment1, commitment2);
    }

    #[test]
    fn test_coin_secrets_commitment() {
        let serial_number = [1u8; 32];
        let serial_randomness = [2u8; 32];
        let secrets = CoinSecrets::new(serial_number, serial_randomness);

        let commitment1 = secrets.serial_commitment(test_hasher);
        let commitment2 =
            SerialCommitment::compute(&serial_number, &serial_randomness, test_hasher);

        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_coin_secrets_nullifier() {
        let serial_number = [42u8; 32];
        let serial_randomness = [99u8; 32];
        let secrets = CoinSecrets::new(serial_number, serial_randomness);

        // nullifier is the serial_number
        assert_eq!(secrets.nullifier(), serial_number);
    }

    #[test]
    fn test_coin_secrets_from_bytes() {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&[1u8; 32]);
        bytes[32..].copy_from_slice(&[2u8; 32]);

        let secrets = CoinSecrets::from_bytes(bytes);

        assert_eq!(secrets.serial_number, [1u8; 32]);
        assert_eq!(secrets.serial_randomness, [2u8; 32]);
    }
}
