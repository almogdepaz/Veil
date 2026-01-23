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

/// XCH (native currency) tail hash - all zeros
pub const XCH_TAIL: [u8; 32] = [0u8; 32];

/// Domain separator for coin commitment v2
pub const COIN_COMMITMENT_DOMAIN: &[u8; 17] = b"clvm_zk_coin_v2.0";

/// Total size of coin commitment preimage: domain(17) + tail(32) + amount(8) + puzzle(32) + serial(32) = 121
pub const COIN_COMMITMENT_PREIMAGE_SIZE: usize = 121;

/// Build coin commitment preimage into a fixed-size buffer (zero-allocation)
///
/// Use this in zkVM guests for efficiency. Returns the filled buffer.
///
/// Layout: domain(17) || tail_hash(32) || amount_be(8) || puzzle_hash(32) || serial_commitment(32)
#[inline]
pub fn build_coin_commitment_preimage(
    tail_hash: &[u8; 32],
    amount: u64,
    puzzle_hash: &[u8; 32],
    serial_commitment: &[u8; 32],
) -> [u8; COIN_COMMITMENT_PREIMAGE_SIZE] {
    let mut data = [0u8; COIN_COMMITMENT_PREIMAGE_SIZE];
    data[0..17].copy_from_slice(COIN_COMMITMENT_DOMAIN);
    data[17..49].copy_from_slice(tail_hash);
    data[49..57].copy_from_slice(&amount.to_be_bytes());
    data[57..89].copy_from_slice(puzzle_hash);
    data[89..121].copy_from_slice(serial_commitment);
    data
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

    /// compute commitment v2: hash(domain || tail_hash || amount || program_hash || serial_commitment)
    ///
    /// tail_hash identifies the asset type:
    /// - XCH (native): [0u8; 32] (use XCH_TAIL constant)
    /// - CAT: hash of the TAIL program
    pub fn compute(
        tail_hash: &[u8; 32],
        amount: u64,
        program_hash: &[u8; 32],
        serial_commitment: &SerialCommitment,
        hasher: fn(&[u8]) -> [u8; 32],
    ) -> Self {
        let data = build_coin_commitment_preimage(
            tail_hash,
            amount,
            program_hash,
            serial_commitment.as_bytes(),
        );
        CoinCommitment(hasher(&data))
    }
}

/// wallet storage for coin secrets
///
/// stores the private information needed to spend a coin.
/// CRITICAL: losing these values = permanent loss of funds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinSecrets {
    /// the serial number - used as input to nullifier computation when spending
    /// nullifier = hash(serial_number || program_hash || amount)
    pub serial_number: [u8; 32],

    /// randomness used to blind the serial commitment
    /// excluded from nullifier to prevent linkability
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

    /// get the serial number (used as input to nullifier computation when spending)
    pub fn serial_number(&self) -> [u8; 32] {
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
        let tail_hash = [0u8; 32]; // XCH
        let amount = 1000u64;
        let program_hash = [5u8; 32];
        let serial_commitment = SerialCommitment([6u8; 32]);

        let commitment = CoinCommitment::compute(
            &tail_hash,
            amount,
            &program_hash,
            &serial_commitment,
            test_hasher,
        );

        // verify consistent
        let commitment2 = CoinCommitment::compute(
            &tail_hash,
            amount,
            &program_hash,
            &serial_commitment,
            test_hasher,
        );
        assert_eq!(commitment, commitment2);

        // different tail_hash produces different commitment
        let cat_tail = [1u8; 32];
        let commitment3 = CoinCommitment::compute(
            &cat_tail,
            amount,
            &program_hash,
            &serial_commitment,
            test_hasher,
        );
        assert_ne!(commitment, commitment3);
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

        // serial_number accessor returns the serial_number
        assert_eq!(secrets.serial_number(), serial_number);
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

    // ========== CAT-specific tests ==========

    #[test]
    fn test_xch_tail_constant() {
        // XCH uses all-zeros tail_hash
        assert_eq!(XCH_TAIL, [0u8; 32]);
    }

    #[test]
    fn test_build_coin_commitment_preimage_layout() {
        let tail_hash = [0xAAu8; 32];
        let amount = 0x0102030405060708u64;
        let puzzle_hash = [0xBBu8; 32];
        let serial_commitment = [0xCCu8; 32];

        let preimage =
            build_coin_commitment_preimage(&tail_hash, amount, &puzzle_hash, &serial_commitment);

        // verify total size
        assert_eq!(preimage.len(), COIN_COMMITMENT_PREIMAGE_SIZE);
        assert_eq!(preimage.len(), 121);

        // verify layout: domain(17) || tail(32) || amount(8) || puzzle(32) || serial(32)
        assert_eq!(&preimage[0..17], COIN_COMMITMENT_DOMAIN);
        assert_eq!(&preimage[17..49], &tail_hash);
        assert_eq!(&preimage[49..57], &amount.to_be_bytes());
        assert_eq!(&preimage[57..89], &puzzle_hash);
        assert_eq!(&preimage[89..121], &serial_commitment);
    }

    #[test]
    fn test_cat_vs_xch_commitment_differs() {
        let amount = 1000u64;
        let puzzle_hash = [5u8; 32];
        let serial_commitment = SerialCommitment([6u8; 32]);

        // XCH commitment
        let xch_commitment = CoinCommitment::compute(
            &XCH_TAIL,
            amount,
            &puzzle_hash,
            &serial_commitment,
            test_hasher,
        );

        // CAT commitment with arbitrary TAIL hash
        let cat_tail: [u8; 32] = {
            let mut h = [0u8; 32];
            // simulate hash of a TAIL program
            for i in 0..32 {
                h[i] = (i as u8).wrapping_mul(7);
            }
            h
        };

        let cat_commitment = CoinCommitment::compute(
            &cat_tail,
            amount,
            &puzzle_hash,
            &serial_commitment,
            test_hasher,
        );

        // same coin data with different asset type must produce different commitment
        assert_ne!(xch_commitment, cat_commitment);
    }

    #[test]
    fn test_same_cat_tail_same_commitment() {
        let cat_tail = [0x42u8; 32]; // some TAIL hash
        let amount = 500u64;
        let puzzle_hash = [0x11u8; 32];
        let serial_commitment = SerialCommitment([0x22u8; 32]);

        let commitment1 = CoinCommitment::compute(
            &cat_tail,
            amount,
            &puzzle_hash,
            &serial_commitment,
            test_hasher,
        );

        let commitment2 = CoinCommitment::compute(
            &cat_tail,
            amount,
            &puzzle_hash,
            &serial_commitment,
            test_hasher,
        );

        // same inputs must produce identical commitment
        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_preimage_determinism() {
        // calling build_coin_commitment_preimage multiple times with same inputs
        // must produce identical preimage (critical for ZK reproducibility)
        let tail = [0xFFu8; 32];
        let amount = 999u64;
        let puzzle = [0xEEu8; 32];
        let serial = [0xDDu8; 32];

        let p1 = build_coin_commitment_preimage(&tail, amount, &puzzle, &serial);
        let p2 = build_coin_commitment_preimage(&tail, amount, &puzzle, &serial);

        assert_eq!(p1, p2);
    }
}
