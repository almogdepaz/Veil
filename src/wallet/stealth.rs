//! Dual-key stealth address implementation
//!
//! Provides unlinkable payments where:
//! - Sender derives unique puzzle_hash per payment via ECDH
//! - Receiver scans blockchain with view key to find payments
//! - Spending requires both view and spend keys

use k256::{
    elliptic_curve::{group::GroupEncoding, sec1::ToEncodedPoint},
    AffinePoint, ProjectivePoint, Scalar,
};
use sha2::{Digest, Sha256};

/// Domain separator for stealth derivation
const STEALTH_DOMAIN: &[u8] = b"veil_stealth_v1";

/// Wallet keys for stealth addresses (view + spend separation)
#[derive(Clone)]
pub struct StealthKeys {
    pub view_privkey: [u8; 32],
    pub spend_privkey: [u8; 32],
}

/// Public stealth address (safe to publish)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StealthAddress {
    pub view_pubkey: [u8; 33],
    pub spend_pubkey: [u8; 33],
}

/// View-only capability (can scan, cannot spend)
#[derive(Clone)]
pub struct StealthViewKey {
    pub view_privkey: [u8; 32],
    pub spend_pubkey: [u8; 33],
}

/// Data needed to spend a stealth payment
#[derive(Clone, Debug)]
pub struct StealthCoinData {
    pub shared_secret: [u8; 32],
    pub ephemeral_pubkey: [u8; 33],
}

/// Result of creating a stealth payment
pub struct StealthPayment {
    pub puzzle_hash: [u8; 32],
    pub ephemeral_pubkey: [u8; 33],
}

impl StealthKeys {
    /// Generate new random stealth keys
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut view_privkey = [0u8; 32];
        let mut spend_privkey = [0u8; 32];
        rng.fill_bytes(&mut view_privkey);
        rng.fill_bytes(&mut spend_privkey);

        Self {
            view_privkey,
            spend_privkey,
        }
    }

    /// Derive from master seed using different paths
    pub fn from_seed(seed: &[u8]) -> Self {
        let view_privkey = derive_key(seed, b"stealth_view");
        let spend_privkey = derive_key(seed, b"stealth_spend");

        Self {
            view_privkey,
            spend_privkey,
        }
    }

    /// Get public stealth address
    pub fn stealth_address(&self) -> StealthAddress {
        StealthAddress {
            view_pubkey: privkey_to_pubkey(&self.view_privkey),
            spend_pubkey: privkey_to_pubkey(&self.spend_privkey),
        }
    }

    /// Extract view-only key (for watch-only wallets, auditors)
    pub fn view_only(&self) -> StealthViewKey {
        StealthViewKey {
            view_privkey: self.view_privkey,
            spend_pubkey: privkey_to_pubkey(&self.spend_privkey),
        }
    }

    /// Derive the spending private key for a stealth payment
    pub fn derive_spend_key(&self, shared_secret: &[u8; 32]) -> [u8; 32] {
        derive_spending_key(&self.spend_privkey, shared_secret)
    }
}

impl StealthAddress {
    /// Encode as 66 bytes (view_pub || spend_pub)
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[..33].copy_from_slice(&self.view_pubkey);
        bytes[33..].copy_from_slice(&self.spend_pubkey);
        bytes
    }

    /// Decode from 66 bytes
    pub fn from_bytes(bytes: &[u8; 66]) -> Self {
        let mut view_pubkey = [0u8; 33];
        let mut spend_pubkey = [0u8; 33];
        view_pubkey.copy_from_slice(&bytes[..33]);
        spend_pubkey.copy_from_slice(&bytes[33..]);
        Self {
            view_pubkey,
            spend_pubkey,
        }
    }
}

impl StealthViewKey {
    /// Scan a list of coins to find ones belonging to this wallet
    pub fn scan_coins(
        &self,
        coins: &[([u8; 32], [u8; 33])], // (puzzle_hash, ephemeral_pubkey)
    ) -> Vec<([u8; 32], StealthCoinData)> {
        let mut found = Vec::new();

        for (puzzle_hash, ephemeral_pubkey) in coins {
            if let Some(stealth_data) = self.try_decrypt(puzzle_hash, ephemeral_pubkey) {
                found.push((*puzzle_hash, stealth_data));
            }
        }

        found
    }

    /// Try to decrypt a single coin - returns Some if it belongs to us
    fn try_decrypt(
        &self,
        puzzle_hash: &[u8; 32],
        ephemeral_pubkey: &[u8; 33],
    ) -> Option<StealthCoinData> {
        // Compute shared secret: view_priv * ephemeral_pub
        let shared_secret = ecdh(&self.view_privkey, ephemeral_pubkey)?;

        // Derive expected puzzle_hash
        let expected_puzzle = derive_stealth_puzzle_hash(&self.spend_pubkey, &shared_secret);

        if &expected_puzzle == puzzle_hash {
            Some(StealthCoinData {
                shared_secret,
                ephemeral_pubkey: *ephemeral_pubkey,
            })
        } else {
            None
        }
    }
}

/// Create a stealth payment to a recipient
///
/// Returns the puzzle_hash to use and the ephemeral_pubkey to publish
pub fn create_stealth_payment(recipient: &StealthAddress) -> StealthPayment {
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    // Generate ephemeral keypair
    let mut ephemeral_privkey = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_privkey);
    let ephemeral_pubkey = privkey_to_pubkey(&ephemeral_privkey);

    // Compute shared secret: ephemeral_priv * view_pub
    let shared_secret =
        ecdh(&ephemeral_privkey, &recipient.view_pubkey).expect("valid pubkey from StealthAddress");

    // Derive puzzle_hash
    let puzzle_hash = derive_stealth_puzzle_hash(&recipient.spend_pubkey, &shared_secret);

    StealthPayment {
        puzzle_hash,
        ephemeral_pubkey,
    }
}

/// Derive the stealth puzzle_hash from spend_pubkey and shared_secret
///
/// puzzle_hash = hash(derived_pubkey) where:
/// derived_pubkey = spend_pubkey + hash(domain || shared_secret || "spend") * G
fn derive_stealth_puzzle_hash(spend_pubkey: &[u8; 33], shared_secret: &[u8; 32]) -> [u8; 32] {
    // Derive scalar from shared secret
    let derive_scalar = derive_scalar_from_secret(shared_secret);

    // Compute derived_pubkey = S + derive_scalar * G
    let spend_point = pubkey_to_point(spend_pubkey).expect("valid spend_pubkey");
    let derived_point = spend_point + (ProjectivePoint::GENERATOR * derive_scalar);
    let derived_pubkey = point_to_pubkey(&derived_point);

    // puzzle_hash = hash(derived_pubkey)
    // In practice this would be hash of the actual puzzle using derived_pubkey
    // For now, simplified to just hash the pubkey
    hash_puzzle(&derived_pubkey)
}

/// Derive the spending private key for a stealth payment
///
/// derived_priv = spend_priv + hash(domain || shared_secret || "spend")
fn derive_spending_key(spend_privkey: &[u8; 32], shared_secret: &[u8; 32]) -> [u8; 32] {
    let derive_scalar = derive_scalar_from_secret(shared_secret);

    // Load spend_privkey as scalar
    let spend_scalar = bytes_to_scalar(spend_privkey);

    // derived = spend + derive_scalar
    let derived_scalar = spend_scalar + derive_scalar;

    scalar_to_bytes(&derived_scalar)
}

// --- Internal helpers ---

fn derive_scalar_from_secret(shared_secret: &[u8; 32]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(STEALTH_DOMAIN);
    hasher.update(shared_secret);
    hasher.update(b"spend");
    let hash: [u8; 32] = hasher.finalize().into();

    // Reduce hash to valid scalar
    bytes_to_scalar(&hash)
}

fn derive_key(seed: &[u8], path: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STEALTH_DOMAIN);
    hasher.update(seed);
    hasher.update(path);
    hasher.finalize().into()
}

fn privkey_to_pubkey(privkey: &[u8; 32]) -> [u8; 33] {
    let scalar = bytes_to_scalar(privkey);
    let point = ProjectivePoint::GENERATOR * scalar;
    point_to_pubkey(&point)
}

fn point_to_pubkey(point: &ProjectivePoint) -> [u8; 33] {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true); // compressed
    let bytes = encoded.as_bytes();
    let mut result = [0u8; 33];
    result.copy_from_slice(bytes);
    result
}

fn pubkey_to_point(pubkey: &[u8; 33]) -> Option<ProjectivePoint> {
    let affine: Option<AffinePoint> = AffinePoint::from_bytes(pubkey.into()).into();
    affine.map(ProjectivePoint::from)
}

fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    use k256::elliptic_curve::PrimeField;
    // Try direct conversion first (valid if bytes < curve order)
    let opt: Option<Scalar> = Scalar::from_repr((*bytes).into()).into();
    match opt {
        Some(scalar) => scalar,
        None => {
            // If bytes >= curve order, hash to reduce and retry
            let mut hasher = Sha256::new();
            hasher.update(b"scalar_reduce");
            hasher.update(bytes);
            let reduced: [u8; 32] = hasher.finalize().into();
            bytes_to_scalar(&reduced)
        }
    }
}

fn scalar_to_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes().into()
}

fn ecdh(privkey: &[u8; 32], pubkey: &[u8; 33]) -> Option<[u8; 32]> {
    let scalar = bytes_to_scalar(privkey);
    let point = pubkey_to_point(pubkey)?;
    let shared_point = point * scalar;

    // Hash the shared point to get uniform bytes
    let shared_pubkey = point_to_pubkey(&shared_point);
    let mut hasher = Sha256::new();
    hasher.update(STEALTH_DOMAIN);
    hasher.update(b"ecdh");
    hasher.update(shared_pubkey);
    Some(hasher.finalize().into())
}

fn hash_puzzle(pubkey: &[u8; 33]) -> [u8; 32] {
    // Simplified: in reality would hash the actual chialisp puzzle
    // For stealth, we use a standard pay-to-pubkey puzzle
    let mut hasher = Sha256::new();
    hasher.update(b"veil_pay_to_pubkey_v1");
    hasher.update(pubkey);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stealth_payment_roundtrip() {
        // Receiver generates keys
        let receiver_keys = StealthKeys::generate();
        let stealth_address = receiver_keys.stealth_address();

        // Sender creates payment
        let payment = create_stealth_payment(&stealth_address);

        // Receiver scans with view key
        let view_key = receiver_keys.view_only();
        let coins = [(payment.puzzle_hash, payment.ephemeral_pubkey)];
        let found = view_key.scan_coins(&coins);

        assert_eq!(found.len(), 1);
        let (found_puzzle, stealth_data) = &found[0];
        assert_eq!(found_puzzle, &payment.puzzle_hash);

        // Receiver derives spending key
        let spend_key = receiver_keys.derive_spend_key(&stealth_data.shared_secret);

        // Verify spend key matches expected derived pubkey
        let derived_pubkey = privkey_to_pubkey(&spend_key);
        let expected_puzzle = hash_puzzle(&derived_pubkey);
        assert_eq!(expected_puzzle, payment.puzzle_hash);
    }

    #[test]
    fn test_wrong_receiver_cannot_find() {
        let receiver_keys = StealthKeys::generate();
        let wrong_keys = StealthKeys::generate();

        let payment = create_stealth_payment(&receiver_keys.stealth_address());

        // Wrong receiver tries to scan
        let wrong_view = wrong_keys.view_only();
        let coins = [(payment.puzzle_hash, payment.ephemeral_pubkey)];
        let found = wrong_view.scan_coins(&coins);

        assert_eq!(found.len(), 0);
    }

    #[test]
    fn test_multiple_payments_unlinkable() {
        let receiver_keys = StealthKeys::generate();
        let stealth_address = receiver_keys.stealth_address();

        let payment1 = create_stealth_payment(&stealth_address);
        let payment2 = create_stealth_payment(&stealth_address);

        // Different puzzle_hash for each payment
        assert_ne!(payment1.puzzle_hash, payment2.puzzle_hash);

        // Different ephemeral keys
        assert_ne!(payment1.ephemeral_pubkey, payment2.ephemeral_pubkey);

        // But receiver can find both
        let view_key = receiver_keys.view_only();
        let coins = [
            (payment1.puzzle_hash, payment1.ephemeral_pubkey),
            (payment2.puzzle_hash, payment2.ephemeral_pubkey),
        ];
        let found = view_key.scan_coins(&coins);

        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_from_seed_deterministic() {
        let seed = b"test seed for deterministic keys";

        let keys1 = StealthKeys::from_seed(seed);
        let keys2 = StealthKeys::from_seed(seed);

        assert_eq!(keys1.view_privkey, keys2.view_privkey);
        assert_eq!(keys1.spend_privkey, keys2.spend_privkey);
    }
}
