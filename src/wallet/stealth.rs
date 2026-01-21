//! stealth address implementation using ECDH
//!
//! provides unlinkable payments where:
//! - sender derives unique puzzle_hash per payment via ECDH
//! - receiver scans blockchain with view key to find payments
//! - spending uses nullifier protocol (view key can spend)
//!
//! ## security model
//!
//! - **nullifier mode** (only mode): fast (~10K zkVM cycles). view key holder CAN spend.
//!   serial secrets derived from shared_secret. security from nullifier protocol, not puzzle logic.

use k256::{
    elliptic_curve::{group::GroupEncoding, sec1::ToEncodedPoint},
    AffinePoint, ProjectivePoint, Scalar,
};
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};

/// domain separator for stealth derivation
const STEALTH_DOMAIN: &[u8] = b"veil_stealth_v1";

/// domain separator for nullifier mode
const STEALTH_NULLIFIER_DOMAIN: &[u8] = b"veil_stealth_nullifier_v1";

// ============================================================================
// nullifier mode puzzle
// ============================================================================

/// compile-time constant for nullifier mode puzzle
/// this is a trivial puzzle - security comes from nullifier protocol, not puzzle logic
const NULLIFIER_PUZZLE_SOURCE: &str = "(mod () ())";

/// puzzle hash for nullifier-mode stealth coins
/// all nullifier-mode coins share this puzzle hash
pub static STEALTH_NULLIFIER_PUZZLE_HASH: Lazy<[u8; 32]> = Lazy::new(|| {
    clvm_zk_core::compile_chialisp_template_hash_default(NULLIFIER_PUZZLE_SOURCE)
        .expect("nullifier puzzle compilation failed")
});

// ============================================================================
// types
// ============================================================================

/// authorization data for spending a stealth coin (nullifier mode only)
#[derive(Clone, Debug)]
pub struct StealthSpendAuth {
    pub serial_number: [u8; 32],
    pub serial_randomness: [u8; 32],
}

impl StealthSpendAuth {
    /// convert to CoinSecrets for use with Spender
    pub fn to_coin_secrets(&self) -> clvm_zk_core::coin_commitment::CoinSecrets {
        clvm_zk_core::coin_commitment::CoinSecrets::new(self.serial_number, self.serial_randomness)
    }
}

/// scanned coin with nullifier mode data
#[derive(Clone, Debug)]
pub struct ScannedStealthCoin {
    pub puzzle_hash: [u8; 32],
    pub shared_secret: [u8; 32],
    pub ephemeral_pubkey: [u8; 33],
    pub puzzle_source: String,
}

/// wallet keys for stealth addresses (view + spend separation)
#[derive(Clone)]
pub struct StealthKeys {
    pub view_privkey: [u8; 32],
    pub spend_privkey: [u8; 32],
}

/// public stealth address (safe to publish)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StealthAddress {
    pub view_pubkey: [u8; 33],
    pub spend_pubkey: [u8; 33],
}

/// view-only capability (can scan, cannot spend)
#[derive(Clone)]
pub struct StealthViewKey {
    pub view_privkey: [u8; 32],
    pub spend_pubkey: [u8; 33],
}

/// result of creating a stealth payment
#[derive(Clone, Debug)]
pub struct StealthPayment {
    pub puzzle_hash: [u8; 32],
    pub ephemeral_pubkey: [u8; 33],
    pub shared_secret: [u8; 32],
    pub puzzle_source: String,
}

impl StealthKeys {
    /// generate new random stealth keys
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

    /// derive from master seed using different paths
    pub fn from_seed(seed: &[u8]) -> Self {
        let view_privkey = derive_key(seed, b"stealth_view");
        let spend_privkey = derive_key(seed, b"stealth_spend");

        Self {
            view_privkey,
            spend_privkey,
        }
    }

    /// derive ephemeral key deterministically for stealth payment
    ///
    /// uses HD-style derivation: ephemeral_key = hash(view_privkey || "ephemeral" || index)
    /// this ensures:
    /// - deterministic generation (wallet recovery from seed)
    /// - no RNG failure risk
    /// - guaranteed uniqueness per index
    pub fn derive_ephemeral_key(&self, ephemeral_index: u32) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"veil_ephemeral_v1");
        hasher.update(&self.view_privkey);
        hasher.update(&ephemeral_index.to_le_bytes());
        hasher.finalize().into()
    }

    /// get public stealth address
    pub fn stealth_address(&self) -> StealthAddress {
        StealthAddress {
            view_pubkey: privkey_to_pubkey(&self.view_privkey),
            spend_pubkey: privkey_to_pubkey(&self.spend_privkey),
        }
    }

    /// extract view-only key (for watch-only wallets, auditors)
    pub fn view_only(&self) -> StealthViewKey {
        StealthViewKey {
            view_privkey: self.view_privkey,
            spend_pubkey: privkey_to_pubkey(&self.spend_privkey),
        }
    }

    /// get authorization for spending a stealth coin
    ///
    /// returns serial secrets for nullifier protocol.
    /// view key holder CAN spend (fast proving, no signatures).
    pub fn get_spend_auth(&self, shared_secret: &[u8; 32]) -> StealthSpendAuth {
        let secrets = derive_nullifier_secrets_from_shared_secret(shared_secret);
        StealthSpendAuth {
            serial_number: secrets.serial_number,
            serial_randomness: secrets.serial_randomness,
        }
    }
}

impl StealthAddress {
    /// encode as 66 bytes (view_pub || spend_pub)
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[..33].copy_from_slice(&self.view_pubkey);
        bytes[33..].copy_from_slice(&self.spend_pubkey);
        bytes
    }

    /// decode from 66 bytes
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
    /// scan coins for payments belonging to this wallet
    ///
    /// checks if puzzle_hash matches STEALTH_NULLIFIER_PUZZLE_HASH (nullifier mode)
    pub fn scan_coins(
        &self,
        coins: &[([u8; 32], [u8; 33])], // (puzzle_hash, ephemeral_pubkey)
    ) -> Vec<ScannedStealthCoin> {
        let mut found = Vec::new();

        for (puzzle_hash, ephemeral_pubkey) in coins {
            if let Some(scanned) = self.try_scan(puzzle_hash, ephemeral_pubkey) {
                found.push(scanned);
            }
        }

        found
    }

    /// try to scan a coin with optional verification tag
    ///
    /// returns Some(ScannedStealthCoin) if coin belongs to us
    ///
    /// # nullifier mode scanning limitation
    /// since all nullifier-mode stealth coins share the same puzzle_hash,
    /// this method produces false positives without additional verification.
    ///
    /// proper usage requires verification tag (derived from shared_secret)
    /// to filter out coins not actually sent to us.
    pub fn try_scan(
        &self,
        puzzle_hash: &[u8; 32],
        ephemeral_pubkey: &[u8; 33],
    ) -> Option<ScannedStealthCoin> {
        // compute shared secret: view_priv * ephemeral_pub
        let shared_secret = ecdh(&self.view_privkey, ephemeral_pubkey)?;

        // nullifier mode: puzzle_hash must match the trivial puzzle
        if puzzle_hash == STEALTH_NULLIFIER_PUZZLE_HASH.as_ref() {
            return Some(ScannedStealthCoin {
                puzzle_hash: *puzzle_hash,
                shared_secret,
                ephemeral_pubkey: *ephemeral_pubkey,
                puzzle_source: NULLIFIER_PUZZLE_SOURCE.to_string(),
            });
        }

        None
    }

    /// try to scan a coin with verification tag (recommended)
    ///
    /// verifies that derived_tag matches expected_tag to prevent false positives
    pub fn try_scan_with_tag(
        &self,
        puzzle_hash: &[u8; 32],
        ephemeral_pubkey: &[u8; 33],
        expected_tag: &[u8; 4],
    ) -> Option<ScannedStealthCoin> {
        // compute shared secret: view_priv * ephemeral_pub
        let shared_secret = ecdh(&self.view_privkey, ephemeral_pubkey)?;

        // derive verification tag from shared_secret
        let derived_tag = derive_stealth_tag(&shared_secret);

        // verify tag matches
        if &derived_tag != expected_tag {
            return None; // not our coin
        }

        // nullifier mode: puzzle_hash must match the trivial puzzle
        if puzzle_hash == STEALTH_NULLIFIER_PUZZLE_HASH.as_ref() {
            return Some(ScannedStealthCoin {
                puzzle_hash: *puzzle_hash,
                shared_secret,
                ephemeral_pubkey: *ephemeral_pubkey,
                puzzle_source: NULLIFIER_PUZZLE_SOURCE.to_string(),
            });
        }

        None
    }
}

/// derive verification tag from shared_secret
///
/// this 4-byte tag allows receivers to filter false positives when scanning
/// nullifier-mode stealth coins (which all share the same puzzle_hash)
pub fn derive_stealth_tag(shared_secret: &[u8; 32]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(b"veil_stealth_tag_v1");
    hasher.update(shared_secret);
    let hash: [u8; 32] = hasher.finalize().into();
    [hash[0], hash[1], hash[2], hash[3]]
}

/// create a stealth payment using HD-derived ephemeral key
///
/// uses nullifier mode: fast proving (~10K cycles), trivial puzzle, view key can spend.
///
/// # arguments
/// * `sender_keys` - sender's stealth keys (used to derive ephemeral key)
/// * `ephemeral_index` - index for ephemeral key derivation (track in wallet)
/// * `recipient` - recipient's stealth address
///
/// # security
/// ephemeral key derived deterministically: hash(sender_view_key || "ephemeral" || index)
/// - wallet recovery: regenerate all payments from seed + indices
/// - no RNG failure risk
/// - guaranteed uniqueness per index
pub fn create_stealth_payment_hd(
    sender_keys: &StealthKeys,
    ephemeral_index: u32,
    recipient: &StealthAddress,
) -> StealthPayment {
    // derive ephemeral keypair deterministically
    let ephemeral_privkey = sender_keys.derive_ephemeral_key(ephemeral_index);
    let ephemeral_pubkey = privkey_to_pubkey(&ephemeral_privkey);

    // compute shared secret: ephemeral_priv * view_pub
    let shared_secret =
        ecdh(&ephemeral_privkey, &recipient.view_pubkey).expect("valid pubkey from StealthAddress");

    // nullifier mode: trivial puzzle, security from nullifier protocol
    StealthPayment {
        puzzle_hash: *STEALTH_NULLIFIER_PUZZLE_HASH,
        ephemeral_pubkey,
        shared_secret,
        puzzle_source: NULLIFIER_PUZZLE_SOURCE.to_string(),
    }
}

/// create a stealth payment to a recipient (DEPRECATED - uses RNG)
///
/// WARNING: ephemeral key is RANDOM, not HD-derived. use create_stealth_payment_hd instead.
/// this function kept for backwards compatibility during transition.
///
/// # deprecated
/// use `create_stealth_payment_hd` with proper ephemeral_index tracking instead
#[deprecated(
    since = "0.2.0",
    note = "use create_stealth_payment_hd with ephemeral_index"
)]
pub fn create_stealth_payment(recipient: &StealthAddress) -> StealthPayment {
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    // generate ephemeral keypair (RANDOM - not recommended)
    let mut ephemeral_privkey = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_privkey);
    let ephemeral_pubkey = privkey_to_pubkey(&ephemeral_privkey);

    // compute shared secret: ephemeral_priv * view_pub
    let shared_secret =
        ecdh(&ephemeral_privkey, &recipient.view_pubkey).expect("valid pubkey from StealthAddress");

    // nullifier mode: trivial puzzle, security from nullifier protocol
    StealthPayment {
        puzzle_hash: *STEALTH_NULLIFIER_PUZZLE_HASH,
        ephemeral_pubkey,
        shared_secret,
        puzzle_source: NULLIFIER_PUZZLE_SOURCE.to_string(),
    }
}

/// derive coin secrets for NULLIFIER mode stealth addresses
///
/// uses domain-separated derivation:
/// - coin_secret = sha256(STEALTH_NULLIFIER_DOMAIN || shared_secret)
/// - serial_number = sha256(coin_secret || "serial")
/// - serial_randomness = sha256(coin_secret || "rand")
///
/// both sender and receiver can derive identical secrets from shared_secret.
/// view key holder CAN spend in this mode (fast proving, no signature needed).
pub fn derive_nullifier_secrets_from_shared_secret(
    shared_secret: &[u8; 32],
) -> clvm_zk_core::coin_commitment::CoinSecrets {
    // derive intermediate coin_secret
    let mut hasher = Sha256::new();
    hasher.update(STEALTH_NULLIFIER_DOMAIN);
    hasher.update(shared_secret);
    let coin_secret: [u8; 32] = hasher.finalize().into();

    // derive serial_number from coin_secret
    let mut hasher = Sha256::new();
    hasher.update(coin_secret);
    hasher.update(b"serial");
    let serial_number: [u8; 32] = hasher.finalize().into();

    // derive serial_randomness from coin_secret
    let mut hasher = Sha256::new();
    hasher.update(coin_secret);
    hasher.update(b"rand");
    let serial_randomness: [u8; 32] = hasher.finalize().into();

    clvm_zk_core::coin_commitment::CoinSecrets::new(serial_number, serial_randomness)
}

// ============================================================================
// internal helpers
// ============================================================================

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
    bytes_to_scalar_with_depth(bytes, 0)
}

fn bytes_to_scalar_with_depth(bytes: &[u8; 32], depth: u8) -> Scalar {
    use k256::elliptic_curve::PrimeField;

    // max depth guard - sha256 output >= curve order is ~1/2^128 probability
    // so hitting this more than twice is effectively impossible
    if depth > 3 {
        panic!("bytes_to_scalar: exceeded max reduction depth (should never happen)");
    }

    // try direct conversion first (valid if bytes < curve order)
    let opt: Option<Scalar> = Scalar::from_repr((*bytes).into()).into();
    match opt {
        Some(scalar) => scalar,
        None => {
            // if bytes >= curve order, hash to reduce and retry
            let mut hasher = Sha256::new();
            hasher.update(b"scalar_reduce");
            hasher.update(bytes);
            let reduced: [u8; 32] = hasher.finalize().into();
            bytes_to_scalar_with_depth(&reduced, depth + 1)
        }
    }
}

fn ecdh(privkey: &[u8; 32], pubkey: &[u8; 33]) -> Option<[u8; 32]> {
    let scalar = bytes_to_scalar(privkey);
    let point = pubkey_to_point(pubkey)?;
    let shared_point = point * scalar;

    // hash the shared point to get uniform bytes
    let shared_pubkey = point_to_pubkey(&shared_point);
    let mut hasher = Sha256::new();
    hasher.update(STEALTH_DOMAIN);
    hasher.update(b"ecdh");
    hasher.update(shared_pubkey);
    Some(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stealth_payment_roundtrip() {
        // receiver generates keys
        let receiver_keys = StealthKeys::generate();
        let stealth_address = receiver_keys.stealth_address();

        // sender creates payment
        let sender_keys = StealthKeys::generate();
        let payment = create_stealth_payment_hd(&sender_keys, 0, &stealth_address);

        // receiver scans with view key
        let view_key = receiver_keys.view_only();
        let coins = [(payment.puzzle_hash, payment.ephemeral_pubkey)];
        let found = view_key.scan_coins(&coins);

        assert_eq!(found.len(), 1);
        let scanned = &found[0];
        assert_eq!(scanned.puzzle_hash, payment.puzzle_hash);

        // verify shared secrets match
        assert_eq!(scanned.shared_secret, payment.shared_secret);

        // derive spending authorization
        let auth = receiver_keys.get_spend_auth(&scanned.shared_secret);
        let coin_secrets = auth.to_coin_secrets();

        // verify secrets are derivable
        assert_eq!(coin_secrets.serial_number.len(), 32);
        assert_eq!(coin_secrets.serial_randomness.len(), 32);
    }

    #[test]
    fn test_wrong_receiver_false_positive() {
        // nullifier mode produces false positives without verification tag
        let receiver_keys = StealthKeys::generate();
        let wrong_keys = StealthKeys::generate();

        #[allow(deprecated)]
        let payment = create_stealth_payment(&receiver_keys.stealth_address());

        // wrong receiver scans - gets false positive (puzzle_hash matches)
        let wrong_view = wrong_keys.view_only();
        let coins = [(payment.puzzle_hash, payment.ephemeral_pubkey)];
        let found_without_verification = wrong_view.scan_coins(&coins);

        // without tag verification, wrong receiver gets false positive
        assert_eq!(found_without_verification.len(), 1);

        // but shared_secret will be wrong (cannot spend)
        let wrong_secret = &found_without_verification[0].shared_secret;
        let correct_secret = &payment.shared_secret;
        assert_ne!(wrong_secret, correct_secret);

        // with tag verification, wrong receiver correctly filtered out
        let payment_tag = derive_stealth_tag(&payment.shared_secret);
        let scan_result = wrong_view.try_scan_with_tag(
            &payment.puzzle_hash,
            &payment.ephemeral_pubkey,
            &payment_tag,
        );
        assert!(scan_result.is_none()); // correctly rejected
    }

    #[test]
    fn test_multiple_payments_same_puzzle() {
        // in nullifier mode, all payments use same puzzle_hash
        let receiver_keys = StealthKeys::generate();
        let stealth_address = receiver_keys.stealth_address();

        let sender_keys = StealthKeys::generate();
        let payment1 = create_stealth_payment_hd(&sender_keys, 0, &stealth_address);
        let payment2 = create_stealth_payment_hd(&sender_keys, 1, &stealth_address);

        // SAME puzzle_hash (nullifier mode)
        assert_eq!(payment1.puzzle_hash, payment2.puzzle_hash);
        assert_eq!(payment1.puzzle_hash, *STEALTH_NULLIFIER_PUZZLE_HASH);

        // different ephemeral keys (unlinkability)
        assert_ne!(payment1.ephemeral_pubkey, payment2.ephemeral_pubkey);

        // different shared secrets
        assert_ne!(payment1.shared_secret, payment2.shared_secret);

        // but receiver can find both
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

    #[test]
    fn test_nullifier_secrets_deterministic() {
        let shared_secret = [42u8; 32];

        let secrets1 = derive_nullifier_secrets_from_shared_secret(&shared_secret);
        let secrets2 = derive_nullifier_secrets_from_shared_secret(&shared_secret);

        assert_eq!(secrets1.serial_number, secrets2.serial_number);
        assert_eq!(secrets1.serial_randomness, secrets2.serial_randomness);
    }

    #[test]
    fn test_hd_ephemeral_derivation_deterministic() {
        // HD ephemeral keys must be deterministic for wallet recovery
        let sender_keys = StealthKeys::generate();

        let eph0_a = sender_keys.derive_ephemeral_key(0);
        let eph0_b = sender_keys.derive_ephemeral_key(0);
        let eph1 = sender_keys.derive_ephemeral_key(1);

        // same index produces same key
        assert_eq!(eph0_a, eph0_b);

        // different indices produce different keys
        assert_ne!(eph0_a, eph1);
    }

    #[test]
    fn test_hd_payment_roundtrip() {
        // sender and receiver keys
        let sender_keys = StealthKeys::generate();
        let receiver_keys = StealthKeys::generate();
        let stealth_address = receiver_keys.stealth_address();

        // sender creates payment with HD ephemeral key
        let ephemeral_index = 0;
        let payment = create_stealth_payment_hd(&sender_keys, ephemeral_index, &stealth_address);

        // receiver scans with view key
        let view_key = receiver_keys.view_only();
        let coins = [(payment.puzzle_hash, payment.ephemeral_pubkey)];
        let found = view_key.scan_coins(&coins);

        assert_eq!(found.len(), 1);
        let scanned = &found[0];
        assert_eq!(scanned.puzzle_hash, payment.puzzle_hash);
        assert_eq!(scanned.shared_secret, payment.shared_secret);

        // derive spending authorization
        let auth = receiver_keys.get_spend_auth(&scanned.shared_secret);
        let coin_secrets = auth.to_coin_secrets();

        // verify secrets are derivable
        assert_eq!(coin_secrets.serial_number.len(), 32);
        assert_eq!(coin_secrets.serial_randomness.len(), 32);
    }

    #[test]
    fn test_hd_payment_deterministic_recreation() {
        // critical: sender can recreate payment details from ephemeral_index
        let sender_keys = StealthKeys::generate();
        let receiver_address = StealthKeys::generate().stealth_address();

        let ephemeral_index = 42;

        // create payment twice with same index
        let payment1 = create_stealth_payment_hd(&sender_keys, ephemeral_index, &receiver_address);
        let payment2 = create_stealth_payment_hd(&sender_keys, ephemeral_index, &receiver_address);

        // must produce identical results (critical for wallet recovery)
        assert_eq!(payment1.puzzle_hash, payment2.puzzle_hash);
        assert_eq!(payment1.ephemeral_pubkey, payment2.ephemeral_pubkey);
        assert_eq!(payment1.shared_secret, payment2.shared_secret);
    }

    #[test]
    fn test_hd_different_indices_unlinkable() {
        // payments to same recipient with different indices must be unlinkable
        let sender_keys = StealthKeys::generate();
        let receiver_address = StealthKeys::generate().stealth_address();

        let payment0 = create_stealth_payment_hd(&sender_keys, 0, &receiver_address);
        let payment1 = create_stealth_payment_hd(&sender_keys, 1, &receiver_address);

        // same puzzle_hash (nullifier mode)
        assert_eq!(payment0.puzzle_hash, payment1.puzzle_hash);

        // different ephemeral keys (unlinkability)
        assert_ne!(payment0.ephemeral_pubkey, payment1.ephemeral_pubkey);
        assert_ne!(payment0.shared_secret, payment1.shared_secret);
    }
}
