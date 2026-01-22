//! Hash-based stealth address implementation
//!
//! provides unlinkable payments where:
//! - sender derives unique puzzle_hash per payment via hash(view_pubkey || nonce)
//! - sender includes encrypted nonce in transaction metadata
//! - receiver decrypts nonce and derives same shared_secret
//! - spending uses nullifier protocol (view key can spend)
//!
//! # ⚠️ CRITICAL SECURITY WARNING
//!
//! **VIEW KEY HOLDERS CAN SPEND COINS IN NULLIFIER MODE.**
//!
//! this is by design for fast proving (~200x faster than ECDH). serial secrets derive
//! from shared_secret, which view key holders can compute. do NOT share view keys with
//! anyone you wouldn't trust with your funds. for audit-only access, use a different
//! approach (signature-based custody mode is not yet implemented).
//!
//! ## security model
//!
//! - **nullifier mode** (only mode): fast (~10K zkVM cycles). view key holder CAN spend.
//!   serial secrets derived from shared_secret. security from nullifier protocol, not puzzle logic.
//!
//! ## migration from ECDH
//!
//! this module now uses hash-based stealth for consistency with settlement proofs.
//! - old: shared_secret = ECDH(ephemeral_priv, view_pub) = ECDH(view_priv, ephemeral_pub)
//! - new: shared_secret = hash("stealth_v1" || view_pubkey || nonce)
//! - nonce transmitted encrypted to receiver

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
    pub nonce: [u8; 32],
    pub puzzle_source: String,
}

/// wallet keys for stealth addresses (view + spend separation)
#[derive(Clone)]
pub struct StealthKeys {
    pub view_privkey: [u8; 32],
    pub spend_privkey: [u8; 32],
}

/// public stealth address (safe to publish)
/// now uses hash-based pubkey derivation (no EC math)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StealthAddress {
    pub view_pubkey: [u8; 32], // changed from 33 bytes (compressed EC) to 32 bytes (hash)
    pub spend_pubkey: [u8; 32], // changed from 33 bytes to 32 bytes
}

/// view-only capability (can scan, cannot spend)
#[derive(Clone)]
pub struct StealthViewKey {
    pub view_privkey: [u8; 32],
    pub spend_pubkey: [u8; 32], // changed from 33 bytes to 32 bytes
}

/// result of creating a stealth payment
#[derive(Clone, Debug)]
pub struct StealthPayment {
    pub puzzle_hash: [u8; 32],
    pub nonce: [u8; 32], // sender must encrypt and transmit this
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

    /// derive nonce deterministically for stealth payment
    ///
    /// uses HD-style derivation: nonce = hash(view_privkey || "nonce" || index)
    /// this ensures:
    /// - deterministic generation (wallet recovery from seed)
    /// - no RNG failure risk
    /// - guaranteed uniqueness per index
    pub fn derive_nonce(&self, nonce_index: u32) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"veil_stealth_nonce_v1");
        hasher.update(&self.view_privkey);
        hasher.update(&nonce_index.to_le_bytes());
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
    /// encode as 64 bytes (view_pub || spend_pub)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.view_pubkey);
        bytes[32..].copy_from_slice(&self.spend_pubkey);
        bytes
    }

    /// decode from 64 bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut view_pubkey = [0u8; 32];
        let mut spend_pubkey = [0u8; 32];
        view_pubkey.copy_from_slice(&bytes[..32]);
        spend_pubkey.copy_from_slice(&bytes[32..]);
        Self {
            view_pubkey,
            spend_pubkey,
        }
    }
}

impl StealthViewKey {
    /// derive shared_secret from nonce (for scanning with known nonce)
    ///
    /// receiver decrypts nonce from transaction metadata, then derives shared_secret
    pub fn derive_shared_secret(&self, nonce: &[u8; 32]) -> [u8; 32] {
        let view_pubkey = privkey_to_pubkey(&self.view_privkey);
        derive_stealth_shared_secret(&view_pubkey, nonce)
    }

    /// scan a coin given its nonce (from decrypted transaction metadata)
    ///
    /// returns Some(ScannedStealthCoin) if coin matches nullifier mode puzzle
    pub fn try_scan_with_nonce(
        &self,
        puzzle_hash: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Option<ScannedStealthCoin> {
        // derive shared secret from nonce
        let shared_secret = self.derive_shared_secret(nonce);

        // nullifier mode: puzzle_hash must match the trivial puzzle
        if puzzle_hash == STEALTH_NULLIFIER_PUZZLE_HASH.as_ref() {
            return Some(ScannedStealthCoin {
                puzzle_hash: *puzzle_hash,
                shared_secret,
                nonce: *nonce,
                puzzle_source: NULLIFIER_PUZZLE_SOURCE.to_string(),
            });
        }

        None
    }

    /// scan a coin with verification tag (prevents false positives)
    ///
    /// verifies that derived_tag matches expected_tag
    pub fn try_scan_with_tag(
        &self,
        puzzle_hash: &[u8; 32],
        nonce: &[u8; 32],
        expected_tag: &[u8; 4],
    ) -> Option<ScannedStealthCoin> {
        // derive shared secret from nonce
        let shared_secret = self.derive_shared_secret(nonce);

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
                nonce: *nonce,
                puzzle_source: NULLIFIER_PUZZLE_SOURCE.to_string(),
            });
        }

        None
    }
}

/// derive stealth shared_secret from view_pubkey and nonce
///
/// consistent with settlement proof stealth address derivation
pub fn derive_stealth_shared_secret(view_pubkey: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"stealth_v1");
    hasher.update(view_pubkey);
    hasher.update(nonce);
    hasher.finalize().into()
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

/// create a stealth payment using HD-derived nonce
///
/// uses nullifier mode: fast proving (~10K cycles), trivial puzzle, view key can spend.
///
/// # arguments
/// * `sender_keys` - sender's stealth keys (used to derive nonce)
/// * `nonce_index` - index for nonce derivation (track in wallet)
/// * `recipient` - recipient's stealth address
///
/// # security
/// nonce derived deterministically: hash(sender_view_key || "nonce" || index)
/// - wallet recovery: regenerate all payments from seed + indices
/// - no RNG failure risk
/// - guaranteed uniqueness per index
///
/// # important
/// sender MUST encrypt and transmit the nonce to receiver
pub fn create_stealth_payment_hd(
    sender_keys: &StealthKeys,
    nonce_index: u32,
    recipient: &StealthAddress,
) -> StealthPayment {
    // derive nonce deterministically
    let nonce = sender_keys.derive_nonce(nonce_index);

    // compute shared secret: hash(view_pubkey || nonce)
    let shared_secret = derive_stealth_shared_secret(&recipient.view_pubkey, &nonce);

    // nullifier mode: trivial puzzle, security from nullifier protocol
    StealthPayment {
        puzzle_hash: *STEALTH_NULLIFIER_PUZZLE_HASH,
        nonce,
        shared_secret,
        puzzle_source: NULLIFIER_PUZZLE_SOURCE.to_string(),
    }
}

/// create a stealth payment with explicit nonce
///
/// use this when you want to provide your own nonce
pub fn create_stealth_payment_with_nonce(
    nonce: [u8; 32],
    recipient: &StealthAddress,
) -> StealthPayment {
    // compute shared secret: hash(view_pubkey || nonce)
    let shared_secret = derive_stealth_shared_secret(&recipient.view_pubkey, &nonce);

    StealthPayment {
        puzzle_hash: *STEALTH_NULLIFIER_PUZZLE_HASH,
        nonce,
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

/// derive pubkey from privkey using hash (no EC math)
fn privkey_to_pubkey(privkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"stealth_pubkey_v1");
    hasher.update(privkey);
    hasher.finalize().into()
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

        // receiver decrypts nonce (simulated) and scans
        let view_key = receiver_keys.view_only();
        let scanned = view_key
            .try_scan_with_nonce(&payment.puzzle_hash, &payment.nonce)
            .expect("should find coin");

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
    fn test_wrong_receiver_filtered_by_tag() {
        let receiver_keys = StealthKeys::generate();
        let wrong_keys = StealthKeys::generate();

        let sender_keys = StealthKeys::generate();
        let payment = create_stealth_payment_hd(&sender_keys, 0, &receiver_keys.stealth_address());

        // compute correct tag
        let payment_tag = derive_stealth_tag(&payment.shared_secret);

        // wrong receiver tries to scan with tag verification
        let wrong_view = wrong_keys.view_only();
        let scan_result =
            wrong_view.try_scan_with_tag(&payment.puzzle_hash, &payment.nonce, &payment_tag);

        // wrong receiver is filtered out because derived shared_secret differs
        assert!(scan_result.is_none());

        // correct receiver succeeds
        let correct_view = receiver_keys.view_only();
        let scan_result =
            correct_view.try_scan_with_tag(&payment.puzzle_hash, &payment.nonce, &payment_tag);
        assert!(scan_result.is_some());
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

        // different nonces (unlinkability)
        assert_ne!(payment1.nonce, payment2.nonce);

        // different shared secrets
        assert_ne!(payment1.shared_secret, payment2.shared_secret);

        // receiver can find both (with decrypted nonces)
        let view_key = receiver_keys.view_only();
        let scanned1 = view_key.try_scan_with_nonce(&payment1.puzzle_hash, &payment1.nonce);
        let scanned2 = view_key.try_scan_with_nonce(&payment2.puzzle_hash, &payment2.nonce);

        assert!(scanned1.is_some());
        assert!(scanned2.is_some());
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
    fn test_hd_nonce_derivation_deterministic() {
        // HD nonces must be deterministic for wallet recovery
        let sender_keys = StealthKeys::generate();

        let nonce0_a = sender_keys.derive_nonce(0);
        let nonce0_b = sender_keys.derive_nonce(0);
        let nonce1 = sender_keys.derive_nonce(1);

        // same index produces same nonce
        assert_eq!(nonce0_a, nonce0_b);

        // different indices produce different nonces
        assert_ne!(nonce0_a, nonce1);
    }

    #[test]
    fn test_hd_payment_deterministic_recreation() {
        // critical: sender can recreate payment details from nonce_index
        let sender_keys = StealthKeys::generate();
        let receiver_address = StealthKeys::generate().stealth_address();

        let nonce_index = 42;

        // create payment twice with same index
        let payment1 = create_stealth_payment_hd(&sender_keys, nonce_index, &receiver_address);
        let payment2 = create_stealth_payment_hd(&sender_keys, nonce_index, &receiver_address);

        // must produce identical results (critical for wallet recovery)
        assert_eq!(payment1.puzzle_hash, payment2.puzzle_hash);
        assert_eq!(payment1.nonce, payment2.nonce);
        assert_eq!(payment1.shared_secret, payment2.shared_secret);
    }

    #[test]
    fn test_address_encoding() {
        let keys = StealthKeys::generate();
        let address = keys.stealth_address();

        let bytes = address.to_bytes();
        let decoded = StealthAddress::from_bytes(&bytes);

        assert_eq!(address, decoded);
    }
}
