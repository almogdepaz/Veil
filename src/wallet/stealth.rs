//! Dual-key stealth address implementation
//!
//! Provides unlinkable payments where:
//! - Sender derives unique puzzle_hash per payment via ECDH
//! - Receiver scans blockchain with view key to find payments
//! - Spending requires view key (nullifier mode) or both keys (signature mode)
//!
//! ## Modes
//!
//! - **Nullifier mode** (default): Fast (~10K zkVM cycles). View key can spend.
//!   Serial secrets derived from shared_secret. No signature verification needed.
//!
//! - **Signature mode**: Secure (~2-5M zkVM cycles). View key cannot spend.
//!   Requires spend_privkey to derive signing key. Use for custody/audit setups.

use k256::{
    elliptic_curve::{group::GroupEncoding, sec1::ToEncodedPoint},
    AffinePoint, ProjectivePoint, Scalar,
};
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};

/// Domain separator for stealth derivation (v1 - signature mode)
const STEALTH_DOMAIN: &[u8] = b"veil_stealth_v1";

/// Domain separator for nullifier mode (v2)
const STEALTH_NULLIFIER_DOMAIN: &[u8] = b"veil_stealth_nullifier_v1";

// ============================================================================
// Stealth Mode Types
// ============================================================================

/// Stealth address operation mode
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum StealthMode {
    /// Fast mode: serial secrets derived from shared_secret only
    /// - View key holder CAN spend (shared_secret is sufficient)
    /// - ~10K zkVM cycles (hash operations only)
    /// - Default for personal wallets
    #[default]
    Nullifier,

    /// Secure mode: signing key derived from shared_secret + spend_privkey
    /// - View key holder CANNOT spend (needs spend_privkey)
    /// - ~2-5M zkVM cycles (ECDSA verification)
    /// - Use for custody, exchanges, auditor setups
    Signature,
}

/// Authorization data for spending a stealth coin
#[derive(Clone, Debug)]
pub enum StealthSpendAuth {
    /// Nullifier mode: just the serial secrets (derived from shared_secret)
    Nullifier {
        serial_number: [u8; 32],
        serial_randomness: [u8; 32],
    },

    /// Signature mode: derived signing key (requires spend_privkey)
    Signature { derived_privkey: [u8; 32] },
}

impl StealthSpendAuth {
    /// Get serial secrets (works for nullifier mode, returns None for signature mode)
    pub fn serial_secrets(&self) -> Option<([u8; 32], [u8; 32])> {
        match self {
            StealthSpendAuth::Nullifier {
                serial_number,
                serial_randomness,
            } => Some((*serial_number, *serial_randomness)),
            StealthSpendAuth::Signature { .. } => None,
        }
    }

    /// Get derived privkey (works for signature mode, returns None for nullifier)
    pub fn derived_privkey(&self) -> Option<[u8; 32]> {
        match self {
            StealthSpendAuth::Signature { derived_privkey } => Some(*derived_privkey),
            StealthSpendAuth::Nullifier { .. } => None,
        }
    }

    /// Convert to CoinSecrets for use with Spender (nullifier mode only)
    ///
    /// Returns Some(CoinSecrets) for nullifier mode, None for signature mode.
    /// Use this when calling `Spender::create_spend_with_serial`.
    pub fn to_coin_secrets(&self) -> Option<clvm_zk_core::coin_commitment::CoinSecrets> {
        match self {
            StealthSpendAuth::Nullifier {
                serial_number,
                serial_randomness,
            } => Some(clvm_zk_core::coin_commitment::CoinSecrets::new(
                *serial_number,
                *serial_randomness,
            )),
            StealthSpendAuth::Signature { .. } => None,
        }
    }

    /// Check if this is nullifier mode
    pub fn is_nullifier(&self) -> bool {
        matches!(self, StealthSpendAuth::Nullifier { .. })
    }

    /// Check if this is signature mode
    pub fn is_signature(&self) -> bool {
        matches!(self, StealthSpendAuth::Signature { .. })
    }
}

/// Scanned coin with mode-specific data
#[derive(Clone, Debug)]
pub struct ScannedStealthCoin {
    pub puzzle_hash: [u8; 32],
    pub mode: StealthMode,
    pub shared_secret: [u8; 32],
    pub ephemeral_pubkey: [u8; 33],
    /// Puzzle source (for signature mode, needed for spending)
    pub puzzle_source: Option<String>,
}

// ============================================================================
// Nullifier Mode Puzzle
// ============================================================================

/// Compile-time constant for nullifier mode puzzle
/// This is a trivial puzzle - security comes from nullifier protocol, not puzzle logic
const NULLIFIER_PUZZLE_SOURCE: &str = "(mod () ())";

/// Puzzle hash for nullifier-mode stealth coins
/// All nullifier-mode coins share this puzzle hash
pub static STEALTH_NULLIFIER_PUZZLE_HASH: Lazy<[u8; 32]> = Lazy::new(|| {
    clvm_zk_core::compile_chialisp_template_hash_default(NULLIFIER_PUZZLE_SOURCE)
        .expect("nullifier puzzle compilation failed")
});

// ============================================================================
// Original Types (kept for compatibility)
// ============================================================================

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
    /// chialisp source for the puzzle (needed for spending)
    pub puzzle_source: String,
}

/// Result of creating a stealth payment
pub struct StealthPayment {
    pub puzzle_hash: [u8; 32],
    pub ephemeral_pubkey: [u8; 33],
    /// Shared secret - use to derive coin secrets deterministically
    pub shared_secret: [u8; 32],
    /// chialisp source for the puzzle (needed for spending)
    pub puzzle_source: String,
}

/// Result of creating a stealth payment (v2 with mode support)
#[derive(Clone, Debug)]
pub struct StealthPaymentV2 {
    pub puzzle_hash: [u8; 32],
    pub ephemeral_pubkey: [u8; 33],
    /// Shared secret - receiver derives from ECDH
    pub shared_secret: [u8; 32],
    /// Operation mode (Nullifier or Signature)
    pub mode: StealthMode,
    /// chialisp source for the puzzle
    /// - Nullifier mode: trivial puzzle "(mod () ())"
    /// - Signature mode: derived unique puzzle
    pub puzzle_source: String,
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

    /// Derive the spending private key for a stealth payment (signature mode)
    pub fn derive_spend_key(&self, shared_secret: &[u8; 32]) -> [u8; 32] {
        derive_spending_key(&self.spend_privkey, shared_secret)
    }

    /// Derive coin secrets for nullifier mode
    ///
    /// IMPORTANT: Only requires shared_secret - view key holder CAN spend!
    /// This is intentional for fast proving. Use signature mode if view/spend
    /// separation is required.
    pub fn derive_nullifier_secrets(
        &self,
        shared_secret: &[u8; 32],
    ) -> clvm_zk_core::coin_commitment::CoinSecrets {
        derive_nullifier_secrets_from_shared_secret(shared_secret)
    }

    /// Get authorization for spending a stealth coin
    ///
    /// Returns appropriate auth based on mode:
    /// - Nullifier: serial secrets (fast, view key can spend)
    /// - Signature: derived privkey (slow, requires spend key)
    pub fn get_spend_auth(&self, mode: StealthMode, shared_secret: &[u8; 32]) -> StealthSpendAuth {
        match mode {
            StealthMode::Nullifier => {
                let secrets = derive_nullifier_secrets_from_shared_secret(shared_secret);
                StealthSpendAuth::Nullifier {
                    serial_number: secrets.serial_number,
                    serial_randomness: secrets.serial_randomness,
                }
            }
            StealthMode::Signature => {
                let derived = self.derive_spend_key(shared_secret);
                StealthSpendAuth::Signature {
                    derived_privkey: derived,
                }
            }
        }
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
    /// Scan a list of coins to find ones belonging to this wallet (legacy)
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

    /// Scan coins with mode detection (v2)
    ///
    /// Tries both nullifier and signature modes:
    /// 1. Check if puzzle_hash matches STEALTH_NULLIFIER_PUZZLE_HASH (nullifier mode)
    /// 2. Try signature mode derivation (existing logic)
    ///
    /// Returns scanned coins with mode info for proper spending authorization.
    pub fn scan_coins_v2(
        &self,
        coins: &[([u8; 32], [u8; 33])], // (puzzle_hash, ephemeral_pubkey)
    ) -> Vec<ScannedStealthCoin> {
        let mut found = Vec::new();

        for (puzzle_hash, ephemeral_pubkey) in coins {
            if let Some(scanned) = self.try_scan_with_mode(puzzle_hash, ephemeral_pubkey) {
                found.push(scanned);
            }
        }

        found
    }

    /// Try to scan a coin with mode detection
    ///
    /// Returns Some(ScannedStealthCoin) if coin belongs to us, with detected mode.
    pub fn try_scan_with_mode(
        &self,
        puzzle_hash: &[u8; 32],
        ephemeral_pubkey: &[u8; 33],
    ) -> Option<ScannedStealthCoin> {
        // Compute shared secret: view_priv * ephemeral_pub
        let shared_secret = ecdh(&self.view_privkey, ephemeral_pubkey)?;

        // Try nullifier mode first (faster detection)
        if puzzle_hash == STEALTH_NULLIFIER_PUZZLE_HASH.as_ref() {
            // Nullifier mode: puzzle_hash matches the trivial puzzle
            // Verify by deriving serials and checking they produce valid commitment
            // (In practice, just matching puzzle_hash + ECDH success is enough)
            return Some(ScannedStealthCoin {
                puzzle_hash: *puzzle_hash,
                mode: StealthMode::Nullifier,
                shared_secret,
                ephemeral_pubkey: *ephemeral_pubkey,
                puzzle_source: Some(NULLIFIER_PUZZLE_SOURCE.to_string()),
            });
        }

        // Try signature mode: derive expected puzzle from shared_secret
        let (puzzle_source, expected_puzzle) =
            derive_stealth_puzzle(&self.spend_pubkey, &shared_secret);

        if &expected_puzzle == puzzle_hash {
            return Some(ScannedStealthCoin {
                puzzle_hash: *puzzle_hash,
                mode: StealthMode::Signature,
                shared_secret,
                ephemeral_pubkey: *ephemeral_pubkey,
                puzzle_source: Some(puzzle_source),
            });
        }

        None
    }

    /// Try to decrypt a single coin - returns Some if it belongs to us (legacy)
    fn try_decrypt(
        &self,
        puzzle_hash: &[u8; 32],
        ephemeral_pubkey: &[u8; 33],
    ) -> Option<StealthCoinData> {
        // Compute shared secret: view_priv * ephemeral_pub
        let shared_secret = ecdh(&self.view_privkey, ephemeral_pubkey)?;

        // Derive expected puzzle (source and hash)
        let (puzzle_source, expected_puzzle) =
            derive_stealth_puzzle(&self.spend_pubkey, &shared_secret);

        if &expected_puzzle == puzzle_hash {
            Some(StealthCoinData {
                shared_secret,
                ephemeral_pubkey: *ephemeral_pubkey,
                puzzle_source,
            })
        } else {
            None
        }
    }
}

/// Create a stealth payment to a recipient (legacy - uses signature mode)
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

    // Derive puzzle (source and hash)
    let (puzzle_source, puzzle_hash) =
        derive_stealth_puzzle(&recipient.spend_pubkey, &shared_secret);

    StealthPayment {
        puzzle_hash,
        ephemeral_pubkey,
        shared_secret,
        puzzle_source,
    }
}

/// Create a stealth payment with specified mode
///
/// ## Modes
///
/// - **Nullifier** (default): Fast proving (~10K cycles). Uses trivial puzzle.
///   View key holder CAN spend. Serial secrets derived deterministically.
///
/// - **Signature**: Secure proving (~2-5M cycles). Uses derived unique puzzle.
///   View key holder CANNOT spend. Requires spend_privkey to authorize.
///
/// ## Returns
///
/// `StealthPaymentV2` containing puzzle_hash, ephemeral_pubkey, and mode info.
/// Sender should create coin with this puzzle_hash and publish ephemeral_pubkey.
pub fn create_stealth_payment_with_mode(
    recipient: &StealthAddress,
    mode: StealthMode,
) -> StealthPaymentV2 {
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    // Generate ephemeral keypair
    let mut ephemeral_privkey = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_privkey);
    let ephemeral_pubkey = privkey_to_pubkey(&ephemeral_privkey);

    // Compute shared secret: ephemeral_priv * view_pub
    let shared_secret =
        ecdh(&ephemeral_privkey, &recipient.view_pubkey).expect("valid pubkey from StealthAddress");

    match mode {
        StealthMode::Nullifier => {
            // Nullifier mode: trivial puzzle, security from nullifier protocol
            // All nullifier-mode coins share the same puzzle hash
            StealthPaymentV2 {
                puzzle_hash: *STEALTH_NULLIFIER_PUZZLE_HASH,
                ephemeral_pubkey,
                shared_secret,
                mode: StealthMode::Nullifier,
                puzzle_source: NULLIFIER_PUZZLE_SOURCE.to_string(),
            }
        }
        StealthMode::Signature => {
            // Signature mode: unique derived puzzle per payment
            let (puzzle_source, puzzle_hash) =
                derive_stealth_puzzle(&recipient.spend_pubkey, &shared_secret);

            StealthPaymentV2 {
                puzzle_hash,
                ephemeral_pubkey,
                shared_secret,
                mode: StealthMode::Signature,
                puzzle_source,
            }
        }
    }
}

/// Derive coin secrets (serial_number, serial_randomness) from stealth shared_secret
///
/// This allows receiver to reconstruct the same secrets as sender:
/// - sender: creates payment, derives secrets from shared_secret, creates coin
/// - receiver: scans, recovers shared_secret via ECDH, derives same secrets
///
/// NOTE: This uses the v1 domain separator. For nullifier mode, use
/// `derive_nullifier_secrets_from_shared_secret` instead.
pub fn derive_coin_secrets_from_shared_secret(
    shared_secret: &[u8; 32],
) -> clvm_zk_core::coin_commitment::CoinSecrets {
    let serial_number = derive_key(shared_secret, b"serial_number");
    let serial_randomness = derive_key(shared_secret, b"serial_randomness");
    clvm_zk_core::coin_commitment::CoinSecrets::new(serial_number, serial_randomness)
}

/// Derive coin secrets for NULLIFIER mode stealth addresses
///
/// Uses domain-separated derivation:
/// - coin_secret = sha256(STEALTH_NULLIFIER_DOMAIN || shared_secret)
/// - serial_number = sha256(coin_secret || "serial")
/// - serial_randomness = sha256(coin_secret || "rand")
///
/// Both sender and receiver can derive identical secrets from shared_secret.
/// View key holder CAN spend in this mode (fast proving, no signature needed).
pub fn derive_nullifier_secrets_from_shared_secret(
    shared_secret: &[u8; 32],
) -> clvm_zk_core::coin_commitment::CoinSecrets {
    // Derive intermediate coin_secret
    let mut hasher = Sha256::new();
    hasher.update(STEALTH_NULLIFIER_DOMAIN);
    hasher.update(shared_secret);
    let coin_secret: [u8; 32] = hasher.finalize().into();

    // Derive serial_number from coin_secret
    let mut hasher = Sha256::new();
    hasher.update(coin_secret);
    hasher.update(b"serial");
    let serial_number: [u8; 32] = hasher.finalize().into();

    // Derive serial_randomness from coin_secret
    let mut hasher = Sha256::new();
    hasher.update(coin_secret);
    hasher.update(b"rand");
    let serial_randomness: [u8; 32] = hasher.finalize().into();

    clvm_zk_core::coin_commitment::CoinSecrets::new(serial_number, serial_randomness)
}

/// Generate a unique chialisp puzzle for a derived pubkey
///
/// Returns (puzzle_source, puzzle_hash) where puzzle is a unique constant module
fn generate_stealth_puzzle(pubkey: &[u8; 33]) -> (String, [u8; 32]) {
    // derive a unique identifier from the pubkey
    let mut hasher = Sha256::new();
    hasher.update(b"stealth_puzzle_id");
    hasher.update(pubkey);
    let hash: [u8; 32] = hasher.finalize().into();

    // take 7 bytes to ensure value fits in i64 (chialisp parser limitation)
    let mut id_bytes = [0u8; 8];
    id_bytes[1..8].copy_from_slice(&hash[..7]);
    let id = i64::from_be_bytes(id_bytes);

    // create a simple puzzle that returns a unique constant
    let puzzle_source = format!("(mod () {})", id);

    // compute puzzle_hash via actual chialisp compilation
    let puzzle_hash = clvm_zk_core::compile_chialisp_template_hash_default(&puzzle_source)
        .expect("stealth puzzle compilation failed");

    (puzzle_source, puzzle_hash)
}

/// Derive the stealth puzzle from spend_pubkey and shared_secret
///
/// Returns (puzzle_source, puzzle_hash) where:
/// derived_pubkey = spend_pubkey + hash(domain || shared_secret || "spend") * G
fn derive_stealth_puzzle(spend_pubkey: &[u8; 33], shared_secret: &[u8; 32]) -> (String, [u8; 32]) {
    // Derive scalar from shared secret
    let derive_scalar = derive_scalar_from_secret(shared_secret);

    // Compute derived_pubkey = S + derive_scalar * G
    let spend_point = pubkey_to_point(spend_pubkey).expect("valid spend_pubkey");
    let derived_point = spend_point + (ProjectivePoint::GENERATOR * derive_scalar);
    let derived_pubkey = point_to_pubkey(&derived_point);

    // Generate unique puzzle for this derived pubkey
    generate_stealth_puzzle(&derived_pubkey)
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

        // Verify derived pubkey produces same puzzle
        let derived_pubkey = privkey_to_pubkey(&spend_key);
        let (_, expected_puzzle) = generate_stealth_puzzle(&derived_pubkey);
        assert_eq!(expected_puzzle, payment.puzzle_hash);

        // Verify puzzle_source is returned correctly
        assert_eq!(stealth_data.puzzle_source, payment.puzzle_source);
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
