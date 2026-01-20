/// comprehensive transfer tests for XCH, CAT, and stealth address functionality
use clvm_zk_core::{CoinCommitment, SerialCommitment, XCH_TAIL};
use sha2::{Digest, Sha256};

fn hash_data(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ============================================================================
// XCH TRANSFER TESTS
// ============================================================================

#[test]
fn test_xch_commitment_format() {
    // v2.0 format: hash("clvm_zk_coin_v2.0" || tail_hash || amount || puzzle_hash || serial_commitment)
    let puzzle_hash = [0x42u8; 32];
    let amount = 1000u64;
    let serial = SerialCommitment([0x99u8; 32]);

    let commitment = CoinCommitment::compute(&XCH_TAIL, amount, &puzzle_hash, &serial, hash_data);

    // verify commitment is 32 bytes
    assert_eq!(commitment.as_bytes().len(), 32);

    // verify determinism
    let commitment2 = CoinCommitment::compute(&XCH_TAIL, amount, &puzzle_hash, &serial, hash_data);
    assert_eq!(commitment, commitment2);
}

#[test]
fn test_xch_different_amounts_different_commitments() {
    let puzzle_hash = [0x42u8; 32];
    let serial = SerialCommitment([0x99u8; 32]);

    let c1 = CoinCommitment::compute(&XCH_TAIL, 1000, &puzzle_hash, &serial, hash_data);
    let c2 = CoinCommitment::compute(&XCH_TAIL, 1001, &puzzle_hash, &serial, hash_data);

    assert_ne!(c1, c2, "different amounts must produce different commitments");
}

#[test]
fn test_xch_different_puzzles_different_commitments() {
    let serial = SerialCommitment([0x99u8; 32]);

    let c1 = CoinCommitment::compute(&XCH_TAIL, 1000, &[0x01u8; 32], &serial, hash_data);
    let c2 = CoinCommitment::compute(&XCH_TAIL, 1000, &[0x02u8; 32], &serial, hash_data);

    assert_ne!(c1, c2, "different puzzles must produce different commitments");
}

#[test]
fn test_xch_zero_amount_valid() {
    // zero-value outputs are valid (used for announcements, etc)
    let puzzle_hash = [0x42u8; 32];
    let serial = SerialCommitment([0x99u8; 32]);

    let commitment = CoinCommitment::compute(&XCH_TAIL, 0, &puzzle_hash, &serial, hash_data);
    assert_eq!(commitment.as_bytes().len(), 32);
}

#[test]
fn test_xch_max_amount_valid() {
    // max u64 amount should work
    let puzzle_hash = [0x42u8; 32];
    let serial = SerialCommitment([0x99u8; 32]);

    let commitment =
        CoinCommitment::compute(&XCH_TAIL, u64::MAX, &puzzle_hash, &serial, hash_data);
    assert_eq!(commitment.as_bytes().len(), 32);
}

// ============================================================================
// CAT (COLORED ASSET TOKEN) TESTS
// ============================================================================

#[test]
fn test_cat_commitment_differs_from_xch() {
    let puzzle_hash = [0x42u8; 32];
    let amount = 1000u64;
    let serial = SerialCommitment([0x99u8; 32]);

    // XCH uses zero tail_hash
    let xch_commitment = CoinCommitment::compute(&XCH_TAIL, amount, &puzzle_hash, &serial, hash_data);

    // CAT uses non-zero tail_hash (hash of TAIL program)
    let cat_tail = hash_data(b"my_cat_tail_program");
    let cat_commitment = CoinCommitment::compute(&cat_tail, amount, &puzzle_hash, &serial, hash_data);

    assert_ne!(
        xch_commitment, cat_commitment,
        "XCH and CAT with same amount/puzzle must have different commitments"
    );
}

#[test]
fn test_different_cats_different_commitments() {
    let puzzle_hash = [0x42u8; 32];
    let amount = 1000u64;
    let serial = SerialCommitment([0x99u8; 32]);

    let cat_a_tail = hash_data(b"cat_token_a");
    let cat_b_tail = hash_data(b"cat_token_b");

    let cat_a = CoinCommitment::compute(&cat_a_tail, amount, &puzzle_hash, &serial, hash_data);
    let cat_b = CoinCommitment::compute(&cat_b_tail, amount, &puzzle_hash, &serial, hash_data);

    assert_ne!(
        cat_a, cat_b,
        "different CAT types must have different commitments"
    );
}

#[test]
fn test_cat_tail_hash_format() {
    // tail_hash should be 32 bytes (sha256 of TAIL program)
    let tail_hash = hash_data(b"(mod () (x))"); // simple TAIL
    assert_eq!(tail_hash.len(), 32);

    // commitment with this tail should work
    let serial = SerialCommitment([0x99u8; 32]);
    let commitment =
        CoinCommitment::compute(&tail_hash, 1000, &[0x42u8; 32], &serial, hash_data);
    assert_eq!(commitment.as_bytes().len(), 32);
}

#[test]
fn test_cat_asset_isolation() {
    // same serial, puzzle, amount but different asset must be different commitment
    // this prevents cross-asset attacks
    let puzzle = [0x42u8; 32];
    let serial = SerialCommitment([0x11u8; 32]);
    let amount = 5000u64;

    let xch = CoinCommitment::compute(&XCH_TAIL, amount, &puzzle, &serial, hash_data);
    let cat1 = CoinCommitment::compute(&[0x01u8; 32], amount, &puzzle, &serial, hash_data);
    let cat2 = CoinCommitment::compute(&[0x02u8; 32], amount, &puzzle, &serial, hash_data);

    // all three must be different
    assert_ne!(xch, cat1);
    assert_ne!(xch, cat2);
    assert_ne!(cat1, cat2);
}

// ============================================================================
// SERIAL COMMITMENT TESTS
// ============================================================================

#[test]
fn test_serial_commitment_format() {
    // v1.0 format: hash("clvm_zk_serial_v1.0" || serial_number || serial_randomness)
    let serial_number = [0x11u8; 32];
    let serial_randomness = [0x22u8; 32];

    let commitment = SerialCommitment::compute(&serial_number, &serial_randomness, hash_data);

    assert_eq!(commitment.as_bytes().len(), 32);
}

#[test]
fn test_serial_commitment_determinism() {
    let serial_number = [0x11u8; 32];
    let serial_randomness = [0x22u8; 32];

    let c1 = SerialCommitment::compute(&serial_number, &serial_randomness, hash_data);
    let c2 = SerialCommitment::compute(&serial_number, &serial_randomness, hash_data);

    assert_eq!(c1, c2, "same inputs must produce same serial commitment");
}

#[test]
fn test_serial_commitment_different_randomness() {
    let serial_number = [0x11u8; 32];

    let c1 = SerialCommitment::compute(&serial_number, &[0x22u8; 32], hash_data);
    let c2 = SerialCommitment::compute(&serial_number, &[0x33u8; 32], hash_data);

    assert_ne!(
        c1, c2,
        "different randomness must produce different commitments"
    );
}

#[test]
fn test_serial_commitment_different_serial_number() {
    let serial_randomness = [0x22u8; 32];

    let c1 = SerialCommitment::compute(&[0x11u8; 32], &serial_randomness, hash_data);
    let c2 = SerialCommitment::compute(&[0x12u8; 32], &serial_randomness, hash_data);

    assert_ne!(
        c1, c2,
        "different serial numbers must produce different commitments"
    );
}

// ============================================================================
// NULLIFIER TESTS
// ============================================================================

#[test]
fn test_nullifier_format() {
    // nullifier = hash(serial_number || program_hash || amount)
    let serial_number = [0x11u8; 32];
    let program_hash = [0x42u8; 32];
    let amount = 1000u64;

    let mut data = Vec::with_capacity(72);
    data.extend_from_slice(&serial_number);
    data.extend_from_slice(&program_hash);
    data.extend_from_slice(&amount.to_be_bytes());
    let nullifier = hash_data(&data);

    assert_eq!(nullifier.len(), 32);
}

#[test]
fn test_nullifier_determinism() {
    let serial_number = [0x11u8; 32];
    let program_hash = [0x42u8; 32];
    let amount = 1000u64;

    let compute_nullifier = || {
        let mut data = Vec::with_capacity(72);
        data.extend_from_slice(&serial_number);
        data.extend_from_slice(&program_hash);
        data.extend_from_slice(&amount.to_be_bytes());
        hash_data(&data)
    };

    assert_eq!(
        compute_nullifier(),
        compute_nullifier(),
        "nullifier must be deterministic"
    );
}

#[test]
fn test_nullifier_excludes_randomness() {
    // nullifier intentionally excludes serial_randomness
    // this prevents linking nullifier to coin_commitment
    let serial_number = [0x11u8; 32];
    let program_hash = [0x42u8; 32];
    let amount = 1000u64;

    let mut data = Vec::with_capacity(72);
    data.extend_from_slice(&serial_number);
    data.extend_from_slice(&program_hash);
    data.extend_from_slice(&amount.to_be_bytes());
    let nullifier = hash_data(&data);

    // coin commitment includes serial_randomness, nullifier doesn't
    // this is by design for unlinkability
    let serial_commitment = SerialCommitment::compute(&serial_number, &[0x22u8; 32], hash_data);
    let coin_commitment =
        CoinCommitment::compute(&XCH_TAIL, amount, &program_hash, &serial_commitment, hash_data);

    // nullifier should NOT be derivable from coin_commitment
    // (they use completely different hash structures)
    assert_ne!(nullifier, *coin_commitment.as_bytes());
}

// ============================================================================
// COIN COMMITMENT PREIMAGE TESTS (v2.0 format)
// ============================================================================

#[test]
fn test_coin_commitment_preimage_size() {
    // v2.0: domain(17) || tail_hash(32) || amount(8) || puzzle_hash(32) || serial_commitment(32) = 121 bytes
    use clvm_zk_core::coin_commitment::{
        build_coin_commitment_preimage, COIN_COMMITMENT_PREIMAGE_SIZE,
    };

    assert_eq!(COIN_COMMITMENT_PREIMAGE_SIZE, 121);

    let preimage = build_coin_commitment_preimage(
        &XCH_TAIL,
        1000,
        &[0x42u8; 32],
        &[0x99u8; 32],
    );

    assert_eq!(preimage.len(), 121);
}

#[test]
fn test_coin_commitment_domain_separation() {
    use clvm_zk_core::coin_commitment::COIN_COMMITMENT_DOMAIN;

    assert_eq!(COIN_COMMITMENT_DOMAIN, b"clvm_zk_coin_v2.0");
    assert_eq!(COIN_COMMITMENT_DOMAIN.len(), 17);
}

// ============================================================================
// STEALTH ADDRESS TESTS
// ============================================================================

#[cfg(feature = "mock")]
mod stealth_tests {
    use clvm_zk::wallet::stealth::{create_stealth_payment, StealthKeys};

    #[test]
    fn test_stealth_payment_creation() {
        let receiver = StealthKeys::generate();
        let address = receiver.stealth_address();

        let payment = create_stealth_payment(&address);

        // payment should have valid puzzle_hash
        assert_eq!(payment.puzzle_hash.len(), 32);

        // ephemeral pubkey should be compressed (33 bytes)
        assert_eq!(payment.ephemeral_pubkey.len(), 33);

        // shared_secret should be 32 bytes
        assert_eq!(payment.shared_secret.len(), 32);

        // puzzle_source should be non-empty chialisp
        assert!(!payment.puzzle_source.is_empty());
    }

    #[test]
    fn test_stealth_unlinkability() {
        let receiver = StealthKeys::generate();
        let address = receiver.stealth_address();

        // multiple payments to same address
        let p1 = create_stealth_payment(&address);
        let p2 = create_stealth_payment(&address);
        let p3 = create_stealth_payment(&address);

        // all puzzle_hashes must be different (unlinkable)
        assert_ne!(p1.puzzle_hash, p2.puzzle_hash);
        assert_ne!(p2.puzzle_hash, p3.puzzle_hash);
        assert_ne!(p1.puzzle_hash, p3.puzzle_hash);

        // all ephemeral keys must be different
        assert_ne!(p1.ephemeral_pubkey, p2.ephemeral_pubkey);
        assert_ne!(p2.ephemeral_pubkey, p3.ephemeral_pubkey);
    }

    #[test]
    fn test_stealth_scanning() {
        let receiver = StealthKeys::generate();
        let wrong_receiver = StealthKeys::generate();

        let payment = create_stealth_payment(&receiver.stealth_address());

        // correct receiver finds it
        let view_key = receiver.view_only();
        let coins = [(payment.puzzle_hash, payment.ephemeral_pubkey)];
        let found = view_key.scan_coins(&coins);
        assert_eq!(found.len(), 1);

        // wrong receiver doesn't find it
        let wrong_view = wrong_receiver.view_only();
        let found_wrong = wrong_view.scan_coins(&coins);
        assert_eq!(found_wrong.len(), 0);
    }

    #[test]
    fn test_stealth_spend_key_derivation() {
        let receiver = StealthKeys::generate();
        let payment = create_stealth_payment(&receiver.stealth_address());

        // scan to get shared_secret
        let view_key = receiver.view_only();
        let coins = [(payment.puzzle_hash, payment.ephemeral_pubkey)];
        let found = view_key.scan_coins(&coins);
        let (_, stealth_data) = &found[0];

        // derive spend key
        let spend_key = receiver.derive_spend_key(&stealth_data.shared_secret);

        // spend_key should be 32 bytes (private key)
        assert_eq!(spend_key.len(), 32);

        // spend_key should be different from receiver's master spend key
        assert_ne!(spend_key, receiver.spend_privkey);
    }

    #[test]
    fn test_stealth_view_only_cannot_spend() {
        let receiver = StealthKeys::generate();
        let view_only = receiver.view_only();

        // view_only has view_privkey but only spend_PUBKEY
        assert_eq!(view_only.view_privkey.len(), 32);
        assert_eq!(view_only.spend_pubkey.len(), 33); // compressed pubkey, not privkey

        // cannot derive spend key from view_only (would need spend_privkey)
    }

    #[test]
    fn test_stealth_deterministic_from_seed() {
        let seed = b"my wallet seed phrase backup";

        let keys1 = StealthKeys::from_seed(seed);
        let keys2 = StealthKeys::from_seed(seed);

        assert_eq!(keys1.view_privkey, keys2.view_privkey);
        assert_eq!(keys1.spend_privkey, keys2.spend_privkey);

        // different seed = different keys
        let keys3 = StealthKeys::from_seed(b"different seed");
        assert_ne!(keys1.view_privkey, keys3.view_privkey);
    }
}

// ============================================================================
// INTEGRATION: COMMITMENT CHAIN VERIFICATION
// ============================================================================

#[test]
fn test_full_commitment_chain() {
    // simulate full coin creation flow:
    // 1. generate serial secrets
    // 2. compute serial_commitment
    // 3. compute coin_commitment
    // 4. verify chain is deterministic

    let serial_number = [0x11u8; 32];
    let serial_randomness = [0x22u8; 32];
    let puzzle_hash = [0x42u8; 32];
    let amount = 1000u64;

    // step 1: serial commitment
    let serial_commitment =
        SerialCommitment::compute(&serial_number, &serial_randomness, hash_data);

    // step 2: coin commitment (XCH)
    let coin_commitment =
        CoinCommitment::compute(&XCH_TAIL, amount, &puzzle_hash, &serial_commitment, hash_data);

    // step 3: nullifier (for spending)
    let mut nullifier_data = Vec::with_capacity(72);
    nullifier_data.extend_from_slice(&serial_number);
    nullifier_data.extend_from_slice(&puzzle_hash);
    nullifier_data.extend_from_slice(&amount.to_be_bytes());
    let nullifier = hash_data(&nullifier_data);

    // all outputs should be 32 bytes
    assert_eq!(serial_commitment.as_bytes().len(), 32);
    assert_eq!(coin_commitment.as_bytes().len(), 32);
    assert_eq!(nullifier.len(), 32);

    // all should be deterministic
    let serial2 = SerialCommitment::compute(&serial_number, &serial_randomness, hash_data);
    let coin2 =
        CoinCommitment::compute(&XCH_TAIL, amount, &puzzle_hash, &serial2, hash_data);

    assert_eq!(serial_commitment, serial2);
    assert_eq!(coin_commitment, coin2);
}

#[test]
fn test_cat_commitment_chain() {
    // same as above but for CAT
    let serial_number = [0x11u8; 32];
    let serial_randomness = [0x22u8; 32];
    let puzzle_hash = [0x42u8; 32];
    let amount = 1000u64;
    let cat_tail = hash_data(b"my_stablecoin_tail");

    let serial_commitment =
        SerialCommitment::compute(&serial_number, &serial_randomness, hash_data);
    let coin_commitment =
        CoinCommitment::compute(&cat_tail, amount, &puzzle_hash, &serial_commitment, hash_data);

    // must differ from XCH with same parameters
    let xch_commitment =
        CoinCommitment::compute(&XCH_TAIL, amount, &puzzle_hash, &serial_commitment, hash_data);

    assert_ne!(coin_commitment, xch_commitment);
}
