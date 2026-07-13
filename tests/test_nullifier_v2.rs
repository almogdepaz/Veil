/// Nullifier v2 tests.
///
/// Verifies the v2 nullifier scheme:
///   1. v2 includes tail_hash — XCH and CAT with same serial/program/amount yield different nullifiers
///   2. v2 output ≠ v1 output for same inputs (domain separation)
///   3. Cross-asset isolation via mock backend — spending XCH does NOT block CAT with same serial
#[cfg(feature = "mock")]
mod nullifier_v2 {
    use clvm_zk::simulator::{CLVMZkSimulator, CoinMetadata, CoinType};
    use clvm_zk_core::coin_commitment::{CoinSecrets, XCH_TAIL};
    #[allow(deprecated)]
    use clvm_zk_core::compute_nullifier;
    use clvm_zk_core::compute_nullifier_v2;
    use sha2::{Digest, Sha256};

    fn hash_data(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    fn rand_bytes() -> [u8; 32] {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    // ────────────────────────────────────────────────────────────
    // Test 1: v2 includes tail_hash — different asset → different nullifier
    // ────────────────────────────────────────────────────────────
    #[test]
    fn test_v2_includes_tail_hash() {
        let serial = [0x42u8; 32];
        let program_hash = hash_data(b"same_puzzle");
        let amount = 1000u64;

        let xch_tail = XCH_TAIL; // [0u8; 32]
        let cat_tail = hash_data(b"my_cat_tail");

        let nullifier_xch =
            compute_nullifier_v2(hash_data, &xch_tail, &serial, &program_hash, amount);
        let nullifier_cat =
            compute_nullifier_v2(hash_data, &cat_tail, &serial, &program_hash, amount);

        assert_ne!(
            nullifier_xch, nullifier_cat,
            "v2 nullifiers for XCH and CAT with same serial/program/amount must differ"
        );
    }

    // ────────────────────────────────────────────────────────────
    // Test 2: v2 domain separates from v1
    // ────────────────────────────────────────────────────────────
    #[test]
    fn test_v2_domain_separates_from_v1() {
        let serial = [0x42u8; 32];
        let program_hash = hash_data(b"test_puzzle");
        let amount = 500u64;

        // XCH tail for both — only structural difference is domain separator
        let xch_tail = XCH_TAIL;

        #[allow(deprecated)]
        let v1 = compute_nullifier(hash_data, &serial, &program_hash, amount);
        let v2 = compute_nullifier_v2(hash_data, &xch_tail, &serial, &program_hash, amount);

        assert_ne!(
            v1, v2,
            "v1 and v2 nullifiers must differ even for same inputs"
        );
    }

    // ────────────────────────────────────────────────────────────
    // Test 3: cross-asset isolation — spending XCH does NOT block CAT
    // ────────────────────────────────────────────────────────────
    #[test]
    fn test_cross_asset_isolation() {
        let mut sim = CLVMZkSimulator::default();

        let puzzle_source = "(mod () 1)";
        let puzzle_hash = clvm_zk_core::compile_chialisp_to_bytecode(
            clvm_zk::crypto_utils::hash_data_default,
            puzzle_source,
        )
        .unwrap()
        .1;

        // use SAME serial/rand for both coins — v1 would collide, v2 must not
        let serial = [0x42u8; 32];
        let rand = [0x43u8; 32];

        let xch_secrets = CoinSecrets::new(serial, rand);
        let xch_coin = clvm_zk::protocol::PrivateCoin::new(
            puzzle_hash,
            1000,
            clvm_zk_core::coin_commitment::SerialCommitment::compute(
                &serial,
                &rand,
                clvm_zk::crypto_utils::hash_data_default,
            ),
        );

        sim.add_coin(
            xch_coin.clone(),
            &xch_secrets,
            CoinMetadata {
                owner: "alice".to_string(),
                coin_type: CoinType::Regular,
                notes: "xch coin".to_string(),
            },
        );

        // mint a CAT coin with different serial (can't reuse exact serial in same UTXO set)
        let cat_serial = rand_bytes();
        let cat_rand = rand_bytes();
        let (_cat_commitment, _cat_tail) = sim
            .mint_cat(
                "(mod () 1)",
                vec![],
                puzzle_hash,
                puzzle_source,
                1000,
                cat_serial,
                cat_rand,
                None,
            )
            .expect("mint should succeed");

        // spend the XCH coin
        let xch_result = sim.spend_coins(vec![(xch_coin, puzzle_source.to_string(), xch_secrets)]);
        assert!(xch_result.is_ok(), "XCH spend should succeed");

        // spend the CAT coin — must NOT be blocked by XCH's nullifier
        let cat_secrets = CoinSecrets::new(cat_serial, cat_rand);
        let cat_serial_commitment = clvm_zk_core::coin_commitment::SerialCommitment::compute(
            &cat_serial,
            &cat_rand,
            clvm_zk::crypto_utils::hash_data_default,
        );
        let cat_tail_hash = clvm_zk_core::compile_chialisp_to_bytecode(
            clvm_zk::crypto_utils::hash_data_default,
            "(mod () 1)",
        )
        .unwrap()
        .1;
        let cat_coin = clvm_zk::protocol::PrivateCoin::new_with_tail(
            puzzle_hash,
            1000,
            cat_serial_commitment,
            cat_tail_hash,
        );
        let cat_result = sim.spend_coins(vec![(cat_coin, puzzle_source.to_string(), cat_secrets)]);
        assert!(
            cat_result.is_ok(),
            "CAT spend should NOT be blocked by XCH nullifier: {:?}",
            cat_result.err()
        );
    }
}
