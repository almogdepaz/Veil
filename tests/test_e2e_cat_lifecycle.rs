/// E2E CAT lifecycle test.
///
/// Full CAT lifecycle: mint → spend → verify nullifier
/// Asserts CAT nullifier ≠ XCH nullifier for same serial (v2 enforcement).
#[cfg(feature = "mock")]
mod e2e_cat_lifecycle {
    use clvm_zk::simulator::{CLVMZkSimulator, CoinMetadata, CoinType};
    use clvm_zk_core::coin_commitment::{CoinSecrets, SerialCommitment, XCH_TAIL};
    use clvm_zk_core::{compile_chialisp_to_bytecode, compute_nullifier_v2, compute_serial_commitment};

    fn rand_bytes() -> [u8; 32] {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    #[test]
    fn test_cat_full_lifecycle() {
        let mut sim = CLVMZkSimulator::default();
        let puzzle_source = "(mod () 1)";
        let puzzle_hash = compile_chialisp_to_bytecode(
            clvm_zk::crypto_utils::hash_data_default,
            puzzle_source,
        )
        .unwrap()
        .1;

        let tail_source = "(mod () 1)";
        let (_, tail_hash) = compile_chialisp_to_bytecode(
            clvm_zk::crypto_utils::hash_data_default,
            tail_source,
        )
        .unwrap();

        // Step 1: Mint a CAT coin
        let mint_serial = rand_bytes();
        let mint_rand = rand_bytes();
        let (coin_commitment, confirmed_tail) = sim
            .mint_cat(
                tail_source,
                vec![],
                puzzle_hash,
                puzzle_source,
                500,
                mint_serial,
                mint_rand,
                None,
            )
            .expect("mint should succeed");

        assert_eq!(confirmed_tail, tail_hash, "tail_hash from mint should match");
        assert_ne!(coin_commitment, [0u8; 32], "coin_commitment should be non-zero");

        // Step 2: Spend the minted CAT coin
        let serial_commitment = SerialCommitment::compute(
            &mint_serial,
            &mint_rand,
            clvm_zk::crypto_utils::hash_data_default,
        );
        let cat_coin = clvm_zk::protocol::PrivateCoin::new_with_tail(
            puzzle_hash,
            500,
            serial_commitment,
            tail_hash,
        );
        let secrets = CoinSecrets::new(mint_serial, mint_rand);

        let tx = sim
            .spend_coins(vec![(cat_coin, puzzle_source.to_string(), secrets)])
            .expect("CAT spend should succeed");

        assert_eq!(tx.nullifiers.len(), 1, "expected 1 nullifier from CAT spend");
        assert!(
            sim.has_nullifier(&tx.nullifiers[0]),
            "CAT nullifier should be in set"
        );

        // Step 3: Verify v2 nullifier binds tail_hash —
        // an XCH coin with the same serial/program/amount would produce a DIFFERENT nullifier
        let xch_nullifier = compute_nullifier_v2(
            clvm_zk::crypto_utils::hash_data_default,
            &XCH_TAIL,
            &mint_serial,
            &puzzle_hash,
            500,
        );
        let cat_nullifier = compute_nullifier_v2(
            clvm_zk::crypto_utils::hash_data_default,
            &tail_hash,
            &mint_serial,
            &puzzle_hash,
            500,
        );

        assert_ne!(
            xch_nullifier, cat_nullifier,
            "CAT nullifier must differ from XCH nullifier for same serial/puzzle/amount"
        );
        // The actual emitted nullifier should match the CAT variant
        assert_eq!(
            tx.nullifiers[0], cat_nullifier,
            "emitted nullifier should match locally computed CAT v2 nullifier"
        );
    }
}
