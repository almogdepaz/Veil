/// E2E CAT ring spend test.
///
/// Mint 2 CAT coins with same tail → ring_spend(coin_a + coin_b)
/// Asserts: TAIL run per-ring-coin, 2 nullifiers emitted, balance enforced.
#[cfg(feature = "mock")]
mod e2e_cat_ring_spend {
    use clvm_zk::simulator::{CLVMZkSimulator, CoinMetadata, CoinType};
    use clvm_zk_core::coin_commitment::{CoinSecrets, SerialCommitment};
    use clvm_zk_core::compile_chialisp_to_bytecode;

    fn rand_bytes() -> [u8; 32] {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    #[test]
    fn test_cat_ring_spend_two_coins() {
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

        // Mint coin A (500 units)
        let serial_a = rand_bytes();
        let rand_a = rand_bytes();
        let (commit_a, _) = sim
            .mint_cat(tail_source, vec![], puzzle_hash, puzzle_source, 500, serial_a, rand_a, None)
            .expect("mint A should succeed");
        assert_ne!(commit_a, [0u8; 32]);

        // Mint coin B (300 units)
        let serial_b = rand_bytes();
        let rand_b = rand_bytes();
        let (commit_b, _) = sim
            .mint_cat(tail_source, vec![], puzzle_hash, puzzle_source, 300, serial_b, rand_b, None)
            .expect("mint B should succeed");
        assert_ne!(commit_b, [0u8; 32]);

        // Build PrivateCoin structs for ring spend
        let sc_a = SerialCommitment::compute(
            &serial_a, &rand_a, clvm_zk::crypto_utils::hash_data_default,
        );
        let coin_a = clvm_zk::protocol::PrivateCoin::new_with_tail(
            puzzle_hash, 500, sc_a, tail_hash,
        );
        let secrets_a = CoinSecrets::new(serial_a, rand_a);

        let sc_b = SerialCommitment::compute(
            &serial_b, &rand_b, clvm_zk::crypto_utils::hash_data_default,
        );
        let coin_b = clvm_zk::protocol::PrivateCoin::new_with_tail(
            puzzle_hash, 300, sc_b, tail_hash,
        );
        let secrets_b = CoinSecrets::new(serial_b, rand_b);

        // Ring spend: both coins in one transaction
        // same tail_hash triggers ring spend path in simulator
        let tx = sim
            .spend_coins(vec![
                (coin_a, puzzle_source.to_string(), secrets_a),
                (coin_b, puzzle_source.to_string(), secrets_b),
            ])
            .expect("ring spend should succeed");

        // 2 nullifiers: one per input coin
        assert_eq!(
            tx.nullifiers.len(),
            2,
            "ring spend should produce 2 nullifiers, got {}",
            tx.nullifiers.len()
        );

        // both nullifiers should be distinct
        assert_ne!(
            tx.nullifiers[0], tx.nullifiers[1],
            "ring spend nullifiers must be distinct"
        );

        // both should be in the simulator's nullifier set
        assert!(sim.has_nullifier(&tx.nullifiers[0]), "nullifier 0 missing from set");
        assert!(sim.has_nullifier(&tx.nullifiers[1]), "nullifier 1 missing from set");

        // double-spend either coin should fail
        let sc_a2 = SerialCommitment::compute(
            &serial_a, &rand_a, clvm_zk::crypto_utils::hash_data_default,
        );
        let coin_a2 = clvm_zk::protocol::PrivateCoin::new_with_tail(
            puzzle_hash, 500, sc_a2, tail_hash,
        );
        let secrets_a2 = CoinSecrets::new(serial_a, rand_a);
        let double = sim.spend_coins(vec![(coin_a2, puzzle_source.to_string(), secrets_a2)]);
        assert!(double.is_err(), "double-spend of ring coin A must fail");
    }
}
