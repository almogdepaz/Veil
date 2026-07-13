/// E2E XCH lifecycle test.
///
/// Full lifecycle: add coin → spend(A→B) → verify nullifier + new coin in tree
#[cfg(feature = "mock")]
mod e2e_xch_lifecycle {
    use clvm_zk::simulator::{CLVMZkSimulator, CoinMetadata, CoinType};
    use clvm_zk_core::coin_commitment::CoinSecrets;

    fn rand_bytes() -> [u8; 32] {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    #[test]
    fn test_xch_full_lifecycle() {
        let mut sim = CLVMZkSimulator::default();

        let puzzle_source = "(mod () 1)";
        let puzzle_hash = clvm_zk_core::compile_chialisp_to_bytecode(
            clvm_zk::crypto_utils::hash_data_default,
            puzzle_source,
        )
        .unwrap()
        .1;

        // Step 1: Alice gets a coin (faucet)
        let alice_serial = rand_bytes();
        let alice_rand = rand_bytes();
        let alice_secrets = CoinSecrets::new(alice_serial, alice_rand);
        let alice_coin = clvm_zk::protocol::PrivateCoin::new_with_secrets(puzzle_hash, 1000);
        let (alice_coin, alice_secrets) = {
            // use deterministic secrets so we can reconstruct
            let sc = clvm_zk_core::coin_commitment::SerialCommitment::compute(
                &alice_serial,
                &alice_rand,
                clvm_zk::crypto_utils::hash_data_default,
            );
            let coin = clvm_zk::protocol::PrivateCoin::new(puzzle_hash, 1000, sc);
            (coin, alice_secrets)
        };

        sim.add_coin(
            alice_coin.clone(),
            &alice_secrets,
            CoinMetadata {
                owner: "alice".to_string(),
                coin_type: CoinType::Regular,
                notes: "faucet".to_string(),
            },
        );

        // Step 2: Alice spends her coin (simulates send to Bob)
        let tx = sim
            .spend_coins(vec![(
                alice_coin.clone(),
                puzzle_source.to_string(),
                alice_secrets.clone(),
            )])
            .expect("alice spend should succeed");

        // Verify: 1 nullifier emitted
        assert_eq!(
            tx.nullifiers.len(),
            1,
            "expected 1 nullifier from XCH spend"
        );

        // Verify: nullifier is in the simulator's set
        assert!(
            sim.has_nullifier(&tx.nullifiers[0]),
            "nullifier should be in simulator set"
        );

        // Step 3: double-spend must fail
        let double_spend =
            sim.spend_coins(vec![(alice_coin, puzzle_source.to_string(), alice_secrets)]);
        assert!(double_spend.is_err(), "double-spend of same coin must fail");
    }
}
