/// E2E settlement test.
///
/// Tests process_settlement on the simulator with fabricated output,
/// then verifies post-settlement coin spending works (NM-001 regression guard).
///
/// NOTE: prove_settlement requires risc0/sp1 backend — this test uses mock
/// by constructing SettlementOutput directly and testing the simulator's
/// settlement processing and post-settlement spend flow.
#[cfg(feature = "mock")]
mod e2e_settlement {
    use clvm_zk::protocol::settlement::SettlementOutput;
    use clvm_zk::simulator::{CLVMZkSimulator, CoinMetadata, CoinType};
    use clvm_zk_core::coin_commitment::{CoinSecrets, SerialCommitment, XCH_TAIL};
    use clvm_zk_core::{compile_chialisp_to_bytecode, compute_coin_commitment, compute_serial_commitment};
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

    #[test]
    fn test_settlement_process_and_post_spend() {
        let mut sim = CLVMZkSimulator::default();
        let puzzle_source = "(mod () 1)";
        let puzzle_hash = compile_chialisp_to_bytecode(
            clvm_zk::crypto_utils::hash_data_default,
            puzzle_source,
        )
        .unwrap()
        .1;

        // Fabricate settlement output:
        // maker (XCH) sends 500 to taker, gets CAT goods
        // taker (CAT) sends 300 to maker, gets XCH payment
        let (_, cat_tail) = compile_chialisp_to_bytecode(
            clvm_zk::crypto_utils::hash_data_default,
            "(mod () 1)",
        )
        .unwrap();

        // maker_change: maker gets back remaining XCH
        let mc_serial = rand_bytes();
        let mc_rand = rand_bytes();
        let mc_sc = compute_serial_commitment(hash_data, &mc_serial, &mc_rand);
        let maker_change_commitment = compute_coin_commitment(
            hash_data, XCH_TAIL, 200, &puzzle_hash, &mc_sc,
        );

        // payment: taker → maker (CAT)
        let pay_serial = rand_bytes();
        let pay_rand = rand_bytes();
        let pay_sc = compute_serial_commitment(hash_data, &pay_serial, &pay_rand);
        let payment_commitment = compute_coin_commitment(
            hash_data, cat_tail, 300, &puzzle_hash, &pay_sc,
        );

        // taker_goods: maker → taker (XCH)
        let goods_serial = rand_bytes();
        let goods_rand = rand_bytes();
        let goods_sc = compute_serial_commitment(hash_data, &goods_serial, &goods_rand);
        let taker_goods_commitment = compute_coin_commitment(
            hash_data, XCH_TAIL, 500, &puzzle_hash, &goods_sc,
        );

        // taker_change: taker's remaining CAT
        let tc_serial = rand_bytes();
        let tc_rand = rand_bytes();
        let tc_sc = compute_serial_commitment(hash_data, &tc_serial, &tc_rand);
        let taker_change_commitment = compute_coin_commitment(
            hash_data, cat_tail, 100, &puzzle_hash, &tc_sc,
        );

        // fabricated nullifiers
        let maker_nullifier = hash_data(b"maker_nullifier_test");
        let taker_nullifier = hash_data(b"taker_nullifier_test");

        let output = SettlementOutput {
            maker_nullifier,
            taker_nullifier,
            maker_change_commitment,
            payment_commitment,
            taker_goods_commitment,
            taker_change_commitment,
            maker_pubkey: [0u8; 32],
        };

        let root_before = sim.get_merkle_root();

        // Process settlement
        sim.process_settlement(&output).expect("settlement should succeed");

        // Verify: both nullifiers recorded
        assert!(sim.has_nullifier(&maker_nullifier), "maker nullifier missing");
        assert!(sim.has_nullifier(&taker_nullifier), "taker nullifier missing");

        // Verify: tree grew (4 new commitments)
        let root_after = sim.get_merkle_root();
        assert_ne!(root_before, root_after, "merkle root should change");

        // Verify: double settlement with same nullifiers fails
        let double = sim.process_settlement(&output);
        assert!(double.is_err(), "double settlement must fail");

        // NM-001 regression guard: post-settlement spend
        // Register maker_change in UTXO set and spend it
        let mc_secrets = CoinSecrets::new(mc_serial, mc_rand);
        let mc_coin = clvm_zk::protocol::PrivateCoin::new(
            puzzle_hash,
            200,
            SerialCommitment::compute(
                &mc_serial, &mc_rand, clvm_zk::crypto_utils::hash_data_default,
            ),
        );
        sim.add_coin(
            mc_coin.clone(),
            &mc_secrets,
            CoinMetadata {
                owner: "maker".to_string(),
                coin_type: CoinType::Regular,
                notes: "settlement change".to_string(),
            },
        );

        let mc_spend = sim.spend_coins(vec![(mc_coin, puzzle_source.to_string(), mc_secrets)]);
        assert!(
            mc_spend.is_ok(),
            "post-settlement maker_change spend should succeed: {:?}",
            mc_spend.err()
        );

        // Register taker_change (CAT) in UTXO set and spend it
        let tc_secrets = CoinSecrets::new(tc_serial, tc_rand);
        let tc_coin = clvm_zk::protocol::PrivateCoin::new_with_tail(
            puzzle_hash,
            100,
            SerialCommitment::compute(
                &tc_serial, &tc_rand, clvm_zk::crypto_utils::hash_data_default,
            ),
            cat_tail,
        );
        sim.add_coin_with_tail(
            tc_coin.clone(),
            &tc_secrets,
            CoinMetadata {
                owner: "taker".to_string(),
                coin_type: CoinType::Cat,
                notes: "settlement change".to_string(),
            },
            "(mod () 1)".to_string(),
        );

        let tc_spend = sim.spend_coins(vec![(tc_coin, puzzle_source.to_string(), tc_secrets)]);
        assert!(
            tc_spend.is_ok(),
            "post-settlement taker_change (CAT) spend should succeed: {:?}",
            tc_spend.err()
        );
    }
}
