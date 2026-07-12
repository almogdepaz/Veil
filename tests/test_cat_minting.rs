/// CAT minting tests.
///
/// Verifies the full mint stack:
///   1. Unlimited TAIL (mod () 1) mints a coin — commitment in public_values[0]
///   2. Genesis coin path — nullifier in nullifiers[0]
///   3. Genesis coin prevents re-minting (double-spend via nullifier set)
///   4. TAIL returning nil → Err
///   5. Wrong tail_source (hash mismatch) → Err
///   6. Mint then spend the minted coin in same simulator session
#[cfg(feature = "mock")]
mod cat_minting {
    use clvm_zk::simulator::{CLVMZkSimulator, CoinMetadata, CoinType};
    use clvm_zk_core::coin_commitment::{CoinCommitment, CoinSecrets, SerialCommitment, XCH_TAIL};
    use clvm_zk_core::merkle::SparseMerkleTree;
    use clvm_zk_core::{
        compile_chialisp_to_bytecode, compute_coin_commitment, compute_genesis_nullifier,
        compute_serial_commitment, CoinMode, GenesisSpend, Input, MintData, ProgramParameter,
    };
    use clvm_zk_mock::MockBackend;
    use sha2::{Digest, Sha256};

    const TREE_DEPTH: usize = 20;

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

    /// Build a minimal mint Input for a given tail_source, optionally with genesis.
    fn build_mint_input(
        tail_source: &str,
        output_serial: [u8; 32],
        output_rand: [u8; 32],
        genesis_coin: Option<GenesisSpend>,
    ) -> Input {
        let (_, tail_hash) =
            compile_chialisp_to_bytecode(hash_data, tail_source).expect("tail compilation failed");

        let output_puzzle_hash = hash_data(b"test_output_puzzle");

        Input {
            chialisp_source: "(mod () ())".to_string(),
            program_parameters: vec![],
            coin_mode: CoinMode::Mint(MintData {
                tail_source: tail_source.to_string(),
                tail_params: vec![],
                output_puzzle_hash,
                output_amount: 1000,
                output_serial,
                output_rand,
                genesis_coin,
            }),
            tail_hash: Some(tail_hash),
            tail_source: None,
            tail_params: vec![],
            additional_coins: None,
        }
    }

    // ────────────────────────────────────────────────────────────
    // Test 1: unlimited TAIL mints — coin_commitment in public_values[0]
    // ────────────────────────────────────────────────────────────
    #[test]
    fn test_mint_unlimited_tail() {
        let backend = MockBackend::new().unwrap();
        let output_serial = rand_bytes();
        let output_rand = rand_bytes();
        let input = build_mint_input("(mod () 1)", output_serial, output_rand, None);

        let result = backend
            .prove_with_input(input)
            .expect("mint should succeed");

        // coin_commitment must be in public_values[0]
        assert_eq!(
            result.proof_output.public_values.len(),
            1,
            "expected exactly 1 public value (coin_commitment)"
        );
        assert_eq!(
            result.proof_output.public_values[0].len(),
            32,
            "coin_commitment must be 32 bytes"
        );

        // no genesis nullifier
        assert!(
            result.proof_output.nullifiers.is_empty(),
            "no genesis nullifier expected for unlimited TAIL"
        );

        // verify the commitment matches what we'd compute locally
        let (_, tail_hash) = compile_chialisp_to_bytecode(hash_data, "(mod () 1)").unwrap();
        let output_puzzle_hash = hash_data(b"test_output_puzzle");
        let serial_commitment = compute_serial_commitment(hash_data, &output_serial, &output_rand);
        let expected_commitment = compute_coin_commitment(
            hash_data,
            tail_hash,
            1000,
            &output_puzzle_hash,
            &serial_commitment,
        );

        let mut got = [0u8; 32];
        got.copy_from_slice(&result.proof_output.public_values[0]);
        assert_eq!(got, expected_commitment, "coin_commitment mismatch");
    }

    // ────────────────────────────────────────────────────────────
    // Test 2: genesis coin path — nullifier in nullifiers[0]
    // ────────────────────────────────────────────────────────────
    #[test]
    fn test_mint_genesis_nullifier() {
        // set up a tree with one genesis coin
        let mut tree = SparseMerkleTree::new(TREE_DEPTH, hash_data);

        let genesis_serial = rand_bytes();
        let genesis_rand = rand_bytes();
        let genesis_puzzle_hash = hash_data(b"genesis_puzzle");
        let genesis_amount = 500u64;
        let genesis_tail_hash = XCH_TAIL; // genesis is XCH

        let serial_commitment =
            compute_serial_commitment(hash_data, &genesis_serial, &genesis_rand);
        let coin_commitment = compute_coin_commitment(
            hash_data,
            genesis_tail_hash,
            genesis_amount,
            &genesis_puzzle_hash,
            &serial_commitment,
        );
        tree.insert(coin_commitment, hash_data);
        let proof = tree.generate_proof(0, hash_data).unwrap();
        let merkle_root = tree.root();

        let genesis = GenesisSpend {
            serial_number: genesis_serial,
            serial_randomness: genesis_rand,
            puzzle_hash: genesis_puzzle_hash,
            amount: genesis_amount,
            tail_hash: genesis_tail_hash,
            serial_commitment,
            coin_commitment,
            merkle_path: proof.path,
            merkle_root,
            leaf_index: 0,
        };

        let backend = MockBackend::new().unwrap();
        let output_serial = rand_bytes();
        let output_rand = rand_bytes();
        let input = build_mint_input("(mod () 1)", output_serial, output_rand, Some(genesis));

        let result = backend
            .prove_with_input(input)
            .expect("genesis mint should succeed");

        // genesis nullifier must be in nullifiers[0]
        assert_eq!(result.proof_output.nullifiers.len(), 1);
        let expected_nullifier =
            compute_genesis_nullifier(hash_data, &genesis_serial, &genesis_tail_hash);
        assert_eq!(result.proof_output.nullifiers[0], expected_nullifier);

        // coin_commitment still in public_values
        assert_eq!(result.proof_output.public_values.len(), 1);
    }

    // ────────────────────────────────────────────────────────────
    // Test 3: same genesis coin → second mint must fail (nullifier set)
    // ────────────────────────────────────────────────────────────
    #[test]
    fn test_mint_genesis_prevents_remint() {
        let mut sim = CLVMZkSimulator::default();

        // add genesis coin to simulator
        let genesis_puzzle = "(mod () 1)".to_string();
        let (genesis_coin, genesis_secrets) = clvm_zk::protocol::PrivateCoin::new_with_secrets(
            clvm_zk_core::compile_chialisp_to_bytecode(
                clvm_zk::crypto_utils::hash_data_default,
                &genesis_puzzle,
            )
            .unwrap()
            .1,
            500,
        );
        sim.add_coin(
            genesis_coin.clone(),
            &genesis_secrets,
            CoinMetadata {
                owner: "tester".to_string(),
                coin_type: CoinType::Regular,
                notes: "genesis".to_string(),
            },
        );

        let (merkle_path, leaf_index) = sim.get_merkle_path_and_index(&genesis_coin).unwrap();
        let merkle_root = sim.get_merkle_root();
        let serial_commitment = *genesis_coin.serial_commitment.as_bytes();
        let coin_commitment = CoinCommitment::compute(
            &genesis_coin.tail_hash,
            genesis_coin.amount,
            &genesis_coin.puzzle_hash,
            &genesis_coin.serial_commitment,
            clvm_zk::crypto_utils::hash_data_default,
        );

        let genesis = GenesisSpend {
            serial_number: genesis_secrets.serial_number,
            serial_randomness: genesis_secrets.serial_randomness,
            puzzle_hash: genesis_coin.puzzle_hash,
            amount: genesis_coin.amount,
            tail_hash: genesis_coin.tail_hash,
            serial_commitment,
            coin_commitment: coin_commitment.0,
            merkle_path,
            merkle_root,
            leaf_index: leaf_index as u64,
        };

        // first mint succeeds
        let output_serial1 = rand_bytes();
        let output_rand1 = rand_bytes();
        let result1 = sim.mint_cat(
            "(mod () 1)",
            vec![],
            hash_data(b"output_puzzle"),
            "(mod () 1)",
            100,
            output_serial1,
            output_rand1,
            Some(genesis.clone()),
        );
        assert!(result1.is_ok(), "first mint should succeed");

        // second mint with same genesis must fail — nullifier already used
        let output_serial2 = rand_bytes();
        let output_rand2 = rand_bytes();
        let result2 = sim.mint_cat(
            "(mod () 1)",
            vec![],
            hash_data(b"output_puzzle2"),
            "(mod () 1)",
            100,
            output_serial2,
            output_rand2,
            Some(genesis),
        );
        assert!(
            result2.is_err(),
            "second mint with same genesis should fail"
        );
        // The error is that the genesis merkle proof is stale (root changed after first mint),
        // OR the genesis nullifier was not checked at backend level (the simulator doesn't
        // re-check nullifier against the genesis when calling the prover again — it would
        // need a fresh merkle root). For proper prevention, the nullifier set check in the
        // simulator is the correct enforcement point.
        // This test documents the current behavior.
    }

    // ────────────────────────────────────────────────────────────
    // Test 4: TAIL returns nil → Err
    // ────────────────────────────────────────────────────────────
    #[test]
    fn test_mint_tail_nil_rejected() {
        let backend = MockBackend::new().unwrap();
        let output_serial = rand_bytes();
        let output_rand = rand_bytes();
        let input = build_mint_input("(mod () ())", output_serial, output_rand, None);

        let result = backend.prove_with_input(input);
        assert!(result.is_err(), "nil TAIL should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("nil"),
            "error should mention nil: {}",
            err
        );
    }

    // ────────────────────────────────────────────────────────────
    // Test 5: wrong tail_source (hash mismatch) → Err
    // ────────────────────────────────────────────────────────────
    #[test]
    fn test_mint_tail_hash_mismatch() {
        let backend = MockBackend::new().unwrap();
        let output_serial = rand_bytes();
        let output_rand = rand_bytes();

        // compile the REAL tail to get its hash
        let (_, real_tail_hash) = compile_chialisp_to_bytecode(hash_data, "(mod () 1)").unwrap();

        // build input with wrong tail_source but correct hash
        let input = Input {
            chialisp_source: "(mod () ())".to_string(),
            program_parameters: vec![],
            coin_mode: CoinMode::Mint(MintData {
                tail_source: "(mod (x) x)".to_string(), // WRONG source
                tail_params: vec![],
                output_puzzle_hash: hash_data(b"output_puzzle"),
                output_amount: 1000,
                output_serial,
                output_rand,
                genesis_coin: None,
            }),
            tail_hash: Some(real_tail_hash), // real hash of (mod () 1)
            tail_source: None,
            tail_params: vec![],
            additional_coins: None,
        };

        let result = backend.prove_with_input(input);
        assert!(result.is_err(), "hash mismatch should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("mismatch"),
            "error should mention mismatch: {}",
            err
        );
    }

    // ────────────────────────────────────────────────────────────
    // Test 6: mint then spend the minted coin in same simulator session
    // ────────────────────────────────────────────────────────────
    #[test]
    fn test_mint_then_spend() {
        let mut sim = CLVMZkSimulator::default();
        let puzzle_source = "(mod () 1)";
        let puzzle_hash =
            compile_chialisp_to_bytecode(clvm_zk::crypto_utils::hash_data_default, puzzle_source)
                .unwrap()
                .1;

        let output_serial = rand_bytes();
        let output_rand = rand_bytes();

        // mint
        let (coin_commitment, tail_hash) = sim
            .mint_cat(
                "(mod () 1)",
                vec![],
                puzzle_hash,
                puzzle_source,
                1000,
                output_serial,
                output_rand,
                None,
            )
            .expect("mint should succeed");

        assert_ne!(
            coin_commitment, [0u8; 32],
            "coin_commitment should be non-zero"
        );

        // build the PrivateCoin for spending
        let serial_commitment_bytes = compute_serial_commitment(
            clvm_zk::crypto_utils::hash_data_default,
            &output_serial,
            &output_rand,
        );
        let private_coin = clvm_zk::protocol::PrivateCoin::new_with_tail(
            puzzle_hash,
            1000,
            SerialCommitment::from_bytes(serial_commitment_bytes),
            tail_hash,
        );
        let secrets = CoinSecrets::new(output_serial, output_rand);

        // spend it
        let result = sim.spend_coins(vec![(private_coin, puzzle_source.to_string(), secrets)]);
        assert!(
            result.is_ok(),
            "spending minted coin should succeed: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().nullifiers.len(), 1, "expected 1 nullifier");
    }
}
