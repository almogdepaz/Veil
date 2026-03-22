/// TAIL enforcement tests for CAT spends.
///
/// Verifies that the guest (and mock backend) enforce:
///   1. A CAT spend requires tail_source to be Some.
///   2. tail_source must compile to a hash matching tail_hash (committed in coin commitment).
///   3. The compiled TAIL program must execute successfully.
///   4. XCH spends (tail_hash == None / [0;32]) proceed without TAIL regardless.
#[cfg(feature = "mock")]
mod cat_tail_enforcement {
    use clvm_zk_core::coin_commitment::XCH_TAIL;
    use clvm_zk_core::merkle::SparseMerkleTree;
    use clvm_zk_core::{
        compile_chialisp_to_bytecode, compute_coin_commitment, compute_serial_commitment,
        CoinMode, Input, ProgramParameter, SerialCommitmentData,
    };
    use clvm_zk_mock::MockBackend;
    use sha2::{Digest, Sha256};

    fn hash_data(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    /// Build a minimal Input for a single CAT spend.
    /// Returns (input, tail_hash) where tail_hash is the hash of the compiled tail_source.
    fn build_cat_spend_input(
        tail_source: Option<String>,
        tail_params: Vec<ProgramParameter>,
        tail_hash_override: Option<[u8; 32]>, // None = compute from tail_source
    ) -> Input {
        // simple pass-through puzzle: transfer full amount to a fixed recipient
        let inner_puzzle = "(mod (amount) (list (list 51 (sha256 1) amount)))";
        let (_, program_hash) =
            compile_chialisp_to_bytecode(hash_data, inner_puzzle).expect("inner puzzle compile");

        // compute the tail_hash to commit to
        let effective_tail_hash = tail_hash_override.unwrap_or_else(|| {
            let src = tail_source.as_deref().expect("need tail_source or tail_hash_override");
            let (_, h) = compile_chialisp_to_bytecode(hash_data, src).expect("tail compile");
            h
        });

        // coin secrets
        let serial_number: [u8; 32] = [0x11u8; 32];
        let serial_randomness: [u8; 32] = [0x22u8; 32];
        let amount: u64 = 1000;

        let serial_commitment =
            compute_serial_commitment(hash_data, &serial_number, &serial_randomness);
        let coin_commitment = compute_coin_commitment(
            hash_data,
            effective_tail_hash,
            amount,
            &program_hash,
            &serial_commitment,
        );

        // single-leaf merkle tree
        let mut tree = SparseMerkleTree::new(20, hash_data);
        let leaf_index = tree.insert(coin_commitment, hash_data);
        let merkle_root = tree.root();
        let proof = tree.generate_proof(leaf_index, hash_data).expect("merkle proof");

        Input {
            chialisp_source: inner_puzzle.to_string(),
            program_parameters: vec![ProgramParameter::Int(amount)],
            coin_mode: CoinMode::Spend(SerialCommitmentData {
                serial_number,
                serial_randomness,
                merkle_path: proof.path,
                coin_commitment,
                serial_commitment,
                merkle_root,
                leaf_index: leaf_index as u64,
                program_hash,
                amount,
            }),
            tail_hash: Some(effective_tail_hash),
            tail_source,
            tail_params,
            additional_coins: None,
        }
    }

    // ------------------------------------------------------------------
    // passing cases
    // ------------------------------------------------------------------

    #[test]
    fn test_cat_spend_trivial_tail_succeeds() {
        // TAIL = "(mod () 1)" — always succeeds, no params needed
        let tail_source = "(mod () 1)".to_string();
        let input = build_cat_spend_input(Some(tail_source), vec![], None);

        let backend = MockBackend::new().expect("backend");
        let result = backend.prove_with_input(input);
        assert!(result.is_ok(), "valid CAT spend should succeed: {:?}", result.err());
    }

    #[test]
    fn test_cat_spend_tail_with_params_succeeds() {
        // TAIL = "(mod (x) x)" — succeeds when x is truthy (non-zero int)
        let tail_source = "(mod (x) x)".to_string();
        let input = build_cat_spend_input(
            Some(tail_source),
            vec![ProgramParameter::Int(1)], // truthy param
            None,
        );

        let backend = MockBackend::new().expect("backend");
        let result = backend.prove_with_input(input);
        assert!(result.is_ok(), "CAT spend with truthy TAIL param should succeed: {:?}", result.err());
    }

    #[test]
    fn test_xch_spend_no_tail_required() {
        // XCH spend: tail_hash = None → TAIL enforcement skipped entirely
        let inner_puzzle = "(mod (amount) (list (list 51 (sha256 1) amount)))";
        let (_, program_hash) =
            compile_chialisp_to_bytecode(hash_data, inner_puzzle).expect("compile");

        let serial_number = [0x33u8; 32];
        let serial_randomness = [0x44u8; 32];
        let amount: u64 = 500;

        let serial_commitment =
            compute_serial_commitment(hash_data, &serial_number, &serial_randomness);
        let coin_commitment = compute_coin_commitment(
            hash_data,
            XCH_TAIL,  // XCH: [0;32]
            amount,
            &program_hash,
            &serial_commitment,
        );

        let mut tree = SparseMerkleTree::new(20, hash_data);
        let leaf_index = tree.insert(coin_commitment, hash_data);
        let merkle_root = tree.root();
        let proof = tree.generate_proof(leaf_index, hash_data).expect("proof");

        let input = Input {
            chialisp_source: inner_puzzle.to_string(),
            program_parameters: vec![ProgramParameter::Int(amount)],
            coin_mode: CoinMode::Spend(SerialCommitmentData {
                serial_number,
                serial_randomness,
                merkle_path: proof.path,
                coin_commitment,
                serial_commitment,
                merkle_root,
                leaf_index: leaf_index as u64,
                program_hash,
                amount,
            }),
            tail_hash: None, // XCH — TAIL not invoked
            tail_source: None,
            tail_params: vec![],
            additional_coins: None,
        };

        let backend = MockBackend::new().expect("backend");
        let result = backend.prove_with_input(input);
        assert!(result.is_ok(), "XCH spend without tail_source should succeed: {:?}", result.err());
    }

    // ------------------------------------------------------------------
    // rejection cases
    // ------------------------------------------------------------------

    #[test]
    fn test_cat_spend_missing_tail_source_rejected() {
        // tail_hash is set but tail_source is None → must be rejected
        let dummy_tail_hash = [0xdeu8; 32]; // non-zero: marks as CAT
        let input = build_cat_spend_input(
            None,                        // no tail_source
            vec![],
            Some(dummy_tail_hash),       // but tail_hash is set
        );

        let backend = MockBackend::new().expect("backend");
        let result = backend.prove_with_input(input);
        assert!(
            result.is_err(),
            "CAT spend without tail_source must be rejected"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("tail_source"),
            "error should mention tail_source, got: {err_msg}"
        );
    }

    #[test]
    fn test_cat_spend_wrong_tail_source_rejected() {
        // tail_source compiles to a DIFFERENT hash than what's committed in the coin
        // — the hash mismatch must be caught
        let committed_tail = "(mod () 1)".to_string(); // this is what's in the commitment
        let wrong_tail = "(mod () 2)".to_string();     // attacker provides different TAIL

        // compute the hash of the CORRECT tail (what gets committed)
        let (_, correct_hash) =
            compile_chialisp_to_bytecode(hash_data, &committed_tail).expect("compile");

        // build input committing to correct_hash but passing wrong_tail as source
        let input = build_cat_spend_input(
            Some(wrong_tail),   // wrong TAIL source
            vec![],
            Some(correct_hash), // commitment uses the correct hash
        );

        let backend = MockBackend::new().expect("backend");
        let result = backend.prove_with_input(input);
        assert!(
            result.is_err(),
            "CAT spend with mismatched tail_source must be rejected"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("tail_hash mismatch") || err_msg.contains("mismatch"),
            "error should indicate hash mismatch, got: {err_msg}"
        );
    }

    #[test]
    fn test_cat_spend_failing_tail_rejected() {
        // TAIL program that always fails: "(mod () 0)" → returns 0 (falsy in CLVM → raises exception)
        // Actually in CLVM, returning 0 is valid — the program needs to explicitly fail.
        // "(mod () (x))" → calls opcode x on nil, which raises an exception.
        let failing_tail = "(mod () (x))".to_string(); // guaranteed to throw
        let input = build_cat_spend_input(Some(failing_tail), vec![], None);

        let backend = MockBackend::new().expect("backend");
        let result = backend.prove_with_input(input);
        assert!(
            result.is_err(),
            "CAT spend with failing TAIL must be rejected"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("TAIL authorization failed") || err_msg.contains("TAIL"),
            "error should indicate TAIL failure, got: {err_msg}"
        );
    }
}
