#![cfg(feature = "mock")]

use clvm_zk::backends::mock::{hash_data, MockBackend};
use clvm_zk_core::merkle::SparseMerkleTree;
use clvm_zk_core::{
    build_network_proof_output_v1, compile_chialisp_to_bytecode, compute_coin_commitment,
    compute_serial_commitment, validate_network_request_v1, AdditionalCoinInput, CoinMode,
    GenesisSpend, Input, MintData, NetworkContextV1, NetworkExecutionResultV1, NetworkProofErrorV1,
    NetworkProofIntentV1, NetworkProofOutputV1, NetworkProofRequestV1, NetworkTransitionV1,
    ProgramParameter, SerialCommitmentData, NETWORK_PROTOCOL_V1,
};

#[test]
fn network_proof_contract_round_trips_with_explicit_faucet_identity() {
    let request = NetworkProofRequestV1 {
        context: NetworkContextV1 {
            network_id: [1; 32],
            protocol_version: NETWORK_PROTOCOL_V1,
            ledger_root: [2; 32],
            anchor_height: 7,
            expiry_height: 12,
            metadata_hash: [3; 32],
        },
        intent: NetworkProofIntentV1::FaucetMint {
            request_id: [4; 32],
        },
    };
    let output = NetworkProofOutputV1 {
        context: request.context.clone(),
        program_hash: [5; 32],
        transition: NetworkTransitionV1::FaucetMint {
            request_id: [4; 32],
            asset_tail_hash: [6; 32],
            public_amount: 100,
            output_commitment: [7; 32],
        },
        public_conditions: vec![8, 9],
        execution_cost: 42,
    };

    let request_bytes = borsh::to_vec(&request).expect("request should encode");
    let output_bytes = borsh::to_vec(&output).expect("output should encode");

    assert_eq!(
        borsh::from_slice::<NetworkProofRequestV1>(&request_bytes).unwrap(),
        request
    );
    assert_eq!(
        borsh::from_slice::<NetworkProofOutputV1>(&output_bytes).unwrap(),
        output
    );
}

#[test]
fn network_proof_output_v1_borsh_golden_hash() {
    let output = NetworkProofOutputV1 {
        context: context([2; 32]),
        program_hash: [5; 32],
        transition: NetworkTransitionV1::FaucetMint {
            request_id: [4; 32],
            asset_tail_hash: [6; 32],
            public_amount: 100,
            output_commitment: [7; 32],
        },
        public_conditions: vec![8, 9],
        execution_cost: 42,
    };

    assert_eq!(
        hash_data(&borsh::to_vec(&output).unwrap()),
        [
            154, 60, 20, 240, 231, 135, 53, 225, 131, 208, 44, 201, 194, 27, 167, 138, 6, 134, 52,
            9, 169, 179, 203, 17, 134, 207, 241, 42, 126, 45, 230, 149,
        ]
    );
}

fn context(root: [u8; 32]) -> NetworkContextV1 {
    NetworkContextV1 {
        network_id: [1; 32],
        protocol_version: NETWORK_PROTOCOL_V1,
        ledger_root: root,
        anchor_height: 7,
        expiry_height: 12,
        metadata_hash: [3; 32],
    }
}

fn spend_data(root: [u8; 32]) -> SerialCommitmentData {
    SerialCommitmentData {
        serial_number: [10; 32],
        serial_randomness: [11; 32],
        merkle_path: vec![],
        coin_commitment: [12; 32],
        serial_commitment: [13; 32],
        merkle_root: root,
        leaf_index: 0,
        program_hash: [14; 32],
        amount: 1,
    }
}

fn input(mode: CoinMode, request: NetworkProofRequestV1) -> Input {
    Input {
        chialisp_source: "(mod () 1)".to_string(),
        program_parameters: vec![],
        coin_mode: mode,
        tail_hash: None,
        tail_source: None,
        tail_params: vec![],
        additional_coins: None,
        network: Some(request),
    }
}

#[test]
fn network_request_requires_mode_and_membership_roots_to_match() {
    let root = [21; 32];
    let request = NetworkProofRequestV1 {
        context: context(root),
        intent: NetworkProofIntentV1::PrivateTransfer,
    };
    let mut spend = input(CoinMode::Spend(spend_data(root)), request);

    assert!(validate_network_request_v1(&spend).is_ok());

    spend.additional_coins = Some(vec![AdditionalCoinInput {
        chialisp_source: "(mod () 1)".to_string(),
        program_parameters: vec![],
        serial_commitment_data: spend_data([22; 32]),
        tail_hash: [0; 32],
        tail_source: None,
        tail_params: vec![],
    }]);
    assert_eq!(
        validate_network_request_v1(&spend),
        Err(NetworkProofErrorV1::LedgerRootMismatch)
    );
}

#[test]
fn faucet_request_requires_mint_mode_and_explicit_asset() {
    let request = NetworkProofRequestV1 {
        context: context([31; 32]),
        intent: NetworkProofIntentV1::FaucetMint {
            request_id: [32; 32],
        },
    };
    let mut mint = input(
        CoinMode::Mint(MintData {
            tail_source: "(mod () 1)".to_string(),
            tail_params: vec![],
            output_puzzle_hash: [33; 32],
            output_amount: 100,
            output_serial: [34; 32],
            output_rand: [35; 32],
            genesis_coin: None,
        }),
        request,
    );

    assert_eq!(
        validate_network_request_v1(&mint),
        Err(NetworkProofErrorV1::MissingAssetTailHash)
    );

    mint.tail_hash = Some([36; 32]);
    assert!(validate_network_request_v1(&mint).is_ok());

    if let CoinMode::Mint(mint_data) = &mut mint.coin_mode {
        mint_data.genesis_coin = Some(GenesisSpend {
            serial_number: [1; 32],
            serial_randomness: [2; 32],
            puzzle_hash: [3; 32],
            amount: 1,
            tail_hash: [0; 32],
            serial_commitment: [4; 32],
            coin_commitment: [5; 32],
            merkle_path: vec![],
            merkle_root: [6; 32],
            leaf_index: 0,
        });
    }
    assert_eq!(
        validate_network_request_v1(&mint),
        Err(NetworkProofErrorV1::UnsupportedFaucetGenesis)
    );

    mint.coin_mode = CoinMode::Execute;
    assert_eq!(
        validate_network_request_v1(&mint),
        Err(NetworkProofErrorV1::IntentModeMismatch)
    );
}

#[test]
fn faucet_output_binds_request_asset_amount_commitment_and_context() {
    let request = NetworkProofRequestV1 {
        context: context([41; 32]),
        intent: NetworkProofIntentV1::FaucetMint {
            request_id: [42; 32],
        },
    };
    let mut mint = input(
        CoinMode::Mint(MintData {
            tail_source: "(mod () 1)".to_string(),
            tail_params: vec![],
            output_puzzle_hash: [43; 32],
            output_amount: 100,
            output_serial: [44; 32],
            output_rand: [45; 32],
            genesis_coin: None,
        }),
        request.clone(),
    );
    mint.tail_hash = Some([46; 32]);

    let output = build_network_proof_output_v1(
        &mint,
        NetworkExecutionResultV1 {
            program_hash: [47; 32],
            public_conditions: vec![48],
            execution_cost: 49,
            nullifiers: vec![],
            output_commitments: vec![],
            mint_output_commitment: Some([50; 32]),
        },
    )
    .unwrap();

    assert_eq!(output.context, request.context);
    assert_eq!(
        output.transition,
        NetworkTransitionV1::FaucetMint {
            request_id: [42; 32],
            asset_tail_hash: [46; 32],
            public_amount: 100,
            output_commitment: [50; 32],
        }
    );
}

#[test]
fn private_transfer_output_uses_verified_nullifiers_and_ordered_commitments() {
    let root = [51; 32];
    let spend = input(
        CoinMode::Spend(spend_data(root)),
        NetworkProofRequestV1 {
            context: context(root),
            intent: NetworkProofIntentV1::PrivateTransfer,
        },
    );

    let output = build_network_proof_output_v1(
        &spend,
        NetworkExecutionResultV1 {
            program_hash: [52; 32],
            public_conditions: vec![53],
            execution_cost: 54,
            nullifiers: vec![[55; 32]],
            output_commitments: vec![[56; 32], [57; 32]],
            mint_output_commitment: None,
        },
    )
    .unwrap();

    assert_eq!(
        output.transition,
        NetworkTransitionV1::PrivateTransfer {
            nullifiers: vec![[55; 32]],
            output_commitments: vec![[56; 32], [57; 32]],
        }
    );
}

#[test]
fn mock_faucet_proof_commits_typed_network_output() {
    let tail_source = "(mod () 1)";
    let (_, tail_hash) =
        compile_chialisp_to_bytecode(hash_data, tail_source).expect("TAIL should compile");
    let request = NetworkProofRequestV1 {
        context: context([61; 32]),
        intent: NetworkProofIntentV1::FaucetMint {
            request_id: [62; 32],
        },
    };
    let mut mint = input(
        CoinMode::Mint(MintData {
            tail_source: tail_source.to_string(),
            tail_params: vec![],
            output_puzzle_hash: [63; 32],
            output_amount: 100,
            output_serial: [64; 32],
            output_rand: [65; 32],
            genesis_coin: None,
        }),
        request.clone(),
    );
    mint.chialisp_source = "(mod () ())".to_string();
    mint.tail_hash = Some(tail_hash);

    let backend = MockBackend::new().unwrap();
    assert!(
        backend.prove_with_input(mint.clone()).is_err(),
        "legacy proving API must reject network-mode inputs"
    );
    let result = backend.prove_network_with_input(mint).unwrap();

    assert_eq!(result.proof_output.context, request.context);
    assert!(matches!(
        result.proof_output.transition,
        NetworkTransitionV1::FaucetMint {
            request_id,
            asset_tail_hash,
            public_amount: 100,
            ..
        } if request_id == [62; 32] && asset_tail_hash == tail_hash
    ));
    assert_eq!(
        borsh::from_slice::<NetworkProofOutputV1>(&result.proof_bytes).unwrap(),
        result.proof_output
    );
}

#[test]
fn mock_private_transfer_commits_membership_root_and_private_outputs() {
    let puzzle = "(mod (amount ph serial rand) (list (list 51 ph amount serial rand)))";
    let (_, program_hash) =
        compile_chialisp_to_bytecode(hash_data, puzzle).expect("puzzle should compile");
    let amount = 100;
    let input_serial = [71; 32];
    let input_rand = [72; 32];
    let serial_commitment = compute_serial_commitment(hash_data, &input_serial, &input_rand);
    let coin_commitment = compute_coin_commitment(
        hash_data,
        [0; 32],
        amount,
        &program_hash,
        &serial_commitment,
    );
    let mut tree = SparseMerkleTree::new(20, hash_data);
    let leaf_index = tree.insert(coin_commitment, hash_data);
    let root = tree.root();
    let proof = tree.generate_proof(leaf_index, hash_data).unwrap();
    let output_puzzle_hash = [73; 32];
    let output_serial = [74; 32];
    let output_rand = [75; 32];
    let expected_output = compute_coin_commitment(
        hash_data,
        [0; 32],
        amount,
        &output_puzzle_hash,
        &compute_serial_commitment(hash_data, &output_serial, &output_rand),
    );
    let spend = Input {
        chialisp_source: puzzle.to_string(),
        program_parameters: vec![
            ProgramParameter::Int(amount),
            ProgramParameter::Bytes(output_puzzle_hash.to_vec()),
            ProgramParameter::Bytes(output_serial.to_vec()),
            ProgramParameter::Bytes(output_rand.to_vec()),
        ],
        coin_mode: CoinMode::Spend(SerialCommitmentData {
            serial_number: input_serial,
            serial_randomness: input_rand,
            merkle_path: proof.path,
            coin_commitment,
            serial_commitment,
            merkle_root: root,
            leaf_index: leaf_index as u64,
            program_hash,
            amount,
        }),
        tail_hash: None,
        tail_source: None,
        tail_params: vec![],
        additional_coins: None,
        network: Some(NetworkProofRequestV1 {
            context: context(root),
            intent: NetworkProofIntentV1::PrivateTransfer,
        }),
    };

    let result = MockBackend::new()
        .unwrap()
        .prove_network_with_input(spend)
        .unwrap();

    assert_eq!(result.proof_output.context.ledger_root, root);
    assert!(matches!(
        result.proof_output.transition,
        NetworkTransitionV1::PrivateTransfer {
            ref nullifiers,
            ref output_commitments,
        } if nullifiers.len() == 1 && output_commitments == &vec![expected_output]
    ));
}
