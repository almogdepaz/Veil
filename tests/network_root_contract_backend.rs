#![cfg(any(feature = "sp1", feature = "risc0"))]

use clvm_zk::crypto_utils::hash_data_default;
use clvm_zk_core::merkle::SparseMerkleTree;
use clvm_zk_core::{
    compile_chialisp_to_bytecode, compute_coin_commitment, compute_serial_commitment, CoinMode,
    Input, MintData, NetworkContextV1, NetworkProofIntentV1, NetworkProofRequestV1,
    NetworkTransitionV1, ProgramParameter, SerialCommitmentData, ZKNetworkResultV1,
    NETWORK_PROTOCOL_V1,
};

fn prove_network(input: Input) -> ZKNetworkResultV1 {
    #[cfg(feature = "sp1")]
    {
        return clvm_zk_sp1::Sp1Backend::new()
            .unwrap()
            .prove_network_with_input(input)
            .unwrap();
    }

    #[cfg(all(feature = "risc0", not(feature = "sp1")))]
    {
        return clvm_zk_risc0::Risc0Backend::new()
            .unwrap()
            .prove_network_with_input(input)
            .unwrap();
    }
}

fn hex32(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn network_program_id() -> [u8; 32] {
    #[cfg(feature = "sp1")]
    {
        return clvm_zk_sp1::Sp1Backend::network_program_id();
    }

    #[cfg(all(feature = "risc0", not(feature = "sp1")))]
    {
        return clvm_zk_risc0::Risc0Backend::network_program_id();
    }
}

fn verify_network(proof: &[u8]) -> clvm_zk_core::NetworkProofOutputV1 {
    #[cfg(feature = "sp1")]
    {
        return clvm_zk_sp1::Sp1Backend::new()
            .unwrap()
            .verify_network_proof_and_decode(proof, usize::MAX)
            .unwrap();
    }

    #[cfg(all(feature = "risc0", not(feature = "sp1")))]
    {
        return clvm_zk_risc0::Risc0Backend::new()
            .unwrap()
            .verify_network_proof_and_decode(proof, usize::MAX)
            .unwrap();
    }
}

#[test]
fn backend_rejects_oversized_proof_before_decode() {
    #[cfg(feature = "sp1")]
    let result = clvm_zk_sp1::Sp1Backend::new()
        .unwrap()
        .verify_network_proof_and_decode(&[0xff], 0);

    #[cfg(all(feature = "risc0", not(feature = "sp1")))]
    let result = clvm_zk_risc0::Risc0Backend::new()
        .unwrap()
        .verify_network_proof_and_decode(&[0xff], 0);

    assert!(matches!(
        result,
        Err(clvm_zk_core::ClvmZkError::InvalidInput(_))
    ));
}

#[test]
fn backend_program_id_is_nonzero() {
    let program_id = network_program_id();
    assert_ne!(program_id, [0; 32]);
    println!("network program id: {}", hex32(&program_id));
}

#[test]
fn real_backend_faucet_proof_commits_typed_network_output() {
    let tail_source = "(mod () 1)";
    let (_, tail_hash) = compile_chialisp_to_bytecode(hash_data_default, tail_source).unwrap();
    let input = Input {
        chialisp_source: "(mod () ())".to_string(),
        program_parameters: vec![],
        coin_mode: CoinMode::Mint(MintData {
            tail_source: tail_source.to_string(),
            tail_params: vec![],
            output_puzzle_hash: [1; 32],
            output_amount: 100,
            output_serial: [2; 32],
            output_rand: [3; 32],
            genesis_coin: None,
        }),
        tail_hash: Some(tail_hash),
        tail_source: None,
        tail_params: vec![],
        additional_coins: None,
        network: Some(NetworkProofRequestV1 {
            context: NetworkContextV1 {
                network_id: [4; 32],
                protocol_version: NETWORK_PROTOCOL_V1,
                ledger_root: [5; 32],
                anchor_height: 6,
                expiry_height: 7,
                metadata_hash: [8; 32],
            },
            intent: NetworkProofIntentV1::FaucetMint {
                request_id: [9; 32],
            },
        }),
    };

    let result = prove_network(input);

    assert_ne!(network_program_id(), [0; 32]);
    assert!(matches!(
        result.proof_output.transition,
        NetworkTransitionV1::FaucetMint {
            request_id,
            asset_tail_hash,
            public_amount: 100,
            ..
        } if request_id == [9; 32] && asset_tail_hash == tail_hash
    ));
    assert_eq!(
        verify_network(&result.proof_bytes),
        result.proof_output,
        "verified journal must equal the output returned after proving"
    );
}

#[test]
fn real_backend_private_transfer_commits_canonical_root_and_outputs() {
    let puzzle = "(mod (amount ph serial rand) (list (list 51 ph amount serial rand)))";
    let (_, program_hash) = compile_chialisp_to_bytecode(hash_data_default, puzzle).unwrap();
    let amount = 100;
    let input_serial = [21; 32];
    let input_rand = [22; 32];
    let serial_commitment =
        compute_serial_commitment(hash_data_default, &input_serial, &input_rand);
    let coin_commitment = compute_coin_commitment(
        hash_data_default,
        [0; 32],
        amount,
        &program_hash,
        &serial_commitment,
    );
    let mut tree = SparseMerkleTree::new(20, hash_data_default);
    let leaf_index = tree.insert(coin_commitment, hash_data_default);
    let root = tree.root();
    let proof = tree.generate_proof(leaf_index, hash_data_default).unwrap();
    let output_puzzle_hash = [23; 32];
    let output_serial = [24; 32];
    let output_rand = [25; 32];
    let expected_output = compute_coin_commitment(
        hash_data_default,
        [0; 32],
        amount,
        &output_puzzle_hash,
        &compute_serial_commitment(hash_data_default, &output_serial, &output_rand),
    );
    let input = Input {
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
            context: NetworkContextV1 {
                network_id: [26; 32],
                protocol_version: NETWORK_PROTOCOL_V1,
                ledger_root: root,
                anchor_height: 27,
                expiry_height: 28,
                metadata_hash: [29; 32],
            },
            intent: NetworkProofIntentV1::PrivateTransfer,
        }),
    };

    let result = prove_network(input);

    assert_eq!(result.proof_output.context.ledger_root, root);
    assert!(matches!(
        result.proof_output.transition,
        NetworkTransitionV1::PrivateTransfer {
            ref nullifiers,
            ref output_commitments,
        } if nullifiers.len() == 1 && output_commitments == &vec![expected_output]
    ));
    assert_eq!(verify_network(&result.proof_bytes), result.proof_output);
    if let NetworkTransitionV1::PrivateTransfer {
        nullifiers,
        output_commitments,
    } = &result.proof_output.transition
    {
        println!(
            "network={} kind=private_transfer root={} anchor={} expiry={} nullifiers={} outputs={}",
            hex32(&result.proof_output.context.network_id),
            hex32(&result.proof_output.context.ledger_root),
            result.proof_output.context.anchor_height,
            result.proof_output.context.expiry_height,
            nullifiers.len(),
            output_commitments.len(),
        );
    }
}
