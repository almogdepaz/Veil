#![cfg(feature = "risc0")]

use clvm_zk_core::coin_commitment::{CoinCommitment, CoinSecrets, XCH_TAIL};
use clvm_zk_core::merkle::SparseMerkleTree;
use clvm_zk_core::{Input, ProgramParameter, SerialCommitmentData, ZKClvmResult};
use clvm_zk_risc0::{RecursiveAggregator, Risc0Backend};
use sha2::{Digest, Sha256};

// test helpers

fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn compile_program_hash(program: &str) -> [u8; 32] {
    clvm_zk_core::compile_chialisp_template_hash(hash_data, program)
        .expect("program compilation failed")
}

/// helper to generate a proof with proper nullifier protocol
fn generate_test_proof(
    backend: &Risc0Backend,
    program: &str,
    params: &[ProgramParameter],
    serial_seed: u8,
) -> ZKClvmResult {
    let program_hash = compile_program_hash(program);

    // create coin with serial commitment
    let serial_number = [serial_seed; 32];
    let serial_randomness = [serial_seed.wrapping_add(100); 32];
    let coin_secrets = CoinSecrets::new(serial_number, serial_randomness);
    let amount = 1000;

    // compute commitments
    let serial_commitment = coin_secrets.serial_commitment(hash_data);
    let coin_commitment = CoinCommitment::compute(
        &XCH_TAIL,
        amount,
        &program_hash,
        &serial_commitment,
        hash_data,
    );

    // create merkle tree with single coin
    let mut merkle_tree = SparseMerkleTree::new(20, hash_data);
    let leaf_index = merkle_tree.insert(*coin_commitment.as_bytes(), hash_data);
    let merkle_root = merkle_tree.root();
    let merkle_proof = merkle_tree.generate_proof(leaf_index, hash_data).unwrap();

    // generate proof with serial commitment
    let input = Input {
        chialisp_source: program.to_string(),
        program_parameters: params.to_vec(),
        serial_commitment_data: Some(SerialCommitmentData {
            serial_number,
            serial_randomness,
            merkle_path: merkle_proof.path,
            coin_commitment: *coin_commitment.as_bytes(),
            serial_commitment: *serial_commitment.as_bytes(),
            merkle_root,
            leaf_index,
            program_hash,
            amount,
        }),
        tail_hash: None, // XCH by default
    };

    backend
        .prove_with_input(input)
        .expect("proof generation should succeed")
}

#[test]
fn test_minimal_aggregation_2_to_1() {
    println!("testing minimal 2→1 aggregation...");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");
    let aggregator = RecursiveAggregator::new().expect("aggregator should initialize");

    // generate 2 base proofs
    let mut proofs = Vec::new();
    for i in 0..2 {
        let proof = generate_test_proof(
            &backend,
            "(mod (x) (* x 2))",
            &[ProgramParameter::Int(i as u64)],
            i as u8,
        );
        proofs.push(proof);
    }

    let proof_refs: Vec<&[u8]> = proofs.iter().map(|p| p.proof_bytes.as_slice()).collect();

    // aggregate
    let aggregated = aggregator
        .aggregate_proofs(&proof_refs)
        .expect("aggregation should succeed");

    // verify aggregated proof is not empty
    assert!(!aggregated.is_empty());

    println!("✓ 2→1 aggregation works");
    println!("  aggregated proof: {} bytes", aggregated.len());
}

#[test]
fn test_aggregate_five_proofs() {
    println!("testing 5→1 aggregation...");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");
    let aggregator = RecursiveAggregator::new().expect("aggregator should initialize");

    // generate 5 base proofs
    let mut proofs = Vec::new();
    for i in 0..5 {
        let proof = generate_test_proof(
            &backend,
            "(mod (x) (+ x 1))",
            &[ProgramParameter::Int(i as u64)],
            i as u8,
        );
        proofs.push(proof);
    }

    let proof_refs: Vec<&[u8]> = proofs.iter().map(|p| p.proof_bytes.as_slice()).collect();

    // aggregate
    let aggregated = aggregator
        .aggregate_proofs(&proof_refs)
        .expect("aggregation should succeed");

    // verify aggregated proof is not empty
    assert!(!aggregated.is_empty());

    println!("✓ 5→1 aggregation works");
    println!("  aggregated proof: {} bytes", aggregated.len());
}

#[test]
fn test_single_proof_handling() {
    println!("testing single proof edge case...");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");
    let aggregator = RecursiveAggregator::new().expect("aggregator should initialize");

    // generate 1 proof
    let proof = generate_test_proof(
        &backend,
        "(mod (x) (* x 3))",
        &[ProgramParameter::Int(5)],
        42,
    );

    let proof_refs = vec![proof.proof_bytes.as_slice()];

    // aggregate single proof
    let result = aggregator.aggregate_proofs(&proof_refs);

    // should handle gracefully (either wrap it or return it as-is)
    assert!(result.is_ok(), "single proof aggregation should succeed");

    println!("✓ single proof handled correctly");
}

#[test]
fn test_empty_batch_rejected() {
    println!("testing empty batch is rejected...");

    let aggregator = RecursiveAggregator::new().expect("aggregator should initialize");

    let empty_proofs: Vec<&[u8]> = vec![];

    // should reject empty batch
    let result = aggregator.aggregate_proofs(&empty_proofs);

    assert!(result.is_err(), "empty batch should be rejected");

    println!("✓ empty batch rejected");
}
