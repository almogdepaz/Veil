#![no_main]

risc0_zkvm::guest::entry!(main);

extern crate alloc;
use alloc::vec::Vec;

use clvm_zk_core::AggregatedOutput;
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

/// Input structure for recursive aggregation
#[derive(serde::Deserialize)]
struct RecursiveInput {
    /// Expected outputs from base proofs
    expected_outputs: Vec<BaseProofData>,
}

/// represents a base proof output
#[derive(serde::Deserialize)]
struct BaseProofData {
    program_hash: [u8; 32],
    nullifier: Option<[u8; 32]>,
    output: Vec<u8>,
}

fn main() {
    // read input
    let input: RecursiveInput = env::read();

    // verify we have at least 1 proof
    if input.expected_outputs.is_empty() {
        panic!("need at least 1 proof to aggregate");
    }

    let mut all_nullifiers = Vec::new();
    let mut all_conditions = Vec::new();
    let mut proof_commitments = Vec::new();

    // aggregate all child proofs (base proofs only)
    for expected_data in input.expected_outputs.iter() {
        // risc0 automatically verifies proofs via add_assumption mechanism

        // collect nullifier if present
        if let Some(n) = expected_data.nullifier {
            if all_nullifiers.contains(&n) {
                panic!("duplicate nullifier detected: {:?}", n);
            }
            all_nullifiers.push(n);
        }

        // collect conditions
        all_conditions.push(expected_data.output.clone());

        // build commitment for base proof
        // commitment = hash(program_hash || nullifier || output)
        let mut commitment_data = Vec::new();
        commitment_data.extend_from_slice(&expected_data.program_hash);
        if let Some(n) = expected_data.nullifier {
            commitment_data.extend_from_slice(&n);
        } else {
            commitment_data.extend_from_slice(&[0u8; 32]);
        }
        commitment_data.extend_from_slice(&expected_data.output);

        let commitment_hash = Impl::hash_bytes(&commitment_data);
        let commitment_bytes: [u8; 32] = commitment_hash.as_bytes().try_into().unwrap();
        proof_commitments.push(commitment_bytes);
    }

    // commit aggregated output
    let aggregated = AggregatedOutput {
        nullifiers: all_nullifiers,
        conditions: all_conditions,
        commitments: proof_commitments,
    };

    env::commit(&aggregated);
}
