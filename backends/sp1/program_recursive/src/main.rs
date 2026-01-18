#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;
use alloc::vec::Vec;

use clvm_zk_core::AggregatedOutput;

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
    nullifiers: Vec<[u8; 32]>,
    output: Vec<u8>,
}

pub fn main() {
    // read input
    let input: RecursiveInput = sp1_zkvm::io::read();

    // verify we have at least 1 proof
    assert!(
        !input.expected_outputs.is_empty(),
        "need at least 1 proof to aggregate"
    );

    // NOTE: SP1 verifies child proofs automatically when passed as input

    let mut all_nullifiers = Vec::new();
    let mut all_conditions = Vec::new();
    let mut proof_commitments = Vec::new();

    // aggregate all child proofs (base proofs only)
    for expected_data in input.expected_outputs.iter() {
        // collect nullifiers
        for nullifier in &expected_data.nullifiers {
            assert!(!all_nullifiers.contains(nullifier), "duplicate nullifier detected");
            all_nullifiers.push(*nullifier);
        }

        // collect conditions
        all_conditions.push(expected_data.output.clone());

        // build commitment for base proof
        // commitment = hash(program_hash || [nullifiers...] || output)
        let mut commitment_data = Vec::new();
        commitment_data.extend_from_slice(&expected_data.program_hash);
        for nullifier in &expected_data.nullifiers {
            commitment_data.extend_from_slice(nullifier);
        }
        // pad if no nullifiers (for backward compatibility)
        if expected_data.nullifiers.is_empty() {
            commitment_data.extend_from_slice(&[0u8; 32]);
        }
        commitment_data.extend_from_slice(&expected_data.output);

        // hash using sha2 crate
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&commitment_data);
        let commitment_hash: [u8; 32] = hasher.finalize().into();
        proof_commitments.push(commitment_hash);
    }

    // commit aggregated output
    let aggregated = AggregatedOutput {
        nullifiers: all_nullifiers,
        conditions: all_conditions,
        commitments: proof_commitments,
    };

    sp1_zkvm::io::commit(&aggregated);
}
