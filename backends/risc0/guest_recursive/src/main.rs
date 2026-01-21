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
    /// Journal bytes from child proofs for verification
    child_journal_bytes: Vec<Vec<u8>>,
    /// IMAGE_ID of the standard guest (passed from host to avoid hardcoding)
    standard_guest_image_id: [u8; 32],
}

fn main() {
    // read input
    let input: RecursiveInput = env::read();

    // verify we have at least 1 proof
    if input.child_journal_bytes.is_empty() {
        panic!("need at least 1 proof to aggregate");
    }

    // Use IMAGE_ID from input (passed by host, stays in sync with compiled guest)
    let standard_guest_image_id = input.standard_guest_image_id;

    let mut all_nullifiers = Vec::new();
    let mut all_conditions = Vec::new();
    let mut proof_commitments = Vec::new();

    // verify and aggregate all child proofs
    for (i, journal_bytes) in input.child_journal_bytes.iter().enumerate() {
        // VERIFY the child proof using risc0 composition pattern
        risc0_zkvm::guest::env::verify(standard_guest_image_id, journal_bytes)
            .expect(&alloc::format!("child proof {} verification failed", i));

        // deserialize journal to extract ProofOutput (uses same bincode format as env::commit)
        let proof_output: clvm_zk_core::ProofOutput = risc0_zkvm::serde::from_slice(journal_bytes)
            .expect(&alloc::format!("failed to deserialize journal {}", i));

        // collect nullifiers
        for nullifier in &proof_output.nullifiers {
            if all_nullifiers.contains(nullifier) {
                panic!("duplicate nullifier detected: {:?}", nullifier);
            }
            all_nullifiers.push(*nullifier);
        }

        // collect conditions
        all_conditions.push(proof_output.clvm_res.output.clone());

        // build commitment for base proof
        // commitment = hash(program_hash || [nullifiers...] || output)
        let mut commitment_data = Vec::new();
        commitment_data.extend_from_slice(&proof_output.program_hash);
        for nullifier in &proof_output.nullifiers {
            commitment_data.extend_from_slice(nullifier);
        }
        commitment_data.extend_from_slice(&proof_output.clvm_res.output);

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
