use borsh;
use clvm_zk_core::ClvmZkError;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

extern crate alloc;
use alloc::vec::Vec;

use crate::{CLVM_RISC0_GUEST_ID, RECURSIVE_ELF};

/// minimal recursive aggregator for risc0
pub struct RecursiveAggregator {}

impl RecursiveAggregator {
    pub fn new() -> Result<Self, ClvmZkError> {
        Ok(Self {})
    }

    /// aggregate N base proofs into 1 (flat aggregation: N→1)
    ///
    /// all input proofs must be base proofs from prove_chialisp_with_nullifier()
    pub fn aggregate_proofs(&self, proofs: &[&[u8]]) -> Result<Vec<u8>, ClvmZkError> {
        if proofs.is_empty() {
            return Err(ClvmZkError::ConfigurationError(
                "need at least 1 proof to aggregate".to_string(),
            ));
        }

        // deserialize all child receipts and extract journal bytes
        let mut receipts = Vec::new();
        let mut journal_bytes_vec = Vec::new();

        for (i, proof_bytes) in proofs.iter().enumerate() {
            let receipt: Receipt = borsh::from_slice(proof_bytes).map_err(|e| {
                ClvmZkError::InvalidProofFormat(format!("failed to deserialize proof {i}: {e}"))
            })?;

            // extract journal bytes for guest to verify
            journal_bytes_vec.push(receipt.journal.bytes.clone());
            receipts.push(receipt);
        }

        // prepare recursive input with journal bytes and IMAGE_ID
        let recursive_input = RecursiveInputData {
            child_journal_bytes: journal_bytes_vec,
            standard_guest_image_id: image_id_to_bytes(CLVM_RISC0_GUEST_ID),
        };

        // build executor environment with inputs
        // CRITICAL: add_assumption() tells risc0 to make receipts available for env::verify()
        let mut env_builder = ExecutorEnv::builder();

        env_builder.write(&recursive_input).map_err(|e| {
            ClvmZkError::ProofGenerationFailed(format!("failed to write recursive input: {e}"))
        })?;

        // add all receipts as assumptions (mutable builder pattern)
        for receipt in receipts {
            env_builder.add_assumption(receipt);
        }

        let env = env_builder.build().map_err(|e| {
            ClvmZkError::ProofGenerationFailed(format!("failed to build executor env: {e}"))
        })?;

        // generate recursive proof
        let prover = default_prover();
        let receipt = prover.prove(env, RECURSIVE_ELF).map_err(|e| {
            ClvmZkError::ProofGenerationFailed(format!("recursive proving failed: {e}"))
        })?;

        // serialize and return
        let proof_bytes = borsh::to_vec(&receipt.receipt).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize aggregated receipt: {e}"))
        })?;

        Ok(proof_bytes)
    }
}

/// backward compatibility wrapper - aggregate exactly 2 proofs
pub fn aggregate_two(
    aggregator: &RecursiveAggregator,
    proof1: &[u8],
    proof2: &[u8],
) -> Result<Vec<u8>, ClvmZkError> {
    aggregator.aggregate_proofs(&[proof1, proof2])
}

/// input structure for recursive guest
#[derive(serde::Serialize)]
struct RecursiveInputData {
    child_journal_bytes: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    standard_guest_image_id: [u8; 32],
}

/// convert [u32; 8] IMAGE_ID to [u8; 32] for guest verification
fn image_id_to_bytes(id: [u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, word) in id.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Risc0Backend, RECURSIVE_ID};
    use clvm_zk_core::coin_commitment::{CoinCommitment, CoinSecrets};
    use clvm_zk_core::merkle::SparseMerkleTree;
    use clvm_zk_core::{Input, ProgramParameter, SerialCommitmentData};
    use sha2::{Digest, Sha256};

    fn hash_data(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn create_test_proof_simple(
        backend: &Risc0Backend,
        program: &str,
        params: &[ProgramParameter],
        serial_number: [u8; 32],
    ) -> clvm_zk_core::ZKClvmResult {
        // compile to get program hash
        let program_hash = clvm_zk_core::compile_chialisp_template_hash(hash_data, program)
            .expect("program should compile");

        // create coin secrets
        let serial_randomness = [42u8; 32];
        let secrets = CoinSecrets::new(serial_number, serial_randomness);

        // compute commitments
        let amount = 100;
        let serial_commitment = secrets.serial_commitment(hash_data);
        let coin_commitment =
            CoinCommitment::compute(amount, &program_hash, &serial_commitment, hash_data);

        // create merkle tree
        let mut merkle_tree = SparseMerkleTree::new(20, hash_data);
        let leaf_index = merkle_tree.insert(*coin_commitment.as_bytes(), hash_data);
        let merkle_root = merkle_tree.root();
        let merkle_proof = merkle_tree.generate_proof(leaf_index, hash_data).unwrap();

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
        };

        backend
            .prove_with_input(input)
            .expect("proof should succeed")
    }

    #[test]
    fn test_aggregate_two_proofs() {
        // generate 2 transaction proofs with nullifiers
        let backend = Risc0Backend::new().unwrap();

        let proof1 = create_test_proof_simple(
            &backend,
            "(mod (x) (* x 2))",
            &[ProgramParameter::Int(5)],
            [1u8; 32],
        );

        let proof2 = create_test_proof_simple(
            &backend,
            "(mod (y) (+ y 10))",
            &[ProgramParameter::Int(3)],
            [2u8; 32],
        );

        // aggregate them
        let aggregator = RecursiveAggregator::new().unwrap();
        let aggregated = aggregator
            .aggregate_proofs(&[&proof1.proof_bytes, &proof2.proof_bytes])
            .unwrap();

        // verify aggregated proof is not empty
        assert!(!aggregated.is_empty());

        // verify we can deserialize it
        let receipt: risc0_zkvm::Receipt = borsh::from_slice(&aggregated).unwrap();

        // verify the aggregated proof with recursive guest ID
        receipt.verify(RECURSIVE_ID).unwrap();

        // decode and verify aggregated output contains merkle root
        use clvm_zk_core::AggregatedOutput;
        let aggregated_output: AggregatedOutput = receipt.journal.decode().unwrap();

        assert_eq!(aggregated_output.nullifiers.len(), 2);
        assert_eq!(aggregated_output.conditions.len(), 2);
        assert_eq!(
            aggregated_output.commitments.len(),
            2,
            "should have 2 commitments"
        );

        println!("✓ aggregated 2 proofs successfully");
        println!("  - nullifiers: {}", aggregated_output.nullifiers.len());
        println!("  - conditions: {}", aggregated_output.conditions.len());
        println!("  - commitments: {}", aggregated_output.commitments.len());
    }

    #[test]
    fn test_aggregate_five_proofs() {
        // generate 5 transaction proofs with nullifiers
        let backend = Risc0Backend::new().unwrap();

        let mut proofs = Vec::new();
        for i in 0..5 {
            let serial_number = [i as u8; 32];
            let proof = create_test_proof_simple(
                &backend,
                "(mod (x) (* x 2))",
                &[ProgramParameter::Int(i as u64)],
                serial_number,
            );
            proofs.push(proof);
        }

        // aggregate all 5
        let aggregator = RecursiveAggregator::new().unwrap();
        let proof_refs: Vec<&[u8]> = proofs.iter().map(|p| p.proof_bytes.as_slice()).collect();
        let aggregated = aggregator.aggregate_proofs(&proof_refs).unwrap();

        // verify
        let receipt: risc0_zkvm::Receipt = borsh::from_slice(&aggregated).unwrap();
        receipt.verify(RECURSIVE_ID).unwrap();

        use clvm_zk_core::AggregatedOutput;
        let aggregated_output: AggregatedOutput = receipt.journal.decode().unwrap();

        assert_eq!(aggregated_output.nullifiers.len(), 5);
        assert_eq!(aggregated_output.conditions.len(), 5);
        assert_eq!(
            aggregated_output.commitments.len(),
            5,
            "should have 5 commitments"
        );

        println!("✓ aggregated 5 proofs successfully");
        println!("  - nullifiers: {}", aggregated_output.nullifiers.len());
        println!("  - conditions: {}", aggregated_output.conditions.len());
        println!("  - commitments: {}", aggregated_output.commitments.len());
    }
}
