use borsh;
use clvm_zk_core::{ClvmZkError, ProofOutput};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

extern crate alloc;
use alloc::vec::Vec;

use crate::RECURSIVE_ELF;

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

        // deserialize all child receipts (all must be base proofs)
        let mut receipts = Vec::new();
        let mut child_data = Vec::new();

        for (i, proof_bytes) in proofs.iter().enumerate() {
            let receipt: Receipt = borsh::from_slice(proof_bytes).map_err(|e| {
                ClvmZkError::InvalidProofFormat(format!("failed to deserialize proof {i}: {e}"))
            })?;

            // decode as ProofOutput (base proof only)
            let output: ProofOutput = receipt.journal.decode().map_err(|e| {
                ClvmZkError::InvalidProofFormat(format!(
                    "failed to decode base proof journal {i}: {e}"
                ))
            })?;

            child_data.push(BaseProofData {
                program_hash: output.program_hash,
                nullifier: output.nullifier,
                output: output.clvm_res.output,
            });

            receipts.push(receipt);
        }

        // prepare recursive input
        let recursive_input = RecursiveInputData {
            expected_outputs: child_data,
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
    expected_outputs: alloc::vec::Vec<BaseProofData>,
}

/// represents a base proof output
#[derive(serde::Serialize)]
struct BaseProofData {
    program_hash: [u8; 32],
    nullifier: Option<[u8; 32]>,
    output: alloc::vec::Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Risc0Backend;
    use clvm_zk_core::{AggregatedOutput, ProgramParameter};

    #[test]
    fn test_aggregate_two_proofs() {
        // generate 2 transaction proofs with nullifiers
        let backend = Risc0Backend::new().unwrap();

        let spend_secret1 = [1u8; 32];
        let spend_secret2 = [2u8; 32];

        let proof1 = backend
            .prove_chialisp_with_nullifier(
                "(mod (x) (* x 2))",
                &[ProgramParameter::Int(5)],
                spend_secret1,
            )
            .unwrap();

        let proof2 = backend
            .prove_chialisp_with_nullifier(
                "(mod (y) (+ y 10))",
                &[ProgramParameter::Int(3)],
                spend_secret2,
            )
            .unwrap();

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
            let spend_secret = [i as u8; 32];
            let proof = backend
                .prove_chialisp_with_nullifier(
                    "(mod (x) (* x 2))",
                    &[ProgramParameter::Int(i as u64)],
                    spend_secret,
                )
                .unwrap();
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
