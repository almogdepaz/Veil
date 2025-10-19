use bincode;
use clvm_zk_core::{ClvmZkError, ProofOutput};
use sp1_sdk::{ProverClient, SP1Stdin, SP1ProofWithPublicValues};

extern crate alloc;
use alloc::vec::Vec;

use crate::RECURSIVE_SP1_ELF;

/// minimal recursive aggregator for sp1
pub struct RecursiveAggregator {}

impl RecursiveAggregator {
    pub fn new() -> Result<Self, ClvmZkError> {
        Ok(Self {})
    }

    /// aggregate N base proofs into 1 (flat aggregation: N→1)
    ///
    /// all input proofs must be base proofs from prove_chialisp_with_nullifier()
    pub fn aggregate_proofs(
        &self,
        proofs: &[&[u8]],
    ) -> Result<Vec<u8>, ClvmZkError> {
        if proofs.is_empty() {
            return Err(ClvmZkError::ConfigurationError(
                "need at least 1 proof to aggregate".to_string()
            ));
        }

        // deserialize all child proofs (all must be base proofs)
        let mut child_data = Vec::new();

        for (i, proof_bytes) in proofs.iter().enumerate() {
            let proof: SP1ProofWithPublicValues = bincode::deserialize(proof_bytes).map_err(|e| {
                ClvmZkError::InvalidProofFormat(format!("failed to deserialize proof {i}: {e}"))
            })?;

            // decode as ProofOutput (base proof only)
            let output: ProofOutput = bincode::deserialize(&proof.public_values.to_vec()).map_err(|e| {
                ClvmZkError::InvalidProofFormat(format!("failed to decode base proof public values {i}: {e}"))
            })?;

            child_data.push(BaseProofData {
                program_hash: output.program_hash,
                nullifier: output.nullifier,
                output: output.clvm_res.output,
            });
        }

        // prepare recursive input
        let recursive_input = RecursiveInputData {
            expected_outputs: child_data,
        };

        // build stdin
        let mut stdin = SP1Stdin::new();
        stdin.write(&recursive_input);

        // generate recursive proof using sp1 5.2.2 API
        let client = ProverClient::from_env();
        let (pk, _vk) = client.setup(RECURSIVE_SP1_ELF);

        let proof = client
            .prove(&pk, &stdin)
            .run()
            .map_err(|e| ClvmZkError::ProofGenerationFailed(format!("recursive proving failed: {e}")))?;

        // serialize and return
        let proof_bytes = bincode::serialize(&proof).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize aggregated proof: {e}"))
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
#[derive(serde::Serialize, serde::Deserialize)]
struct RecursiveInputData {
    expected_outputs: alloc::vec::Vec<BaseProofData>,
}

/// represents a base proof output
#[derive(serde::Serialize, serde::Deserialize)]
struct BaseProofData {
    program_hash: [u8; 32],
    nullifier: Option<[u8; 32]>,
    output: alloc::vec::Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sp1Backend;
    use clvm_zk_core::ProgramParameter;

    #[test]
    fn test_aggregate_two_proofs() {
        // generate 2 transaction proofs with nullifiers
        let backend = Sp1Backend::new().unwrap();

        let spend_secret1 = [1u8; 32];
        let spend_secret2 = [2u8; 32];

        let proof1 = backend
            .prove_chialisp_with_nullifier(
                "(mod (x) (* x 2))",
                &[ProgramParameter::Int(5)],
                spend_secret1
            )
            .unwrap();

        let proof2 = backend
            .prove_chialisp_with_nullifier(
                "(mod (y) (+ y 10))",
                &[ProgramParameter::Int(3)],
                spend_secret2
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
        let proof: SP1ProofWithPublicValues = bincode::deserialize(&aggregated).unwrap();

        // decode and verify aggregated output
        let aggregated_output: AggregatedOutput = bincode::deserialize(&proof.public_values.to_vec()).unwrap();

        assert_eq!(aggregated_output.nullifiers.len(), 2);
        assert_eq!(aggregated_output.conditions.len(), 2);
        assert_eq!(aggregated_output.commitments.len(), 2, "should have 2 commitments");

        println!("✓ aggregated 2 proofs successfully");
        println!("  - nullifiers: {}", aggregated_output.nullifiers.len());
        println!("  - conditions: {}", aggregated_output.conditions.len());
        println!("  - commitments: {}", aggregated_output.commitments.len());
    }

    #[test]
    fn test_aggregate_five_proofs() {
        // generate 5 transaction proofs with nullifiers
        let backend = Sp1Backend::new().unwrap();

        let mut proofs = Vec::new();
        for i in 0..5 {
            let spend_secret = [i as u8; 32];
            let proof = backend
                .prove_chialisp_with_nullifier(
                    "(mod (x) (* x 2))",
                    &[ProgramParameter::Int(i as u64)],
                    spend_secret
                )
                .unwrap();
            proofs.push(proof);
        }

        // aggregate all 5
        let aggregator = RecursiveAggregator::new().unwrap();
        let proof_refs: Vec<&[u8]> = proofs.iter().map(|p| p.proof_bytes.as_slice()).collect();
        let aggregated = aggregator.aggregate_proofs(&proof_refs).unwrap();

        // verify
        let proof: SP1ProofWithPublicValues = bincode::deserialize(&aggregated).unwrap();
        let aggregated_output: AggregatedOutput = bincode::deserialize(&proof.public_values.to_vec()).unwrap();

        assert_eq!(aggregated_output.nullifiers.len(), 5);
        assert_eq!(aggregated_output.conditions.len(), 5);
        assert_eq!(aggregated_output.commitments.len(), 5, "should have 5 commitments");

        println!("✓ aggregated 5 proofs successfully");
        println!("  - nullifiers: {}", aggregated_output.nullifiers.len());
        println!("  - conditions: {}", aggregated_output.conditions.len());
        println!("  - commitments: {}", aggregated_output.commitments.len());
    }

}
