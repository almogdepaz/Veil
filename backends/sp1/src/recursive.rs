use bincode;
use clvm_zk_core::{ClvmZkError, ProofOutput};
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1Stdin};

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
    /// all input proofs must be base proofs from prove_with_input()
    pub fn aggregate_proofs(&self, proofs: &[&[u8]]) -> Result<Vec<u8>, ClvmZkError> {
        if proofs.is_empty() {
            return Err(ClvmZkError::ConfigurationError(
                "need at least 1 proof to aggregate".to_string(),
            ));
        }

        // deserialize all child proofs (all must be base proofs)
        let mut child_data = Vec::new();

        for (i, proof_bytes) in proofs.iter().enumerate() {
            let proof: SP1ProofWithPublicValues =
                bincode::deserialize(proof_bytes).map_err(|e| {
                    ClvmZkError::InvalidProofFormat(format!("failed to deserialize proof {i}: {e}"))
                })?;

            // decode as ProofOutput (base proof only)
            let output: ProofOutput =
                bincode::deserialize(&proof.public_values.to_vec()).map_err(|e| {
                    ClvmZkError::InvalidProofFormat(format!(
                        "failed to decode base proof public values {i}: {e}"
                    ))
                })?;

            child_data.push(BaseProofData {
                program_hash: output.program_hash,
                nullifiers: output.nullifiers.clone(),
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

        let proof = client.prove(&pk, &stdin).run().map_err(|e| {
            ClvmZkError::ProofGenerationFailed(format!("recursive proving failed: {e}"))
        })?;

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
    nullifiers: alloc::vec::Vec<[u8; 32]>,
    output: alloc::vec::Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sp1Backend;
    use clvm_zk_core::coin_commitment::{CoinCommitment, CoinSecrets, XCH_TAIL};
    use clvm_zk_core::merkle::SparseMerkleTree;
    use clvm_zk_core::{
        hash_data, AggregatedOutput, Input, ProgramParameter, SerialCommitmentData, ZKClvmResult,
    };

    fn compile_program_hash(program: &str) -> [u8; 32] {
        clvm_zk_core::compile_chialisp_template_hash(hash_data, program)
            .expect("program compilation failed")
    }

    /// helper to generate a proof with proper nullifier protocol
    fn generate_test_proof(
        backend: &Sp1Backend,
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
            additional_coins: None,
        };

        backend
            .prove_with_input(input)
            .expect("proof generation should succeed")
    }

    #[test]
    fn test_aggregate_two_proofs() {
        // generate 2 transaction proofs with nullifiers
        let backend = Sp1Backend::new().unwrap();

        let proof1 = generate_test_proof(
            &backend,
            "(mod (x) (* x 2))",
            &[ProgramParameter::Int(5)],
            1,
        );

        let proof2 = generate_test_proof(
            &backend,
            "(mod (y) (+ y 10))",
            &[ProgramParameter::Int(3)],
            2,
        );

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
        let aggregated_output: AggregatedOutput =
            bincode::deserialize(&proof.public_values.to_vec()).unwrap();

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
        let backend = Sp1Backend::new().unwrap();

        let mut proofs = Vec::new();
        for i in 0..5 {
            let proof = generate_test_proof(
                &backend,
                "(mod (x) (* x 2))",
                &[ProgramParameter::Int(i as u64)],
                i as u8,
            );
            proofs.push(proof);
        }

        // aggregate all 5
        let aggregator = RecursiveAggregator::new().unwrap();
        let proof_refs: Vec<&[u8]> = proofs.iter().map(|p| p.proof_bytes.as_slice()).collect();
        let aggregated = aggregator.aggregate_proofs(&proof_refs).unwrap();

        // verify
        let proof: SP1ProofWithPublicValues = bincode::deserialize(&aggregated).unwrap();
        let aggregated_output: AggregatedOutput =
            bincode::deserialize(&proof.public_values.to_vec()).unwrap();

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
