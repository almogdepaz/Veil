use clvm_zk_core::verify_ecdsa_signature_with_hasher;
use clvm_zk_core::{
    compile_chialisp_to_bytecode_with_table, ClvmEvaluator, ClvmResult, ClvmZkError,
    ProgramParameter, ProofOutput, ZKClvmResult, BLS_DST,
};
use sha2::{Digest, Sha256};

use blst::min_sig as blst_core;
use blst::BLST_ERROR;

pub struct MockBackend;

impl MockBackend {}

pub fn default_bls_verifier(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    // using min_sig variant: pk in G2 (96 bytes), sig in G1 (48 bytes)
    let pk = blst_core::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| "invalid public key bytes")?;

    let sig =
        blst_core::Signature::from_bytes(signature_bytes).map_err(|_| "invalid signature bytes")?;

    let res: BLST_ERROR = sig.verify(true, message_bytes, BLS_DST, &[], &pk, true);

    Ok(res == BLST_ERROR::BLST_SUCCESS)
}

pub fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn ecdsa_verifier(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    verify_ecdsa_signature_with_hasher(hash_data, public_key_bytes, message_bytes, signature_bytes)
}

pub use ecdsa_verifier as default_ecdsa_verifier;

impl MockBackend {
    pub fn new() -> Result<Self, ClvmZkError> {
        Ok(Self)
    }

    pub fn prove_chialisp_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        let (instance_bytecode, program_hash, function_table) =
            compile_chialisp_to_bytecode_with_table(hash_data, chialisp_source, program_parameters)
                .map_err(|e| {
                    ClvmZkError::ProofGenerationFailed(format!(
                        "chialisp compilation failed: {:?}",
                        e
                    ))
                })?;

        let mut evaluator = ClvmEvaluator::new(hash_data, default_bls_verifier, ecdsa_verifier);
        evaluator.function_table = function_table;

        let (output_bytes, _conditions) = evaluator
            .evaluate_clvm_program(&instance_bytecode)
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("clvm execution failed: {:?}", e))
            })?;

        let clvm_output = ClvmResult {
            output: output_bytes,
            cost: 0,
        };

        let proof_output = ProofOutput {
            program_hash,
            nullifier: None,
            clvm_res: clvm_output.clone(),
        };

        let proof_bytes = borsh::to_vec(&proof_output).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize mock proof: {e}"))
        })?;

        Ok(ZKClvmResult {
            proof_output,
            proof_bytes,
        })
    }

    pub fn verify_mock_proof(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        expected_result: &[u8],
    ) -> Result<bool, ClvmZkError> {
        let result = self.prove_chialisp_program(chialisp_source, program_parameters)?;
        Ok(result.proof_output.clvm_res.output == expected_result)
    }

    pub fn prove_with_input(
        &self,
        inputs: clvm_zk_core::InputWithSerial,
    ) -> Result<ZKClvmResult, ClvmZkError> {
        let (instance_bytecode, program_hash, function_table) =
            compile_chialisp_to_bytecode_with_table(
                hash_data,
                &inputs.chialisp_source,
                &inputs.program_parameters,
            )
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("chialisp compilation failed: {:?}", e))
            })?;

        let mut evaluator = ClvmEvaluator::new(hash_data, default_bls_verifier, ecdsa_verifier);
        evaluator.function_table = function_table;

        let (output_bytes, _conditions) = evaluator
            .evaluate_clvm_program(&instance_bytecode)
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("clvm execution failed: {:?}", e))
            })?;

        let clvm_output = ClvmResult {
            output: output_bytes,
            cost: 0,
        };

        // Serial commitment protocol for spending
        let serial_randomness = inputs.serial_randomness;
        let serial_number = inputs.serial_number;
        let puzzle_hash = inputs.program_hash;
        // 1. Verify program_hash matches puzzle_hash
        if program_hash != puzzle_hash {
            return Err(ClvmZkError::ProofGenerationFailed(
                "program_hash mismatch: cannot spend coin with different puzzle".to_string(),
            ));
        }

        // 2. Verify serial commitment
        let domain = b"clvm_zk_serial_v1.0";
        let mut commitment_data = Vec::with_capacity(19 + 64);
        commitment_data.extend_from_slice(domain);
        commitment_data.extend_from_slice(&serial_number);
        commitment_data.extend_from_slice(&serial_randomness);
        let computed_serial_commitment = hash_data(&commitment_data);

        let serial_commitment_expected = inputs.serial_commitment;
        if computed_serial_commitment != serial_commitment_expected {
            return Err(ClvmZkError::ProofGenerationFailed(
                "serial commitment verification failed".to_string(),
            ));
        }

        // 3. Reconstruct and verify coin_commitment = hash(domain || puzzle_hash || serial_commitment)
        let coin_domain = b"clvm_zk_coin_v1.0";
        let mut coin_data = Vec::with_capacity(17 + 64);
        coin_data.extend_from_slice(coin_domain);
        coin_data.extend_from_slice(&puzzle_hash);
        coin_data.extend_from_slice(&computed_serial_commitment);
        let computed_coin_commitment = hash_data(&coin_data);
        let coin_commitment_provided = inputs.coin_commitment;
        if computed_coin_commitment != coin_commitment_provided {
            return Err(ClvmZkError::ProofGenerationFailed(
                "coin commitment verification failed".to_string(),
            ));
        }
        // 4. Verify merkle membership
        let merkle_path = inputs.merkle_path;
        let expected_root = inputs.merkle_root;
        let leaf_index = inputs.leaf_index;
        let mut current_hash = computed_coin_commitment;
        let mut current_index = leaf_index;
        for sibling in merkle_path.iter() {
            let mut combined = [0u8; 64];
            if current_index % 2 == 0 {
                combined[..32].copy_from_slice(&current_hash);
                combined[32..].copy_from_slice(sibling);
            } else {
                combined[..32].copy_from_slice(sibling);
                combined[32..].copy_from_slice(&current_hash);
            }
            current_hash = hash_data(&combined);
            current_index /= 2;
        }

        let computed_root = current_hash;
        if computed_root != expected_root {
            return Err(ClvmZkError::ProofGenerationFailed(
                "merkle root mismatch: coin not in current tree state".to_string(),
            ));
        }

        // 5. Compute nullifier = hash(serial_number || program_hash)
        let mut nullifier_data = Vec::with_capacity(64);
        nullifier_data.extend_from_slice(&serial_number);
        nullifier_data.extend_from_slice(&program_hash);
        let nullifier = hash_data(&nullifier_data);

        let proof_output = ProofOutput {
            program_hash,
            nullifier: Some(nullifier),
            clvm_res: clvm_output.clone(),
        };

        let proof_bytes = borsh::to_vec(&proof_output).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize mock proof: {e}"))
        })?;

        Ok(ZKClvmResult {
            proof_output,
            proof_bytes,
        })
    }

    pub fn verify_proof_and_extract(
        &self,
        proof: &[u8],
    ) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError> {
        let output: ProofOutput = borsh::from_slice(proof).map_err(|e| {
            ClvmZkError::InvalidProofFormat(format!("failed to deserialize mock proof: {e}"))
        })?;

        Ok((true, output.program_hash, output.clvm_res.output))
    }

    pub fn backend_name(&self) -> &'static str {
        "mock"
    }

    pub fn is_available(&self) -> bool {
        true // mock backend is always available
    }
}
