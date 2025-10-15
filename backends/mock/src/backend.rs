use clvm_zk_core::verify_ecdsa_signature_with_hasher;
use clvm_zk_core::{
    compile_chialisp_to_bytecode_with_table, generate_nullifier, ClvmEvaluator, ClvmResult,
    ClvmZkError, ProgramParameter, ProofOutput, ZKClvmResult, BLS_DST,
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

    pub fn prove_chialisp_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        spend_secret: [u8; 32],
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

        let computed_nullifier = generate_nullifier(hash_data, &spend_secret, &program_hash);

        let clvm_output = ClvmResult {
            output: output_bytes,
            cost: 0,
        };

        let proof_output = ProofOutput {
            program_hash,
            nullifier: Some(computed_nullifier),
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
