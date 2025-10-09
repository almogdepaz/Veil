use clvm_zk_core::verify_ecdsa_signature_with_hasher;
use clvm_zk_core::{
    compile_chialisp_to_bytecode, compile_chialisp_with_function_table, generate_nullifier,
    ClvmEvaluator, ClvmOutput, ClvmZkError, ProgramParameter, ProofOutput, PublicInputs,
    ZKClvmNullifierResult, ZKClvmResult,
};
use sha2::{Digest, Sha256};

use blst::min_pk as blst_core;
use blst::BLST_ERROR;

pub struct MockBackend;

impl MockBackend {}

pub fn default_bls_verifier(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    // Deserialize public key
    let pk = blst_core::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| "invalid public key bytes")?;

    // Deserialize signature
    let sig =
        blst_core::Signature::from_bytes(signature_bytes).map_err(|_| "invalid signature bytes")?;

    // Domain separation tag (Ethereum-style)
    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    // The verify() function signature is:
    // verify(hash_or_encode: bool, msg: &[u8], dst: &[u8], aug: &[u8], pk: &PublicKey, validate: bool)
    let res: BLST_ERROR = sig.verify(true, message_bytes, DST, &[], &pk, true);

    Ok(res == BLST_ERROR::BLST_SUCCESS)
}

fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn ecdsa_verifier(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    verify_ecdsa_signature_with_hasher(hash_data, public_key_bytes, message_bytes, signature_bytes)
}

impl MockBackend {
    pub fn new() -> Result<Self, ClvmZkError> {
        Ok(Self)
    }

    /// runs the exact same logic as the guest but without zkvm overhead
    /// now with function table support and detailed logging
    pub fn prove_chialisp_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        // compile chialisp source to bytecode WITH function table
        let (instance_bytecode, program_hash, function_table) =
            compile_chialisp_with_function_table(chialisp_source, program_parameters).map_err(
                |e| {
                    ClvmZkError::ProofGenerationFailed(format!(
                        "chialisp compilation failed: {:?}",
                        e
                    ))
                },
            )?;

        // execute the compiled bytecode using evaluator with function table
        let mut evaluator = ClvmEvaluator::new(hash_data, default_bls_verifier, ecdsa_verifier);
        evaluator.function_table = function_table;

        let (output_bytes, _conditions) = evaluator
            .evaluate_clvm_program_with_params(&instance_bytecode, program_parameters)
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("clvm execution failed: {:?}", e))
            })?;

        let clvm_output = ClvmOutput {
            result: output_bytes,
            cost: 0, // mock backend doesn't track cycles
        };

        // create fake proof (just serialize the output for now)
        let proof_output = ProofOutput {
            public_inputs: PublicInputs {}, // empty for now
            program_hash,
            nullifier: None,
            clvm_output: clvm_output.clone(),
        };

        let proof_bytes = borsh::to_vec(&proof_output).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize mock proof: {e}"))
        })?;

        Ok(ZKClvmResult {
            result: clvm_output.result,
            cost: clvm_output.cost,
            proof: proof_bytes,
        })
    }

    /// verify a mock proof by re-executing and comparing results
    pub fn verify_mock_proof(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        expected_result: &[u8],
    ) -> Result<bool, ClvmZkError> {
        let result = self.prove_chialisp_program(chialisp_source, program_parameters)?;
        Ok(result.result == expected_result)
    }

    /// same as prove_chialisp_program but with nullifier generation
    pub fn prove_chialisp_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmNullifierResult, ClvmZkError> {
        // compile chialisp source to bytecode (same as guest)
        let (instance_bytecode, program_hash) = compile_chialisp_to_bytecode(
            hash_data,
            chialisp_source,
            program_parameters,
        )
        .map_err(|e| {
            ClvmZkError::ProofGenerationFailed(format!("chialisp compilation failed: {:?}", e))
        })?;

        // execute the compiled bytecode using default evaluator (same as SP1 guest)
        let mut evaluator = ClvmEvaluator::new(hash_data, default_bls_verifier, ecdsa_verifier);
        let (output_bytes, _conditions) = evaluator
            .evaluate_clvm_program_with_params(&instance_bytecode, program_parameters)
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("clvm execution failed: {:?}", e))
            })?;

        // generate nullifier using program hash (same as guest)
        let computed_nullifier = generate_nullifier(hash_data, &spend_secret, &program_hash);

        let clvm_output = ClvmOutput {
            result: output_bytes,
            cost: 0, // mock backend doesn't track cycles
        };

        // create fake proof with nullifier
        let proof_output = ProofOutput {
            public_inputs: PublicInputs {},
            program_hash,
            nullifier: Some(computed_nullifier),
            clvm_output: clvm_output.clone(),
        };

        let proof_bytes = borsh::to_vec(&proof_output).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize mock proof: {e}"))
        })?;

        Ok(ZKClvmNullifierResult {
            nullifier: computed_nullifier,
            result: clvm_output.result,
            cost: clvm_output.cost,
            proof: proof_bytes,
        })
    }

    /// "verify" the mock proof by just deserializing it
    pub fn verify_proof_and_extract(
        &self,
        proof: &[u8],
    ) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError> {
        let output: ProofOutput = borsh::from_slice(proof).map_err(|e| {
            ClvmZkError::InvalidProofFormat(format!("failed to deserialize mock proof: {e}"))
        })?;

        // always return true for mock verification since we trust our own execution
        Ok((true, output.program_hash, output.clvm_output.result))
    }

    pub fn backend_name(&self) -> &'static str {
        "mock"
    }

    pub fn is_available(&self) -> bool {
        true // mock backend is always available
    }
}
