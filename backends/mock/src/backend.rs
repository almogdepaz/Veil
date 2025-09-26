use clvm_zk_core::{
    compile_chialisp_to_bytecode, generate_nullifier, ClvmEvaluator, ClvmOutput, ClvmZkError,
    ProgramParameter, ProofOutput, PublicInputs, ZKClvmNullifierResult, ZKClvmResult,
};

pub struct MockBackend;

impl MockBackend {
    pub fn new() -> Result<Self, ClvmZkError> {
        Ok(Self)
    }

    /// runs the exact same logic as the guest but without zkvm overhead
    pub fn prove_chialisp_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        // compile chialisp source to bytecode (same as guest)
        let (instance_bytecode, program_hash) =
            compile_chialisp_to_bytecode(chialisp_source, program_parameters).map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("chialisp compilation failed: {:?}", e))
            })?;

        // execute the compiled bytecode using default evaluator (same as SP1 guest)
        let evaluator = ClvmEvaluator::new();
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

    /// same as prove_chialisp_program but with nullifier generation
    pub fn prove_chialisp_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmNullifierResult, ClvmZkError> {
        // compile chialisp source to bytecode (same as guest)
        let (instance_bytecode, program_hash) =
            compile_chialisp_to_bytecode(chialisp_source, program_parameters).map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("chialisp compilation failed: {:?}", e))
            })?;

        // execute the compiled bytecode using default evaluator (same as SP1 guest)
        let evaluator = ClvmEvaluator::new();
        let (output_bytes, _conditions) = evaluator
            .evaluate_clvm_program_with_params(&instance_bytecode, program_parameters)
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("clvm execution failed: {:?}", e))
            })?;

        // generate nullifier using program hash (same as guest)
        let computed_nullifier = generate_nullifier(&spend_secret, &program_hash);

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
