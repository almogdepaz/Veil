use clvm_zk_core::{
    compile_chialisp_to_bytecode, compile_chialisp_with_function_table, generate_nullifier,
    ClvmEvaluator, ClvmOutput, ClvmZkError, ProgramParameter, ProofOutput, PublicInputs,
    ZKClvmNullifierResult, ZKClvmResult,
};
use std::fs;
use std::path::Path;

pub struct MockBackend;

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
        let mut execution_log = String::new();
        execution_log.push_str("=== MOCK BACKEND EXECUTION LOG ===\n\n");
        execution_log.push_str(&format!("Chialisp Source:\n{}\n\n", chialisp_source));
        execution_log.push_str(&format!("Parameters: {:?}\n\n", program_parameters));

        // compile chialisp source to bytecode WITH function table support
        let (instance_bytecode, program_hash, function_table) =
            compile_chialisp_with_function_table(chialisp_source, program_parameters).map_err(|e| {
                let error_msg = format!("chialisp compilation failed: {:?}", e);
                execution_log.push_str(&format!("❌ COMPILATION ERROR: {}\n", error_msg));
                self.save_execution_log(&execution_log, "compilation_failed");
                ClvmZkError::ProofGenerationFailed(error_msg)
            })?;

        execution_log.push_str("✅ Compilation successful\n");
        execution_log.push_str(&format!("Program hash: {:?}\n", hex::encode(program_hash)));
        execution_log.push_str(&format!("Bytecode length: {} bytes\n", instance_bytecode.len()));
        execution_log.push_str(&format!("Function table: {} functions\n", function_table.function_names().len()));
        execution_log.push_str(&format!("Functions: {:?}\n\n", function_table.function_names()));

        execution_log.push_str("=== EXECUTION START ===\n");

        // execute the compiled bytecode using evaluator with function table
        let mut evaluator = ClvmEvaluator::new();
        evaluator.function_table = function_table;

        // Add debug tracing for evaluation steps
        execution_log.push_str(&format!("Instance bytecode: {:?}\n", instance_bytecode));

        let execution_start = std::time::Instant::now();

        let (output_bytes, conditions) = evaluator
            .evaluate_clvm_program_with_params(&instance_bytecode, program_parameters)
            .map_err(|e| {
                let error_msg = format!("clvm execution failed: {:?}", e);
                execution_log.push_str(&format!("❌ EXECUTION ERROR: {}\n", error_msg));

                // Try to parse the bytecode to understand what's happening
                execution_log.push_str("🔍 Bytecode analysis:\n");
                if instance_bytecode.len() >= 7 {
                    let op_byte = instance_bytecode[1]; // Skip the 0xFF prefix
                    execution_log.push_str(&format!("  Operator byte: {} ({})\n", op_byte, op_byte as char));

                    if op_byte == 42 { // Multiplication operator
                        execution_log.push_str("  This is a multiplication operation!\n");
                        execution_log.push_str(&format!("  Full bytecode: {:?}\n", instance_bytecode));

                        // Try to decode the arguments
                        if instance_bytecode.len() > 3 {
                            let arg1_start = 3; // Skip [255, 42, 255]
                            execution_log.push_str(&format!("  Argument section starts at byte {}: {:?}\n",
                                arg1_start, &instance_bytecode[arg1_start..]));
                        }
                    }
                }

                self.save_execution_log(&execution_log, "execution_failed");
                ClvmZkError::ProofGenerationFailed(error_msg)
            })?;

        let execution_time = execution_start.elapsed();
        execution_log.push_str(&format!("✅ Execution successful in {:?}\n", execution_time));
        execution_log.push_str(&format!("Result bytes: {:?}\n", output_bytes));
        execution_log.push_str(&format!("Result bytes (hex): {}\n", hex::encode(&output_bytes)));
        execution_log.push_str(&format!("Conditions: {} generated\n", conditions.len()));

        // try to parse result as integer for convenience
        if output_bytes.len() == 1 {
            execution_log.push_str(&format!("Result as u8: {}\n", output_bytes[0]));
        } else if output_bytes.is_empty() {
            execution_log.push_str("Result: nil (empty)\n");
        } else {
            execution_log.push_str(&format!("Result: complex ({} bytes)\n", output_bytes.len()));
        }

        execution_log.push_str("\n=== EXECUTION COMPLETE ===\n");
        self.save_execution_log(&execution_log, "success");

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

    /// save execution log to file for debugging
    fn save_execution_log(&self, log: &str, status: &str) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let filename = format!("mock_execution_{}_{}.log", status, timestamp);
        let filepath = Path::new("target").join("mock_logs").join(filename);

        // create directory if it doesn't exist
        if let Some(parent) = filepath.parent() {
            let _ = fs::create_dir_all(parent);
        }

        match fs::write(&filepath, log) {
            Ok(_) => println!("📝 Execution log saved to: {:?}", filepath),
            Err(e) => eprintln!("⚠️  Failed to save execution log: {}", e),
        }
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
        let (instance_bytecode, program_hash) =
            compile_chialisp_to_bytecode(chialisp_source, program_parameters).map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("chialisp compilation failed: {:?}", e))
            })?;

        // execute the compiled bytecode using default evaluator (same as SP1 guest)
        let mut evaluator = ClvmEvaluator::new();
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
