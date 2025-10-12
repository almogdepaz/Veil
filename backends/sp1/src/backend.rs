//! sp1 zkvm backend

// import sp1 elf from this crate
use crate::CLVM_ZK_SP1_ELF;

// use common types from clvm_zk_core
pub use clvm_zk_core::{
    ClvmResult, ClvmZkError, Input, ProgramParameter, ProofOutput, ZKClvmResult,
};

// use common backend utilities
use crate::common::{
    convert_proving_error, validate_nullifier_proof_output, validate_proof_output,
};

// import the global common module with prepare_guest_inputs
use crate::global_common::prepare_guest_inputs;

use sp1_sdk::SP1ProofMode;

/// sp1 zkvm backend
pub struct Sp1Backend {
    skip_execution: bool,
    proof_mode: String,
}

impl Sp1Backend {
    pub fn new() -> Result<Self, ClvmZkError> {
        // check if sp1 is available
        if !Self::is_sp1_available() {
            return Err(ClvmZkError::ConfigurationError(
                "sp1 zkvm not available - install sp1 toolchain".to_string(),
            ));
        }

        let skip_execution = std::env::var("SP1_SKIP_EXECUTION").is_ok();
        let proof_mode = std::env::var("SP1_PROOF_MODE").unwrap_or_else(|_| "core".to_string());
        Ok(Self {
            skip_execution,
            proof_mode,
        })
    }

    fn is_sp1_available() -> bool {
        // check if we have the program elf
        !CLVM_ZK_SP1_ELF.is_empty()
    }

    fn parse_proof_mode(&self) -> SP1ProofMode {
        match self.proof_mode.to_lowercase().as_str() {
            "core" => SP1ProofMode::Core,
            "compressed" => SP1ProofMode::Compressed,
            "plonk" => SP1ProofMode::Plonk,
            "groth16" => SP1ProofMode::Groth16,
            _ => {
                println!(
                    "unknown proof mode '{}', defaulting to core",
                    self.proof_mode
                );
                SP1ProofMode::Core
            }
        }
    }

    // Legacy function - no longer used with guest-side compilation
    #[allow(dead_code)]
    fn serialize_parameters(parameters: &[ProgramParameter]) -> Result<Vec<u8>, ClvmZkError> {
        borsh::to_vec(parameters).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize parameters: {e}"))
        })
    }

    pub fn prove_chialisp_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        use sp1_sdk::{ProverClient, SP1Stdin};

        // prepare inputs for the guest
        let inputs = prepare_guest_inputs(chialisp_source, program_parameters, None);

        // create stdin for sp1
        let mut stdin = SP1Stdin::new();
        stdin.write(&inputs);

        // execute to get cycle count, then generate proof
        let client = ProverClient::from_env();
        let (pk, _vk) = client.setup(CLVM_ZK_SP1_ELF);

        let total_cycles = if self.skip_execution {
            println!("sp1 cycle counting skipped - cost will be 0");
            0
        } else {
            // execute to get cycle count
            let execute_start = std::time::Instant::now();
            let (_public_values, execution_report) =
                client.execute(CLVM_ZK_SP1_ELF, &stdin).run().map_err(|e| {
                    ClvmZkError::ProofGenerationFailed(format!("sp1 execution failed: {e}"))
                })?;
            let execute_time = execute_start.elapsed();
            println!("sp1 execute took: {}ms", execute_time.as_millis());

            // get instruction count from execution report
            execution_report.total_instruction_count()
        };

        let proof_mode = self.parse_proof_mode();
        let mut proof = {
            use std::panic::AssertUnwindSafe;
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                client.prove(&pk, &stdin).mode(proof_mode).run()
            }))
            .map_err(|_| ClvmZkError::ProofGenerationFailed("SP1 proving panicked".to_string()))?
            .map_err(|e| convert_proving_error(e, "SP1"))?
        };

        // extract outputs from the proof
        let output: ProofOutput = proof.public_values.read();

        // Validate proof output
        validate_proof_output(&output, "SP1")?;

        // SP1 proofs use serde/bincode serialization, not borsh
        let proof_bytes = bincode::serialize(&proof).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize proof: {e}"))
        })?;

        Ok(ZKClvmResult {
            output,
            proof: proof_bytes,
        })
    }

    pub fn prove_chialisp_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        use sp1_sdk::{ProverClient, SP1Stdin};

        // prepare inputs for the guest
        let inputs = prepare_guest_inputs(chialisp_source, program_parameters, Some(spend_secret));

        // create stdin for sp1
        let mut stdin = SP1Stdin::new();
        stdin.write(&inputs);

        // execute to get cycle count, then generate proof
        let client = ProverClient::from_env();
        let (pk, _vk) = client.setup(CLVM_ZK_SP1_ELF);

        let total_cycles = if self.skip_execution {
            println!("sp1 cycle counting skipped - cost will be 0");
            0
        } else {
            // execute to get cycle count
            let execute_start = std::time::Instant::now();
            let (_public_values, execution_report) =
                client.execute(CLVM_ZK_SP1_ELF, &stdin).run().map_err(|e| {
                    ClvmZkError::ProofGenerationFailed(format!("sp1 execution failed: {e}"))
                })?;
            let execute_time = execute_start.elapsed();
            println!("sp1 execute took: {}ms", execute_time.as_millis());

            // get instruction count from execution report
            execution_report.total_instruction_count()
        };

        let proof_mode = self.parse_proof_mode();
        let mut proof = {
            use std::panic::AssertUnwindSafe;
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                client.prove(&pk, &stdin).mode(proof_mode).run()
            }))
            .map_err(|_| ClvmZkError::ProofGenerationFailed("SP1 proving panicked".to_string()))?
            .map_err(|e| convert_proving_error(e, "SP1"))?
        };

        // extract nullifier-aware outputs from the proof
        let output: ProofOutput = proof.public_values.read();

        // Validate nullifier proof output
        validate_nullifier_proof_output(&output, "SP1")?;

        // SP1 proofs use serde/bincode serialization, not borsh
        let proof_bytes = bincode::serialize(&proof).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize proof: {e}"))
        })?;

        Ok(ZKClvmResult {
            output,
            proof: proof_bytes,
        })
    }

    pub fn verify_proof_and_extract(
        &self,
        proof: &[u8],
    ) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError> {
        use sp1_sdk::{ProverClient, SP1ProofWithPublicValues};

        // deserialize the proof using bincode
        let proof: SP1ProofWithPublicValues = bincode::deserialize(proof).map_err(|e| {
            ClvmZkError::InvalidProofFormat(format!("failed to deserialize proof: {e}"))
        })?;

        // verify the proof cryptographically first
        let client = ProverClient::from_env();
        let (_, vk) = client.setup(CLVM_ZK_SP1_ELF);
        client.verify(&proof, &vk).map_err(|e| {
            ClvmZkError::VerificationFailed(format!("sp1 verification failed: {e}"))
        })?;

        // extract and validate outputs from the proof
        let mut public_values = proof.public_values;
        let output = public_values.read::<clvm_zk_core::ProofOutput>();

        // return success, extracted program hash, and output
        Ok((true, output.program_hash, output.clvm_res.output))
    }

    pub fn backend_name(&self) -> &'static str {
        "sp1"
    }

    pub fn is_available(&self) -> bool {
        Self::is_sp1_available()
    }
}
