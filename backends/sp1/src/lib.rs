mod methods;
pub use methods::*;

pub use clvm_zk_core::{
    ClvmResult, ClvmZkError, Input, ProgramParameter, ProofOutput, ZKClvmResult,
};

use clvm_zk_core::backend_utils::{
    convert_proving_error, validate_nullifier_proof_output, validate_proof_output,
};

use sp1_sdk::SP1ProofMode;

pub struct Sp1Backend {
    skip_execution: bool,
    proof_mode: String,
}

impl Sp1Backend {
    pub fn new() -> Result<Self, ClvmZkError> {
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

    pub fn prove_chialisp_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        use sp1_sdk::{ProverClient, SP1Stdin};

        let inputs = Input {
            chialisp_source: chialisp_source.to_string(),
            program_parameters: program_parameters.to_vec(),
            serial_commitment_data: None,
        };

        let mut stdin = SP1Stdin::new();
        stdin.write(&inputs);

        let client = ProverClient::from_env();
        let (pk, _vk) = client.setup(CLVM_ZK_SP1_ELF);

        if !self.skip_execution {
            let execute_start = std::time::Instant::now();
            let _ = client.execute(CLVM_ZK_SP1_ELF, &stdin).run().map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("sp1 execution failed: {e}"))
            })?;
            let execute_time = execute_start.elapsed();
            println!("sp1 execute took: {}ms", execute_time.as_millis());
        } else {
            println!("sp1 cycle counting skipped - cost will be 0");
        }

        let proof_mode = self.parse_proof_mode();
        let mut proof = {
            use std::panic::AssertUnwindSafe;
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                client.prove(&pk, &stdin).mode(proof_mode).run()
            }))
            .map_err(|_| ClvmZkError::ProofGenerationFailed("SP1 proving panicked".to_string()))?
            .map_err(|e| convert_proving_error(e, "SP1"))?
        };

        let output: ProofOutput = proof.public_values.read();

        validate_proof_output(&output, "SP1")?;

        let proof_bytes = bincode::serialize(&proof).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize proof: {e}"))
        })?;

        Ok(ZKClvmResult {
            proof_output: output,
            proof_bytes,
        })
    }

    pub fn prove_with_input(
        &self,
        inputs: clvm_zk_core::Input,
    ) -> Result<ZKClvmResult, ClvmZkError> {
        use sp1_sdk::{ProverClient, SP1Stdin};
        let mut stdin = SP1Stdin::new();
        stdin.write(&inputs);

        let client = ProverClient::from_env();
        let (pk, _vk) = client.setup(CLVM_ZK_SP1_ELF);

        if !self.skip_execution {
            let execute_start = std::time::Instant::now();
            let _ = client.execute(CLVM_ZK_SP1_ELF, &stdin).run().map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("sp1 execution failed: {e}"))
            })?;
            let execute_time = execute_start.elapsed();
            println!("sp1 execute took: {}ms", execute_time.as_millis());
        } else {
            println!("sp1 cycle counting skipped - cost will be 0");
        }

        let proof_mode = self.parse_proof_mode();
        let mut proof = {
            use std::panic::AssertUnwindSafe;
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                client.prove(&pk, &stdin).mode(proof_mode).run()
            }))
            .map_err(|_| ClvmZkError::ProofGenerationFailed("SP1 proving panicked".to_string()))?
            .map_err(|e| convert_proving_error(e, "SP1"))?
        };

        let output: ProofOutput = proof.public_values.read();

        validate_nullifier_proof_output(&output, "SP1")?;

        let proof_bytes = bincode::serialize(&proof).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize proof: {e}"))
        })?;

        Ok(ZKClvmResult {
            proof_output: output,
            proof_bytes,
        })
    }

    pub fn verify_proof_and_extract(
        &self,
        proof: &[u8],
    ) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError> {
        use sp1_sdk::{ProverClient, SP1ProofWithPublicValues};

        let proof: SP1ProofWithPublicValues = bincode::deserialize(proof).map_err(|e| {
            ClvmZkError::InvalidProofFormat(format!("failed to deserialize proof: {e}"))
        })?;

        let client = ProverClient::from_env();
        let (_, vk) = client.setup(CLVM_ZK_SP1_ELF);
        client.verify(&proof, &vk).map_err(|e| {
            ClvmZkError::VerificationFailed(format!("sp1 verification failed: {e}"))
        })?;

        let mut public_values = proof.public_values;
        let output = public_values.read::<clvm_zk_core::ProofOutput>();

        Ok((true, output.program_hash, output.clvm_res.output))
    }

    pub fn backend_name(&self) -> &'static str {
        "sp1"
    }

    pub fn is_available(&self) -> bool {
        Self::is_sp1_available()
    }
}
