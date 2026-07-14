mod methods;
pub mod recursive;

pub use methods::*;
pub use recursive::RecursiveAggregator;

// re-export for settlement.rs
pub use bincode;
pub use sp1_sdk;

pub use clvm_zk_core::{
    ClvmResult, ClvmZkError, CoinMode, Input, ProgramParameter, ProofOutput, ZKClvmResult,
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

    #[allow(clippy::const_is_empty)]
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

    fn validate_input(input: &Input) -> Result<(), ClvmZkError> {
        clvm_zk_core::backend_utils::validate_guest_input(input)
    }

    fn generate_proof(
        &self,
        inputs: &Input,
    ) -> Result<sp1_sdk::SP1ProofWithPublicValues, ClvmZkError> {
        use sp1_sdk::{ProverClient, SP1Stdin};

        let mut stdin = SP1Stdin::new();
        stdin.write(inputs);
        let client = ProverClient::from_env();
        let (proving_key, _) = client.setup(CLVM_ZK_SP1_ELF);

        if !self.skip_execution {
            let execute_start = std::time::Instant::now();
            client
                .execute(CLVM_ZK_SP1_ELF, &stdin)
                .run()
                .map_err(|error| {
                    ClvmZkError::ProofGenerationFailed(format!("sp1 execution failed: {error}"))
                })?;
            println!(
                "sp1 execute took: {}ms",
                execute_start.elapsed().as_millis()
            );
        } else {
            println!("sp1 cycle counting skipped - cost will be 0");
        }

        use std::panic::AssertUnwindSafe;
        std::panic::catch_unwind(AssertUnwindSafe(|| {
            client
                .prove(&proving_key, &stdin)
                .mode(self.parse_proof_mode())
                .run()
        }))
        .map_err(|_| ClvmZkError::ProofGenerationFailed("SP1 proving panicked".to_string()))?
        .map_err(|error| convert_proving_error(error, "SP1"))
    }

    pub fn prove_chialisp_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        let inputs = Input {
            chialisp_source: chialisp_source.to_string(),
            program_parameters: program_parameters.to_vec(),
            coin_mode: CoinMode::Execute,
            tail_hash: None,        // XCH by default
            additional_coins: None, // single-coin spend
            tail_source: None,
            tail_params: vec![],
            network: None,
        };
        let mut proof = self.generate_proof(&inputs)?;

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
        if inputs.network.is_some() {
            return Err(ClvmZkError::InvalidInput(
                "network input requires prove_network_with_input".to_string(),
            ));
        }
        Self::validate_input(&inputs)?;
        let mut proof = self.generate_proof(&inputs)?;
        let output: ProofOutput = proof.public_values.read();
        validate_nullifier_proof_output(&output, "SP1")?;
        let proof_bytes = bincode::serialize(&proof).map_err(|error| {
            ClvmZkError::SerializationError(format!("failed to serialize proof: {error}"))
        })?;
        Ok(ZKClvmResult {
            proof_output: output,
            proof_bytes,
        })
    }

    pub fn prove_network_with_input(
        &self,
        inputs: clvm_zk_core::Input,
    ) -> Result<clvm_zk_core::ZKNetworkResultV1, ClvmZkError> {
        clvm_zk_core::validate_network_request_v1(&inputs)
            .map_err(|error| ClvmZkError::InvalidInput(error.to_string()))?;
        Self::validate_input(&inputs)?;
        let proof = self.generate_proof(&inputs)?;
        let output =
            borsh::from_slice::<clvm_zk_core::NetworkProofOutputV1>(proof.public_values.as_slice())
                .map_err(|error| {
                    ClvmZkError::InvalidProofFormat(format!(
                        "failed to decode SP1 network journal: {error}"
                    ))
                })?;
        let proof_bytes = bincode::serialize(&proof).map_err(|error| {
            ClvmZkError::SerializationError(format!("failed to serialize proof: {error}"))
        })?;
        Ok(clvm_zk_core::ZKNetworkResultV1 {
            proof_output: output,
            proof_bytes,
        })
    }

    pub fn network_program_id() -> [u8; 32] {
        use sp1_sdk::{HashableKey, ProverClient};

        let client = ProverClient::from_env();
        let (_, verifying_key) = client.setup(CLVM_ZK_SP1_ELF);
        verifying_key.bytes32_raw()
    }

    pub fn verify_network_proof_and_decode(
        &self,
        proof: &[u8],
        max_proof_bytes: usize,
    ) -> Result<clvm_zk_core::NetworkProofOutputV1, ClvmZkError> {
        if proof.len() > max_proof_bytes {
            return Err(ClvmZkError::InvalidInput(
                "SP1 proof exceeds configured byte limit".to_string(),
            ));
        }
        use bincode::Options;
        use sp1_sdk::{ProverClient, SP1ProofWithPublicValues};

        let proof: SP1ProofWithPublicValues = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(proof)
            .map_err(|error| {
                ClvmZkError::InvalidProofFormat(format!("failed to deserialize SP1 proof: {error}"))
            })?;
        let client = ProverClient::from_env();
        let (_, verifying_key) = client.setup(CLVM_ZK_SP1_ELF);
        client.verify(&proof, &verifying_key).map_err(|error| {
            ClvmZkError::VerificationFailed(format!("SP1 verification failed: {error}"))
        })?;
        borsh::from_slice(proof.public_values.as_slice()).map_err(|error| {
            ClvmZkError::InvalidProofFormat(format!(
                "failed to decode SP1 network journal: {error}"
            ))
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
