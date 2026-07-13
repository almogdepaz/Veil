mod methods;
pub mod recursive;

pub use methods::*;
pub use recursive::RecursiveAggregator;

use clvm_zk_core::backend_utils::{
    convert_proving_error, validate_nullifier_proof_output, validate_proof_output,
};
pub use clvm_zk_core::{
    ClvmResult, ClvmZkError, CoinMode, Input, ProgramParameter, ProofOutput, ZKClvmResult,
};

pub struct Risc0Backend {}

impl Risc0Backend {
    pub fn new() -> Result<Self, ClvmZkError> {
        if !Self::is_risc0_available() {
            return Err(ClvmZkError::ConfigurationError(
                "risc0 zkvm not available - run ./install-deps.sh".to_string(),
            ));
        }

        Ok(Self {})
    }

    #[allow(clippy::const_is_empty)]
    fn is_risc0_available() -> bool {
        !CLVM_RISC0_GUEST_ELF.is_empty()
    }

    fn generate_receipt(&self, inputs: &Input) -> Result<risc0_zkvm::Receipt, ClvmZkError> {
        use risc0_zkvm::{default_prover, ExecutorEnv};

        let env = ExecutorEnv::builder()
            .write(inputs)
            .map_err(|error| {
                ClvmZkError::ProofGenerationFailed(format!(
                    "failed to write private inputs: {error}"
                ))
            })?
            .build()
            .map_err(|error| {
                ClvmZkError::ProofGenerationFailed(format!("failed to build executor env: {error}"))
            })?;
        let prover = default_prover();
        use std::panic::AssertUnwindSafe;
        std::panic::catch_unwind(AssertUnwindSafe(move || {
            prover.prove(env, CLVM_RISC0_GUEST_ELF)
        }))
        .map_err(|_| ClvmZkError::ProofGenerationFailed("RISC0 proving panicked".to_string()))?
        .map_err(|error| convert_proving_error(error, "RISC0"))
        .map(|info| info.receipt)
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
        let receipt_obj = self.generate_receipt(&inputs)?;
        let result: ProofOutput = receipt_obj.journal.decode().map_err(|e| {
            ClvmZkError::InvalidProofFormat(format!("failed to decode journal: {e}"))
        })?;

        // // PROFILING: decode and print cycle counts if present
        // if !result.public_values.is_empty() && result.public_values[0].len() == 24 {
        //     let data = &result.public_values[0];
        //     let compile_cycles = u64::from_le_bytes(data[0..8].try_into().unwrap());
        //     let exec_cycles = u64::from_le_bytes(data[8..16].try_into().unwrap());
        //     let total_cycles = u64::from_le_bytes(data[16..24].try_into().unwrap());
        //
        //     // convert cycles to approximate seconds (risc0 ~2.4M cycles/sec on modern hardware)
        //     let cycles_per_sec = 2_400_000.0;
        //     eprintln!("   📊 PROFILING: compile={:.1}M cycles ({:.1}s) | exec={:.1}M cycles ({:.1}s) | total={:.1}M cycles ({:.1}s)",
        //         compile_cycles as f64 / 1_000_000.0,
        //         compile_cycles as f64 / cycles_per_sec,
        //         exec_cycles as f64 / 1_000_000.0,
        //         exec_cycles as f64 / cycles_per_sec,
        //         total_cycles as f64 / 1_000_000.0,
        //         total_cycles as f64 / cycles_per_sec,
        //     );
        // }

        validate_proof_output(&result, "RISC0")?;

        let proof_bytes = borsh::to_vec(&receipt_obj).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize receipt: {e}"))
        })?;

        Ok(ZKClvmResult {
            proof_output: result,
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
        clvm_zk_core::backend_utils::validate_guest_input(&inputs)?;
        let receipt_obj = self.generate_receipt(&inputs)?;
        let result: ProofOutput = receipt_obj.journal.decode().map_err(|e| {
            ClvmZkError::InvalidProofFormat(format!("failed to decode journal: {e}"))
        })?;

        // // PROFILING: decode and print cycle counts if present
        // if !result.public_values.is_empty() && result.public_values[0].len() == 24 {
        //     let data = &result.public_values[0];
        //     let compile_cycles = u64::from_le_bytes(data[0..8].try_into().unwrap());
        //     let exec_cycles = u64::from_le_bytes(data[8..16].try_into().unwrap());
        //     let total_cycles = u64::from_le_bytes(data[16..24].try_into().unwrap());
        //
        //     // convert cycles to approximate seconds (risc0 ~2.4M cycles/sec on modern hardware)
        //     let cycles_per_sec = 2_400_000.0;
        //     eprintln!("   📊 PROFILING: compile={:.1}M cycles ({:.1}s) | exec={:.1}M cycles ({:.1}s) | total={:.1}M cycles ({:.1}s)",
        //         compile_cycles as f64 / 1_000_000.0,
        //         compile_cycles as f64 / cycles_per_sec,
        //         exec_cycles as f64 / 1_000_000.0,
        //         exec_cycles as f64 / cycles_per_sec,
        //         total_cycles as f64 / 1_000_000.0,
        //         total_cycles as f64 / cycles_per_sec,
        //     );
        // }

        validate_nullifier_proof_output(&result, "RISC0")?;

        let proof_bytes: Vec<u8> = borsh::to_vec(&receipt_obj).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize receipt: {e}"))
        })?;

        Ok(ZKClvmResult {
            proof_bytes,
            proof_output: result,
        })
    }

    pub fn prove_network_with_input(
        &self,
        inputs: clvm_zk_core::Input,
    ) -> Result<clvm_zk_core::ZKNetworkResultV1, ClvmZkError> {
        clvm_zk_core::validate_network_request_v1(&inputs)
            .map_err(|error| ClvmZkError::InvalidInput(error.to_string()))?;
        clvm_zk_core::backend_utils::validate_guest_input(&inputs)?;
        let receipt = self.generate_receipt(&inputs)?;
        let output =
            borsh::from_slice::<clvm_zk_core::NetworkProofOutputV1>(&receipt.journal.bytes)
                .map_err(|error| {
                    ClvmZkError::InvalidProofFormat(format!(
                        "failed to decode RISC Zero network journal: {error}"
                    ))
                })?;
        let proof_bytes = borsh::to_vec(&receipt).map_err(|error| {
            ClvmZkError::SerializationError(format!("failed to serialize receipt: {error}"))
        })?;
        Ok(clvm_zk_core::ZKNetworkResultV1 {
            proof_output: output,
            proof_bytes,
        })
    }

    pub fn network_program_id() -> [u8; 32] {
        let digest = risc0_zkvm::sha::Digest::new(CLVM_RISC0_GUEST_ID);
        let mut program_id = [0; 32];
        program_id.copy_from_slice(digest.as_bytes());
        program_id
    }

    pub fn verify_network_proof_and_decode(
        &self,
        proof: &[u8],
        max_proof_bytes: usize,
    ) -> Result<clvm_zk_core::NetworkProofOutputV1, ClvmZkError> {
        if proof.len() > max_proof_bytes {
            return Err(ClvmZkError::InvalidInput(
                "RISC Zero proof exceeds configured byte limit".to_string(),
            ));
        }
        let receipt: risc0_zkvm::Receipt = borsh::from_slice(proof).map_err(|error| {
            ClvmZkError::InvalidProofFormat(format!(
                "failed to deserialize RISC Zero receipt: {error}"
            ))
        })?;
        receipt.verify(CLVM_RISC0_GUEST_ID).map_err(|error| {
            ClvmZkError::VerificationFailed(format!("RISC Zero verification failed: {error}"))
        })?;
        borsh::from_slice(&receipt.journal.bytes).map_err(|error| {
            ClvmZkError::InvalidProofFormat(format!(
                "failed to decode RISC Zero network journal: {error}"
            ))
        })
    }

    pub fn verify_proof_and_extract(
        &self,
        proof: &[u8],
    ) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError> {
        let receipt: risc0_zkvm::Receipt = borsh::from_slice(proof).map_err(|e| {
            ClvmZkError::InvalidProofFormat(format!("failed to deserialize receipt: {e}"))
        })?;

        receipt.verify(CLVM_RISC0_GUEST_ID).map_err(|e| {
            ClvmZkError::VerificationFailed(format!("risc0 verification failed: {e}"))
        })?;

        let output = receipt
            .journal
            .decode::<clvm_zk_core::ProofOutput>()
            .map_err(|e| {
                ClvmZkError::InvalidProofFormat(format!("failed to decode journal: {e}"))
            })?;

        Ok((true, output.program_hash, output.clvm_res.output))
    }

    pub fn backend_name(&self) -> &'static str {
        "risc0"
    }

    pub fn is_available(&self) -> bool {
        Self::is_risc0_available()
    }
}
