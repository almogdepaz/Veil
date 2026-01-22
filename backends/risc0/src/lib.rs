mod methods;
pub mod recursive;

pub use methods::*;
pub use recursive::RecursiveAggregator;

use borsh;
use clvm_zk_core::backend_utils::{
    convert_proving_error, validate_nullifier_proof_output, validate_proof_output,
};
pub use clvm_zk_core::{
    ClvmResult, ClvmZkError, Input, ProgramParameter, ProofOutput, ZKClvmResult,
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

    fn is_risc0_available() -> bool {
        !CLVM_RISC0_GUEST_ELF.is_empty()
    }

    pub fn prove_chialisp_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        use risc0_zkvm::{default_prover, ExecutorEnv};

        let inputs = Input {
            chialisp_source: chialisp_source.to_string(),
            program_parameters: program_parameters.to_vec(),
            serial_commitment_data: None,
            tail_hash: None,        // XCH by default
            additional_coins: None, // single-coin spend
        };
        let env = ExecutorEnv::builder()
            .write(&inputs)
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("failed to write private inputs: {e}"))
            })?
            .build()
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("failed to build executor env: {e}"))
            })?;

        let prover = default_prover();

        let receipt = {
            let elf = CLVM_RISC0_GUEST_ELF;
            prover
                .prove(env, elf)
                .map_err(|e| convert_proving_error(e, "RISC0"))?
        };

        let receipt_obj = receipt.receipt;
        let result: ProofOutput = receipt_obj.journal.decode().map_err(|e| {
            ClvmZkError::InvalidProofFormat(format!("failed to decode journal: {e}"))
        })?;

        // PROFILING: decode and print cycle counts if present
        if !result.public_values.is_empty() && result.public_values[0].len() == 24 {
            let data = &result.public_values[0];
            let compile_cycles = u64::from_le_bytes(data[0..8].try_into().unwrap());
            let exec_cycles = u64::from_le_bytes(data[8..16].try_into().unwrap());
            let total_cycles = u64::from_le_bytes(data[16..24].try_into().unwrap());

            // convert cycles to approximate seconds (risc0 ~2.4M cycles/sec on modern hardware)
            let cycles_per_sec = 2_400_000.0;
            eprintln!("   📊 PROFILING: compile={:.1}M cycles ({:.1}s) | exec={:.1}M cycles ({:.1}s) | total={:.1}M cycles ({:.1}s)",
                compile_cycles as f64 / 1_000_000.0,
                compile_cycles as f64 / cycles_per_sec,
                exec_cycles as f64 / 1_000_000.0,
                exec_cycles as f64 / cycles_per_sec,
                total_cycles as f64 / 1_000_000.0,
                total_cycles as f64 / cycles_per_sec,
            );
        }

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
        use risc0_zkvm::{default_prover, ExecutorEnv};

        let env = ExecutorEnv::builder()
            .write(&inputs)
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("failed to write private inputs: {e}"))
            })?
            .build()
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("failed to build executor env: {e}"))
            })?;

        let prover = default_prover();
        let receipt = {
            use std::panic::AssertUnwindSafe;
            let elf = CLVM_RISC0_GUEST_ELF;
            std::panic::catch_unwind(AssertUnwindSafe(move || prover.prove(env, elf)))
                .map_err(|_| {
                    ClvmZkError::ProofGenerationFailed("RISC0 proving panicked".to_string())
                })?
                .map_err(|e| convert_proving_error(e, "RISC0"))?
        };

        let receipt_obj = receipt.receipt;
        let result: ProofOutput = receipt_obj.journal.decode().map_err(|e| {
            ClvmZkError::InvalidProofFormat(format!("failed to decode journal: {e}"))
        })?;

        // PROFILING: decode and print cycle counts if present
        if !result.public_values.is_empty() && result.public_values[0].len() == 24 {
            let data = &result.public_values[0];
            let compile_cycles = u64::from_le_bytes(data[0..8].try_into().unwrap());
            let exec_cycles = u64::from_le_bytes(data[8..16].try_into().unwrap());
            let total_cycles = u64::from_le_bytes(data[16..24].try_into().unwrap());

            // convert cycles to approximate seconds (risc0 ~2.4M cycles/sec on modern hardware)
            let cycles_per_sec = 2_400_000.0;
            eprintln!("   📊 PROFILING: compile={:.1}M cycles ({:.1}s) | exec={:.1}M cycles ({:.1}s) | total={:.1}M cycles ({:.1}s)",
                compile_cycles as f64 / 1_000_000.0,
                compile_cycles as f64 / cycles_per_sec,
                exec_cycles as f64 / 1_000_000.0,
                exec_cycles as f64 / cycles_per_sec,
                total_cycles as f64 / 1_000_000.0,
                total_cycles as f64 / cycles_per_sec,
            );
        }

        validate_nullifier_proof_output(&result, "RISC0")?;

        let proof_bytes: Vec<u8> = borsh::to_vec(&receipt_obj).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize receipt: {e}"))
        })?;

        Ok(ZKClvmResult {
            proof_bytes,
            proof_output: result,
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
