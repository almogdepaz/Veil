use crate::common::{
    convert_proving_error, validate_nullifier_proof_output, validate_proof_output,
};
use crate::global_common::prepare_guest_inputs;
use crate::{CLVM_RISC0_GUEST_ELF, CLVM_RISC0_GUEST_ID};
use borsh;
pub use clvm_zk_core::{
    ClvmResult, ClvmZkError, Input, ProgramParameter, ProofOutput, PublicInputs,
    ZKClvmNullifierResult, ZKClvmResult,
};

pub struct Risc0Backend {}

impl Risc0Backend {
    pub fn new() -> Result<Self, ClvmZkError> {
        if !Self::is_risc0_available() {
            return Err(ClvmZkError::ConfigurationError(
                "risc0 zkvm not available - run ./install-deps.sh".to_string(),
            ));
        }

        // RISC0 backend uses feature flags - no runtime initialization needed

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

        let (public_inputs, private_inputs) =
            prepare_guest_inputs(chialisp_source, program_parameters, None);
        let env = ExecutorEnv::builder()
            .write(&public_inputs)
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("failed to write public inputs: {e}"))
            })?
            .write(&private_inputs)
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

        validate_proof_output(&result, "RISC0")?;

        let proof_bytes = borsh::to_vec(&receipt_obj).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize receipt: {e}"))
        })?;

        Ok(ZKClvmResult {
            output: result.clvm_output,
            proof: proof_bytes,
        })
    }

    pub fn prove_chialisp_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmNullifierResult, ClvmZkError> {
        use risc0_zkvm::{default_prover, ExecutorEnv};

        let (public_inputs, private_inputs) =
            prepare_guest_inputs(chialisp_source, program_parameters, Some(spend_secret));
        let env = ExecutorEnv::builder()
            .write(&public_inputs)
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("failed to write public inputs: {e}"))
            })?
            .write(&private_inputs)
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
            ClvmZkError::InvalidProofFormat(format!("failed to decode nullifier journal: {e}"))
        })?;

        validate_nullifier_proof_output(&result, "RISC0")?;

        let proof_bytes = borsh::to_vec(&receipt_obj).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize receipt: {e}"))
        })?;

        Ok(ZKClvmNullifierResult {
            nullifier: result.nullifier.unwrap_or([0u8; 32]),
            base: ZKClvmResult {
                output: result.clvm_output,
                proof: proof_bytes,
            },
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

        Ok((true, output.program_hash, output.clvm_output.result))
    }

    pub fn backend_name(&self) -> &'static str {
        "risc0"
    }

    pub fn is_available(&self) -> bool {
        Self::is_risc0_available()
    }
}
