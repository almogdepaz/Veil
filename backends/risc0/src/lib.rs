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

    pub fn prove_chialisp_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        use risc0_zkvm::{default_prover, ExecutorEnv};

        let inputs = Input {
            chialisp_source: chialisp_source.to_string(),
            program_parameters: program_parameters.to_vec(),
            coin_mode: CoinMode::Execute,
            tail_hash: None,        // XCH by default
            additional_coins: None, // single-coin spend
            tail_source: None,
            tail_params: vec![],
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
        use risc0_zkvm::{default_prover, ExecutorEnv};

        // guard: Execute mode with a non-zero tail_hash is semantically invalid —
        // TAIL is never run in Execute mode, producing a misleading CAT-labelled proof.
        if matches!(inputs.coin_mode, CoinMode::Execute) {
            if inputs.tail_hash.map_or(false, |h| h != [0u8; 32]) {
                return Err(ClvmZkError::ProofGenerationFailed(
                    "Execute mode with non-zero tail_hash is not allowed — use CoinMode::Spend for CAT operations".to_string(),
                ));
            }
        }

        // host-side guard: reject CoinMode::Mint before reaching the guest.
        // the guest panics on Mint (not yet implemented); this surfaces a clean error instead.
        if matches!(inputs.coin_mode, CoinMode::Mint(_)) {
            return Err(ClvmZkError::ProofGenerationFailed(
                "mint mode not yet supported in risc0 backend".to_string(),
            ));
        }

        // host-side guard: CAT spend without tail_source produces an opaque guest panic.
        // surface a clean error here instead.
        let is_cat = inputs.tail_hash.map_or(false, |h| h != [0u8; 32]);
        if is_cat && matches!(inputs.coin_mode, CoinMode::Spend(_)) && inputs.tail_source.is_none()
        {
            return Err(ClvmZkError::ProofGenerationFailed(
                "CAT spend requires tail_source: tail_hash is set but tail_source was not provided"
                    .to_string(),
            ));
        }

        // guard: CAT ring coins without tail_source produce opaque guest panics.
        if let Some(ref additional_coins) = inputs.additional_coins {
            for (i, coin) in additional_coins.iter().enumerate() {
                if coin.tail_hash != [0u8; 32] && coin.tail_source.is_none() {
                    return Err(ClvmZkError::ProofGenerationFailed(format!(
                        "CAT ring coin {i} requires tail_source: tail_hash is set but tail_source was not provided"
                    )));
                }
            }
        }

        // host-side guard: leaf_index values must fit in u32 since the guest runs on 32-bit RISC-V.
        // catch this here to avoid an opaque guest panic.
        const MAX_LEAF: u64 = u32::MAX as u64;
        if let CoinMode::Spend(ref d) = inputs.coin_mode {
            if d.leaf_index > MAX_LEAF {
                return Err(ClvmZkError::ProofGenerationFailed(format!(
                    "primary coin leaf_index {} exceeds 32-bit platform limit ({})",
                    d.leaf_index, MAX_LEAF
                )));
            }
        }
        if let Some(ref additional_coins) = inputs.additional_coins {
            for (i, coin) in additional_coins.iter().enumerate() {
                if coin.serial_commitment_data.leaf_index > MAX_LEAF {
                    return Err(ClvmZkError::ProofGenerationFailed(format!(
                        "ring coin {i} leaf_index {} exceeds 32-bit platform limit ({})",
                        coin.serial_commitment_data.leaf_index, MAX_LEAF
                    )));
                }
            }
        }

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
