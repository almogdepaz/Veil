//! Common utilities shared between different zkVM backends

use crate::{ClvmZkError, CoinMode, Input, ProofOutput};
use alloc::{format, string::ToString};
use core::fmt::Display;

/// Convert proving errors from zkVM into clean user-facing error messages
pub fn convert_proving_error(error: impl Display, backend_name: &str) -> ClvmZkError {
    let error_msg = error.to_string();
    // Check if the error is from guest compilation or execution failure
    if error_msg.contains("Chialisp compilation failed") {
        ClvmZkError::ProofGenerationFailed(
            "Chialisp compilation failed - invalid syntax or unsupported features".to_string(),
        )
    } else if error_msg.contains("CLVM execution failed") {
        ClvmZkError::ProofGenerationFailed(
            "CLVM execution failed - runtime error during program execution".to_string(),
        )
    } else {
        ClvmZkError::ProofGenerationFailed(format!("{} proving failed: {error}", backend_name))
    }
}

/// Reject inputs that would otherwise fail opaquely inside a 32-bit zkVM guest.
pub fn validate_guest_input(input: &Input) -> Result<(), ClvmZkError> {
    if matches!(input.coin_mode, CoinMode::Execute)
        && input.tail_hash.is_some_and(|hash| hash != [0; 32])
    {
        return Err(ClvmZkError::ProofGenerationFailed(
            "Execute mode with non-zero tail_hash is not allowed — use CoinMode::Spend for CAT operations".to_string(),
        ));
    }
    let is_cat = input.tail_hash.is_some_and(|hash| hash != [0; 32]);
    if is_cat && matches!(input.coin_mode, CoinMode::Spend(_)) && input.tail_source.is_none() {
        return Err(ClvmZkError::ProofGenerationFailed(
            "CAT spend requires tail_source: tail_hash is set but tail_source was not provided"
                .to_string(),
        ));
    }
    if let Some(additional_coins) = &input.additional_coins {
        for (index, coin) in additional_coins.iter().enumerate() {
            if coin.tail_hash != [0; 32] && coin.tail_source.is_none() {
                return Err(ClvmZkError::ProofGenerationFailed(format!(
                    "CAT ring coin {index} requires tail_source: tail_hash is set but tail_source was not provided"
                )));
            }
        }
    }
    const MAX_LEAF: u64 = u32::MAX as u64;
    if let CoinMode::Spend(spend) = &input.coin_mode {
        if spend.leaf_index > MAX_LEAF {
            return Err(ClvmZkError::ProofGenerationFailed(format!(
                "primary coin leaf_index {} exceeds 32-bit platform limit ({MAX_LEAF})",
                spend.leaf_index
            )));
        }
    }
    if let Some(additional_coins) = &input.additional_coins {
        for (index, coin) in additional_coins.iter().enumerate() {
            if coin.serial_commitment_data.leaf_index > MAX_LEAF {
                return Err(ClvmZkError::ProofGenerationFailed(format!(
                    "ring coin {index} leaf_index {} exceeds 32-bit platform limit ({MAX_LEAF})",
                    coin.serial_commitment_data.leaf_index
                )));
            }
        }
    }
    Ok(())
}

/// Validate that proof output contains expected values
pub fn validate_proof_output(output: &ProofOutput, backend_name: &str) -> Result<(), ClvmZkError> {
    // Make sure the program actually committed values
    if output.clvm_res.output.is_empty() {
        return Err(ClvmZkError::ProofGenerationFailed(format!(
            "{} proof appears to have exited before commit - no outputs generated",
            backend_name
        )));
    }
    Ok(())
}

/// Validate that nullifier proof output contains expected values
pub fn validate_nullifier_proof_output(
    output: &ProofOutput,
    backend_name: &str,
) -> Result<(), ClvmZkError> {
    // Make sure the program actually committed values
    if output.clvm_res.output.is_empty() && output.nullifiers.is_empty() {
        return Err(ClvmZkError::ProofGenerationFailed(format!(
            "{} proof appears to have exited before commit - no outputs generated",
            backend_name
        )));
    }

    // Make sure nullifiers were actually generated (required for spend proofs)
    if output.nullifiers.is_empty() {
        return Err(ClvmZkError::ProofGenerationFailed(format!(
            "{} proof missing valid nullifiers - execution may have failed",
            backend_name
        )));
    }

    // Check for invalid null nullifiers
    for nullifier in &output.nullifiers {
        if nullifier == &[0u8; 32] {
            return Err(ClvmZkError::ProofGenerationFailed(format!(
                "{} proof contains invalid null nullifier",
                backend_name
            )));
        }
    }

    Ok(())
}
