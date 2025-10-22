//! Common utilities shared between different zkVM backends

use crate::{ClvmZkError, Input, ProgramParameter, ProofOutput};
use alloc::{format, string::ToString, vec::Vec};
use core::fmt::Display;

/// Prepare inputs for guest-side compilation (old protocol)
pub fn prepare_guest_inputs(
    chialisp_source: &str,
    program_parameters: &[ProgramParameter],
    spend_secret: Option<[u8; 32]>,
) -> Input {
    Input {
        chialisp_source: chialisp_source.to_string(),
        program_parameters: program_parameters.to_vec(),
        spend_secret,
        // Serial commitment protocol fields - default to None for non-spending use cases
        serial_randomness: None,
        merkle_path: None,
        coin_commitment: None,
        serial_commitment: None,
        merkle_root: None,
        puzzle_hash: None,
    }
}

/// Prepare inputs with serial commitment protocol (v2.0)
#[allow(clippy::too_many_arguments)]
pub fn prepare_guest_inputs_with_serial(
    chialisp_source: &str,
    program_parameters: &[ProgramParameter],
    serial_number: [u8; 32],
    serial_randomness: [u8; 32],
    merkle_path: Vec<[u8; 32]>,
    coin_commitment: [u8; 32],
    serial_commitment: [u8; 32],
    merkle_root: [u8; 32],
    puzzle_hash: [u8; 32],
) -> Input {
    Input {
        chialisp_source: chialisp_source.to_string(),
        program_parameters: program_parameters.to_vec(),
        spend_secret: Some(serial_number), // serial_number is used as spend_secret in new protocol
        serial_randomness: Some(serial_randomness),
        merkle_path: Some(merkle_path),
        coin_commitment: Some(coin_commitment),
        serial_commitment: Some(serial_commitment),
        merkle_root: Some(merkle_root),
        puzzle_hash: Some(puzzle_hash),
    }
}

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
    if output.clvm_res.output.is_empty() && output.nullifier.is_none() {
        return Err(ClvmZkError::ProofGenerationFailed(format!(
            "{} proof appears to have exited before commit - no outputs generated",
            backend_name
        )));
    }

    // Make sure nullifier was actually generated (required for spend proofs)
    if output.nullifier.is_none() || output.nullifier == Some([0u8; 32]) {
        return Err(ClvmZkError::ProofGenerationFailed(format!(
            "{} proof missing valid nullifier - execution may have failed",
            backend_name
        )));
    }

    Ok(())
}
