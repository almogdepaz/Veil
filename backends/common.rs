//! Common utilities shared between different zkVM backends

use clvm_zk_core::{ClvmZkError, Input, ProofOutput, PublicInputs, ProgramParameter};

/// Prepare inputs for guest-side compilation
pub fn prepare_guest_inputs(
    chialisp_source: &str,
    program_parameters: &[ProgramParameter],
    spend_secret: Option<[u8; 32]>,
) -> (PublicInputs, Input) {
    let public_inputs = PublicInputs {};

    // For backward compatibility, extract i64 values for legacy param_values field
    let param_values: Vec<i64> = program_parameters
        .iter()
        .map(|param| match param {
            ProgramParameter::Int(val) => *val as i64,
            ProgramParameter::Bytes(_) => 0i64, // Legacy field, bytes not supported
        })
        .collect();

    let private_inputs = Input {
        chialisp_source: chialisp_source.to_string(),
        program_parameters: program_parameters.to_vec(),
        spend_secret,
        // Legacy fields - will be removed later
        program: vec![],
        args: vec![],
        parameters: vec![],
        param_values, // Legacy compatibility
    };

    (public_inputs, private_inputs)
}

/// Convert proving errors from zkVM into clean user-facing error messages
pub fn convert_proving_error(error: impl std::fmt::Display, backend_name: &str) -> ClvmZkError {
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
    if output.clvm_output.result.is_empty() {
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
    if output.clvm_output.result.is_empty() && output.nullifier.is_none() {
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