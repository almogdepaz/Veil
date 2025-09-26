mod common;
use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::chialisp::compile_chialisp_template_hash;
/// Generate valid ECDSA signature data for testing
/// Returns (public_key_bytes, message_bytes, signature_bytes)
pub fn generate_valid_sig_data() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::thread_rng;
    use sha2::{Digest, Sha256};

    // Generate a random ECDSA signing key
    let signing_key = SigningKey::random(&mut thread_rng());
    let verifying_key = signing_key.verifying_key();

    // Get the public key bytes (compressed format for compatibility with CLVM)
    let public_key_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec(); // Compressed

    // Message to sign
    let message = b"test message for agg_sig validation";

    // Hash the message exactly like alice_bob example
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    // Create signature (compact format for CLVM compatibility)
    let signature: Signature = signing_key.sign(&message_hash);
    let signature_bytes = signature.to_bytes().to_vec();

    // Return the message hash (not raw message) to match working alice_bob example
    (public_key_bytes, message_hash.to_vec(), signature_bytes)
}

/// Generate intentionally invalid signature data for negative testing
pub fn generate_invalid_sig_data() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (pk, msg, _) = generate_valid_sig_data();
    // Return all zeros as clearly invalid signature (wrong length and content)
    let invalid_sig = vec![0u8; 64]; // Different length than valid ECDSA signature
    (pk, msg, invalid_sig)
}
/// Test agg_sig_unsafe with valid cryptographic data
#[test]
fn fuzz_agg_sig_unsafe_valid() -> Result<(), Box<dyn std::error::Error>> {
    test_info!("\nTesting agg_sig_unsafe with valid cryptographic data...");

    let (pk_bytes, msg_bytes, sig_bytes) = generate_valid_sig_data();
    test_info!(
        "Generated test data - PK: {} bytes, MSG: {} bytes, SIG: {} bytes",
        pk_bytes.len(),
        msg_bytes.len(),
        sig_bytes.len()
    );

    // The expression uses variables for the byte arrays
    let expr = "(mod (a b c) (agg_sig_unsafe a b c))";
    let params = vec![
        ProgramParameter::from_bytes(&pk_bytes),
        ProgramParameter::from_bytes(&msg_bytes),
        ProgramParameter::from_bytes(&sig_bytes),
    ];

    test_info!("Generating proof for agg_sig_unsafe...");
    let proof_result = ClvmZkProver::prove(expr, &params)
        .map_err(|e| format!("Proof generation failed for valid agg_sig_unsafe: {e}"))?;
    let output = proof_result.clvm_output.result;
    let proof = proof_result.zk_proof;

    test_info!("Verifying proof for agg_sig_unsafe...");
    let program_hash = compile_chialisp_template_hash(expr)
        .map_err(|e| format!("Hash template failed: {:?}", e))?;
    let (verified, _) = ClvmZkProver::verify_proof(program_hash, &proof, Some(&output))
        .map_err(|e| format!("Verification error for agg_sig_unsafe: {e}"))?;

    if !verified {
        return Err("Valid agg_sig_unsafe proof should verify successfully".into());
    }

    test_info!("✓ agg_sig_unsafe with valid crypto data: PASSED");
    test_info!(
        "  Output: {} bytes, Proof: {} bytes",
        output.len(),
        proof.len()
    );

    Ok(())
}

/// Test agg_sig_unsafe with invalid cryptographic data (negative test)
#[test]
fn fuzz_agg_sig_unsafe_invalid() -> Result<(), Box<dyn std::error::Error>> {
    test_info!("\nTesting agg_sig_unsafe with invalid cryptographic data...");

    let (pk_bytes, msg_bytes, invalid_sig_bytes) = generate_invalid_sig_data();
    test_info!(
        "Generated test data - PK: {} bytes, MSG: {} bytes, INVALID_SIG: {} bytes",
        pk_bytes.len(),
        msg_bytes.len(),
        invalid_sig_bytes.len()
    );

    let expr = "(mod (a b c) (agg_sig_unsafe a b c))";
    let params = vec![
        ProgramParameter::from_bytes(&pk_bytes),
        ProgramParameter::from_bytes(&msg_bytes),
        ProgramParameter::from_bytes(&invalid_sig_bytes),
    ];

    test_info!("Attempting proof generation for invalid agg_sig_unsafe...");
    match ClvmZkProver::prove(expr, &params) {
        Ok(proof_result) => {
            let output = proof_result.clvm_output.result;
            let proof = proof_result.zk_proof;
            test_info!("Proof generation succeeded, checking if verification catches the invalid signature...");

            // The proof might succeed but verification should fail or return invalid result
            let program_hash = compile_chialisp_template_hash(expr)
                .map_err(|e| format!("Hash template failed: {:?}", e))?;
            let (verified, _) = ClvmZkProver::verify_proof(program_hash, &proof, Some(&output))
                .map_err(|e| format!("Verification error for invalid agg_sig_unsafe: {e}"))?;

            if verified && !output.is_empty() && output != vec![0u8] {
                return Err(
                    "Invalid agg_sig_unsafe should not produce valid verified result".into(),
                );
            }

            test_info!("✓ Invalid agg_sig_unsafe correctly handled - verification result: {verified}, output: {output:?}");
        }
        Err(e) => {
            test_info!("✓ Invalid agg_sig_unsafe correctly failed at proof generation: {e}");
        }
    }

    Ok(())
}
