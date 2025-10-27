use crate::ProgramParameter;
use clvm_zk_core::chialisp::compile_chialisp_template_hash_default;
use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
/// Signature-enabled puzzle programs for secure spend authorization
///
/// This module provides puzzle programs that require valid ECDSA signatures
/// for spending, enhancing the security of the nullifier protocol.
use sha2::{Digest, Sha256};

/// Generate a puzzle program that requires an ECDSA signature for spending
///
/// The puzzle program will:
/// 1. Verify the provided signature against the public key and spend message
/// 2. Create a coin output if the signature is valid
/// 3. Fail if the signature verification fails
///
/// # Arguments
/// * `public_key_bytes` - The public key that must sign the spend (33 or 65 bytes)
/// * `amount` - The amount of the coin being created
///
/// # Returns
/// * A tuple of (puzzle_program_code, puzzle_hash)
pub fn create_signature_puzzle() -> Result<(String, [u8; 32]), crate::ClvmZkError> {
    // Create a simple puzzle program that requires signature verification
    // This will be used with the hybrid parameter system at spend time
    let program =
        "(mod (pubkey message signature) (agg_sig_unsafe pubkey message signature))".to_string();

    // Generate deterministic puzzle hash from the COMPILED TEMPLATE (matches backend behavior)
    let hash = compile_chialisp_template_hash_default(&program).map_err(|e| {
        crate::ClvmZkError::InvalidProgram(format!(
            "Failed to compile template hash for signature puzzle: {:?}",
            e
        ))
    })?;
    Ok((program, hash))
}

/// Generate a key pair and corresponding signature puzzle for testing
///
/// This creates a complete setup for signature-based spending:
/// - Generates fresh ECDSA key pair
/// - Creates puzzle program requiring signature from that key
/// - Returns all necessary components for testing
///
/// # Arguments
/// * `amount` - The amount of the coin being created
///
/// # Returns
/// * A tuple of (signing_key, verifying_key, puzzle_program, puzzle_hash)
pub fn create_test_signature_setup(
) -> Result<(SigningKey, VerifyingKey, String, [u8; 32]), crate::ClvmZkError> {
    use rand::thread_rng;

    // Generate fresh ECDSA key pair
    let signing_key = SigningKey::random(&mut thread_rng());
    let verifying_key = VerifyingKey::from(&signing_key);

    // Create puzzle program requiring signature from this key
    let (puzzle_program, puzzle_hash) = create_signature_puzzle()?;

    Ok((signing_key, verifying_key, puzzle_program, puzzle_hash))
}

/// Create a valid signature for spending a signature-protected coin
///
/// # Arguments
/// * `signing_key` - The private key to sign with
/// * `message` - The message to sign (typically includes spend details)
///
/// # Returns
/// * The signature bytes in raw 64-byte format (r,s)
pub fn create_spend_signature(signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
    // Hash the message (consistent with ZK circuit behavior)
    let message_hash = Sha256::digest(message);

    // Sign the hash
    let signature: Signature = signing_key.sign(&message_hash);

    // Return in raw 64-byte format for CLVM compatibility
    signature.to_bytes().to_vec()
}

/// Create program parameters for spending a signature-protected coin
///
/// # Arguments
/// * `public_key_bytes` - The public key that must verify the signature
/// * `message` - The message that was signed
/// * `signature_bytes` - The signature bytes
///
/// # Returns
/// * Vector of ProgramParameter for use with the puzzle
pub fn create_signature_spend_params(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Vec<ProgramParameter> {
    vec![
        ProgramParameter::from_bytes(public_key_bytes), // a: public key
        ProgramParameter::from_bytes(message),          // b: message
        ProgramParameter::from_bytes(signature_bytes),  // c: signature
    ]
}

/// Create a password-locked puzzle program
///
/// The puzzle requires the correct password/preimage to spend the coin.
/// It uses SHA256 hash verification: the spender must provide the preimage
/// that hashes to the expected hash.
///
/// # Arguments
/// * `password_hash` - SHA256 hash of the required password
///
/// # Returns
/// * A tuple of (puzzle_program_code, puzzle_hash)
pub fn create_password_puzzle() -> Result<(String, [u8; 32]), crate::ClvmZkError> {
    // Simple puzzle that checks if sha256(provided_password) == expected_hash
    // The puzzle takes one parameter: the password preimage
    let program = "(mod (a b) (= (sha256 a) b))".to_string();
    // Generate deterministic puzzle hash from the COMPILED TEMPLATE (matches backend behavior)
    let hash = compile_chialisp_template_hash_default(&program).map_err(|e| {
        crate::ClvmZkError::InvalidProgram(format!(
            "Failed to compile template hash for password puzzle: {:?}",
            e
        ))
    })?;
    Ok((program, hash))
}

/// Create program parameters for spending a password-protected coin
///
/// # Arguments
/// * `password` - The password preimage
/// * `expected_hash` - The expected SHA256 hash (hardcoded in puzzle)
///
/// # Returns
/// * Vector of ProgramParameter for use with the puzzle  
pub fn create_password_spend_params(
    password: &[u8],
    expected_hash: [u8; 32],
) -> Vec<ProgramParameter> {
    vec![
        ProgramParameter::from_bytes(password), // a: password preimage
        ProgramParameter::from_bytes(&expected_hash), // b: expected hash
    ]
}

/// Helper to create password hash from string
pub fn hash_password(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

/// Create a complete password puzzle program with embedded hash
///
/// This generates a CLVM program that verifies a password preimage against
/// a hardcoded hash. The hash is embedded in the program itself, making
/// the program specific to that password.
///
/// # Arguments
/// * `password` - The password that will unlock this puzzle
///
/// # Returns
/// * Complete CLVM program string with embedded hash
///
/// # Example
/// ```rust
/// use clvm_zk::protocol::create_password_puzzle_program;
/// let program = create_password_puzzle_program("mysecret");
/// // Returns: "(= (sha256 a) 0x2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b)"
/// ```
pub fn create_password_puzzle_program(password: &str) -> String {
    let hash = Sha256::digest(password.as_bytes());
    format!("(= (sha256 a) 0x{})", hex::encode(hash))
}

/// Create parameters for spending a password puzzle
///
/// # Arguments
/// * `password` - The password preimage
///
/// # Returns  
/// * Vector with single parameter containing the password
pub fn create_password_spend_parameters(password: &str) -> Vec<ProgramParameter> {
    vec![ProgramParameter::from_bytes(password.as_bytes())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PrivateCoin;
    use k256::ecdsa::{signature::Verifier, Signature};
    use sha2::{Digest, Sha256};

    #[test]
    fn test_signature_puzzle_creation() {
        // Generate test setup
        let (signing_key, verifying_key, puzzle_program, puzzle_hash) =
            create_test_signature_setup().expect("Failed to create test signature setup");

        // Verify puzzle program contains signature verification
        assert!(puzzle_program.contains("agg_sig_unsafe"));
        assert_eq!(
            puzzle_program,
            "(mod (pubkey message signature) (agg_sig_unsafe pubkey message signature))"
        ); // Proper Chialisp syntax

        // Create a coin with this puzzle
        let _ = [0x42; 32]; // ignored for test
        let _coin = PrivateCoin::new_random(puzzle_hash, 1000);

        // Create a test message and signature
        let message = b"spend_authorization_test";
        let signature_bytes = create_spend_signature(&signing_key, message);

        // Create parameters for spending
        let encoded_point = verifying_key.to_encoded_point(true);
        let public_key_bytes = encoded_point.as_bytes();
        let params = create_signature_spend_params(public_key_bytes, message, &signature_bytes);

        // Verify we have the right number of parameters
        assert_eq!(params.len(), 3);

        // Verify signature can be verified outside ZK
        let message_hash = Sha256::digest(message);
        let signature_array: [u8; 64] = signature_bytes
            .try_into()
            .expect("Signature should be 64 bytes");
        let signature = Signature::from_bytes((&signature_array).into()).unwrap();
        assert!(verifying_key.verify(&message_hash, &signature).is_ok());

        println!("Signature puzzle creation test passed");
    }
}
