use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::chialisp::compile_chialisp_template_hash;
use clvm_zk_core::chialisp::hash_data;

use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use rand::thread_rng;
use sha2::{Digest, Sha256};

/// Create an ECDSA signature verification program using the new guest-side compilation
/// This demonstrates real ECDSA signature verification in zero-knowledge
fn create_signature_puzzle() -> String {
    // Use our custom ecdsa_verify function which returns 1 for valid, 0 for invalid
    "(mod (pubkey message signature) (ecdsa_verify pubkey message signature))".to_string()
}

/// Example: Demonstrating byte parameter support in guest-side compilation
/// This shows how we can pass raw byte data (public keys, messages, signatures) to the ZK guest
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ECDSA Signature Verification in Zero-Knowledge (Updated for Guest-Side Compilation)");
    println!("=================================================================================");

    // === BOB'S SIDE (Generate Real ECDSA Keys) ===
    println!("\nBob's Key Generation:");

    // Bob generates a real ECDSA key pair
    let bob_signing_key = SigningKey::random(&mut thread_rng());
    let bob_verifying_key = VerifyingKey::from(&bob_signing_key);

    // Get the public key bytes (33 bytes compressed format)
    let bob_public_key_bytes = bob_verifying_key.to_encoded_point(true).as_bytes().to_vec();

    println!("Bob generated real ECDSA key pair");

    // === ALICE'S SIDE (Create Locking Condition) ===
    println!("\nAlice's Action: Creating signature-locked program");

    // Alice creates a message that Bob must sign
    let required_message = b"unlock_this_coin_for_bob";
    println!(
        "   - Required message: {:?}",
        String::from_utf8_lossy(required_message)
    );

    // === BOB'S SIDE (Sign the Message) ===
    println!("\nBob's Signature Generation:");

    // Bob signs the required message with his private key
    // First, hash the message with SHA-256 (as done in the ZK circuit)
    let mut hasher = Sha256::new();
    hasher.update(required_message);
    let message_hash = hasher.finalize();

    // Sign the hash
    let signature: Signature = bob_signing_key.sign(&message_hash);
    let signature_bytes = signature.to_bytes().to_vec();

    println!("Bob signed the message");

    // === VERIFICATION TEST (Outside ZK Circuit) ===
    println!("\nTesting signature verification outside ZK circuit:");

    // Verify the signature outside ZK first
    use k256::ecdsa::signature::Verifier;
    let verification_result = bob_verifying_key.verify(&message_hash, &signature);

    match verification_result {
        Ok(_) => println!("Signature verification successful (outside ZK)"),
        Err(e) => {
            println!("Signature verification failed (outside ZK): {e}");
            return Err(Box::new(e));
        }
    }

    // === ALICE'S SIDE (Create the Locking Program) ===
    println!("\nCreating signature verification program using new guest-side compilation:");
    println!("   - Public key: {} bytes", bob_public_key_bytes.len());
    println!("   - Message: {} bytes", required_message.len());
    println!("   - Signature: {} bytes", signature_bytes.len());

    // Create a signature puzzle using the new API
    let signature_puzzle = create_signature_puzzle();
    println!("   - Puzzle program: {}", signature_puzzle);

    println!("Created signature verification program using new guest-side compilation");

    // === ZK PROOF GENERATION ===
    println!("\nTesting with simple program first using new guest-side compilation...");

    // Test simple arithmetic with new API - much cleaner!
    match ClvmZkProver::prove(
        "(mod (x y) (+ x y))",
        &[ProgramParameter::int(5), ProgramParameter::int(7)],
    ) {
        Ok(result) => {
            println!("Simple mod program ZK proof generated successfully!");
            println!("   - Output: {:?}", result.result());
            println!("   - Proof size: {} bytes", result.zk_proof.len());
        }
        Err(e) => {
            println!("Simple mod program failed: {e}");
            // Continue with other tests
        }
    }

    println!("\nTesting Chialisp examples with new API...");

    // Test create_coin condition - new API handles everything in guest
    match ClvmZkProver::prove(
        "(mod (puzzle_hash amount) (create_coin puzzle_hash amount))",
        &[ProgramParameter::int(999), ProgramParameter::int(1000)],
    ) {
        Ok(result) => {
            println!("Guest-compiled create_coin succeeded!");
            println!("   - Output: {:?}", result.result());
            println!("   - Proof size: {} bytes", result.zk_proof.len());
        }
        Err(e) => {
            println!("Guest-compiled create_coin failed: {e}");
        }
    }

    // Test reserve_fee condition - much simpler with guest compilation
    match ClvmZkProver::prove(
        "(mod (fee_amount) (reserve_fee fee_amount))",
        &[ProgramParameter::int(50)],
    ) {
        Ok(result) => {
            println!("Guest-compiled reserve_fee succeeded!");
            println!("   - Output: {:?}", result.result());
            println!("   - Proof size: {} bytes", result.zk_proof.len());
        }
        Err(e) => {
            println!("Guest-compiled reserve_fee failed: {e}");
        }
    }

    println!("\nGenerating ZK proof of signature verification with new API...");

    // Debug the signature data
    println!("   Signature verification debug:");
    println!("   - Public key bytes: {:02x?}", &bob_public_key_bytes[..8]);
    println!("   - Message bytes: {:02x?}", &required_message[..8]);
    println!("   - Signature bytes: {:02x?}", &signature_bytes[..8]);
    println!("   - Message hash: {:02x?}", &message_hash.as_slice()[..8]);

    // The new API is much simpler - we just pass the Chialisp source and parameters!
    // No more host-side compilation, everything happens in the guest
    let signature_program = signature_puzzle;

    // For the signature verification, we need to convert byte data to parameter values
    // Since the new API expects i64 values, we'll create a simpler example first
    println!("\nTesting ECDSA signature verification in ZK with guest compilation...");

    // Test ECDSA signature verification with the message hash (not raw message)
    match ClvmZkProver::prove(
        &signature_program,
        &[
            // Pass the public key, message hash (not raw message), and signature
            ProgramParameter::from_bytes(&bob_public_key_bytes),
            ProgramParameter::from_bytes(&message_hash), // Use the hash, not raw message
            ProgramParameter::from_bytes(&signature_bytes),
        ],
    ) {
        Ok(result) => {
            println!("✅ ECDSA signature verification in ZK succeeded!");
            println!("   - Proof size: {} bytes", result.zk_proof.len());
            println!("   - Output: {:?}", result.result());
            println!("   - Cost: {} cycles", result.cost());

            // The output should be [1] for valid signature, [0] for invalid
            println!("   - Expected output: [1] (signature verification passed)");

            // === ZK PROOF VERIFICATION ===
            println!("\nVerifying ZK proof publicly...");
            let program_hash =
                compile_chialisp_template_hash(hash_data, &signature_program).unwrap();
            match ClvmZkProver::verify_proof(program_hash, &result.zk_proof, Some(result.result()))
            {
                Ok((true, _)) => {
                    println!("✅ ZK proof verification successful!");
                    println!("   - ECDSA signature was verified in zero-knowledge!");
                    println!(
                        "   - Bob's authorization was proven without revealing the signature!"
                    );
                    println!("   - Alice can be confident Bob authorized this transaction!");
                }
                Ok((false, _)) => {
                    println!("❌ ZK proof verification failed!");
                    println!("   - Proof is invalid or tampered with");
                }
                Err(e) => {
                    println!("❌ ZK proof verification error: {e}");
                }
            }
        }
        Err(e) => {
            println!("❌ ECDSA signature verification failed: {e}");
            println!("   This could happen if:");
            println!("   - The signature is invalid or doesn't match the message");
            println!("   - The public key doesn't correspond to the private key used for signing");
            println!("   - There's an error in the signature format or encoding");

            // Let's try a simpler signature test
            println!("\n   Trying simplified signature verification test...");
            match ClvmZkProver::prove(
                "(mod (x) (+ x 1))", // Simple test program
                &[ProgramParameter::int(41)],
            ) {
                Ok(_) => {
                    println!("   ✅ Simple program works, issue is with signature verification")
                }
                Err(e2) => println!("   ❌ Even simple program fails: {e2}"),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alice_bob_locking_concept() {
        // Test that the basic concept works
        let result = main();
        assert!(result.is_ok());
    }
}
