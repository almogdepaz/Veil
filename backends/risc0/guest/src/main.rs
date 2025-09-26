#![no_main]

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256 as RiscSha256};

// Use our no-std Chialisp compiler and evaluation engine
use clvm_zk_core::{
    compile_chialisp_to_bytecode, generate_nullifier, ClvmEvaluator, ClvmOutput, Input,
    ProofOutput, PublicInputs,
};

// BLS12-381 cryptographic operations
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine};
use sha2::Sha256;

// RISC0 guest implements all crypto optimizations directly here

risc0_zkvm::guest::entry!(main);

/// RISC0-optimized SHA-256 hash function using precompiles in guest
fn risc0_hash_data_guest(data: &[u8]) -> [u8; 32] {
    let digest = Impl::hash_bytes(data);
    digest
        .as_bytes()
        .try_into()
        .expect("SHA-256 digest should be 32 bytes")
}

/// RISC0 BLS verification using precompiles in guest
fn risc0_verify_bls_signature_guest(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    // Validate input sizes for BLS12-381
    if public_key_bytes.len() != 48 {
        return Err("invalid public key size - expected 48 bytes for BLS12-381");
    }
    if signature_bytes.len() != 96 {
        return Err("invalid signature size - expected 96 bytes for BLS12-381");
    }

    // Parse public key (G2 point - standard BLS12-381 public keys are in G2)
    let public_key = G2Affine::from_compressed(
        public_key_bytes
            .try_into()
            .map_err(|_| "invalid public key length")?,
    );
    let public_key = if public_key.is_some().into() {
        public_key.unwrap()
    } else {
        return Err("invalid BLS public key format");
    };

    // Parse signature (G1 point - standard BLS12-381 signatures are in G1)
    let signature = G1Affine::from_compressed(
        signature_bytes
            .try_into()
            .map_err(|_| "invalid signature length")?,
    );
    let signature = if signature.is_some().into() {
        signature.unwrap()
    } else {
        return Err("invalid BLS signature format");
    };

    // Hash message to G1 point using proper BLS domain separation
    const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    // Hash message using RISC0 optimized hasher first
    let message_hash = risc0_hash_data_guest(message_bytes);

    // Use the Message trait properly with iterator
    let message_parts = [&message_hash[..]];
    let message_point = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        message_parts.iter().copied(),
        DST,
    );

    // Verify using pairing equation: e(signature, g2) = e(message_point, public_key)
    let g2_generator = G2Affine::generator();
    let lhs = pairing(&signature, &g2_generator);
    let rhs = pairing(&message_point.into(), &public_key);

    Ok(lhs == rhs)
}

/// RISC0 ECDSA verification using guest-optimized hasher
fn risc0_verify_ecdsa_signature_guest(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    clvm_zk_core::verify_ecdsa_signature_with_hasher(
        &risc0_hash_data_guest,
        public_key_bytes,
        message_bytes,
        signature_bytes,
    )
}

fn main() {
    // Track performance with cycle counting
    let start_cycles = env::cycle_count();

    // Read public inputs (currently empty)
    let public_inputs: PublicInputs = env::read();

    // Read private inputs with Chialisp source
    let private_inputs: Input = env::read();

    // Compile Chialisp source to bytecode in the guest
    let (instance_bytecode, program_hash) = compile_chialisp_to_bytecode(
        &private_inputs.chialisp_source,
        &private_inputs.program_parameters,
    )
    .expect("Chialisp compilation failed");

    // Create evaluator with RISC0-specific optimized implementations (guest-only)
    let evaluator = ClvmEvaluator::with_backends(
        risc0_hash_data_guest,              // RISC0 SHA-256 precompiles in guest
        risc0_verify_bls_signature_guest,   // RISC0 BLS verification with precompiles in guest
        risc0_verify_ecdsa_signature_guest, // RISC0 ECDSA verification with guest hasher
    );

    // Use program parameters directly (they already support both int and bytes)
    let parameters = private_inputs.program_parameters;

    // Execute the compiled bytecode using evaluator with injected backends
    let (output_bytes, conditions) = evaluator
        .evaluate_clvm_program_with_params(&instance_bytecode, &parameters)
        .expect("CLVM execution failed");

    // Generate nullifier using program hash if needed
    let computed_nullifier = match private_inputs.spend_secret {
        Some(spend_secret) => {
            // Use program hash for nullifier, not instance bytecode
            generate_nullifier(&spend_secret, &program_hash)
        }
        None => [0u8; 32],
    };

    // Conditions are validated internally but not exposed publicly
    let _validated_conditions = conditions;

    let end_cycles = env::cycle_count();
    let total_cycles = end_cycles.saturating_sub(start_cycles);

    let clvm_output = ClvmOutput {
        result: output_bytes,
        cost: total_cycles,
    };

    // Commit result with program hash for verification
    env::commit(&ProofOutput {
        public_inputs,
        program_hash, // Key output for verification
        nullifier: if private_inputs.spend_secret.is_some() {
            Some(computed_nullifier)
        } else {
            None
        },
        clvm_output,
    });
}
