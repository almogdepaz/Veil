#![no_main]

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256 as RiscSha256};

// Use our no-std Chialisp compiler and evaluation engine
use clvm_zk_core::{
    compile_chialisp_to_bytecode_with_table, generate_nullifier, ClvmEvaluator, ClvmResult, Input,
    ProofOutput, BLS_DST,
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
    // Pad public key to 96 bytes if shorter (CLVM may strip leading zeros)
    // G2 public keys are 96 bytes compressed
    let mut pk_padded = [0u8; 96];
    if public_key_bytes.len() > 96 {
        return Err("invalid public key size - too large (max 96 bytes for BLS12-381 G2)");
    }
    let pk_start = 96 - public_key_bytes.len();
    pk_padded[pk_start..].copy_from_slice(public_key_bytes);

    // Pad signature to 48 bytes if shorter (CLVM may strip leading zeros)
    // G1 signatures are 48 bytes compressed
    let mut sig_padded = [0u8; 48];
    if signature_bytes.len() > 48 {
        return Err("invalid signature size - too large (max 48 bytes for BLS12-381 G1)");
    }
    let sig_start = 48 - signature_bytes.len();
    sig_padded[sig_start..].copy_from_slice(signature_bytes);

    // parse public key (g2)
    let public_key = G2Affine::from_compressed(&pk_padded);
    let public_key = if public_key.is_some().into() {
        public_key.unwrap()
    } else {
        return Err("invalid BLS public key format");
    };

    // parse signature (g1)
    let signature = G1Affine::from_compressed(&sig_padded);
    let signature = if signature.is_some().into() {
        signature.unwrap()
    } else {
        return Err("invalid BLS signature format");
    };

    // hash message directly to curve (no pre-hashing)
    let message_parts = [message_bytes];
    let message_point = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        message_parts.iter().copied(),
        BLS_DST,
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
        risc0_hash_data_guest,
        public_key_bytes,
        message_bytes,
        signature_bytes,
    )
}

fn main() {
    // Track performance with cycle counting
    let start_cycles = env::cycle_count();

    // Read private inputs with Chialisp source
    let private_inputs: Input = env::read();

    // Compile Chialisp source to bytecode WITH function table in the guest
    let (instance_bytecode, program_hash, function_table) =
        compile_chialisp_to_bytecode_with_table(
            risc0_hash_data_guest,
            &private_inputs.chialisp_source,
            &private_inputs.program_parameters,
        )
        .expect("Chialisp compilation failed");

    // Create evaluator with RISC0-specific optimized implementations (guest-only)
    let mut evaluator = ClvmEvaluator::new(
        risc0_hash_data_guest,              // RISC0 SHA-256 precompiles in guest
        risc0_verify_bls_signature_guest,   // RISC0 BLS verification with precompiles in guest
        risc0_verify_ecdsa_signature_guest, // RISC0 ECDSA verification with guest hasher
    );
    evaluator.function_table = function_table;

    // Execute the compiled bytecode using evaluator with injected backends
    let (output_bytes, conditions) = evaluator
        .evaluate_clvm_program(&instance_bytecode)
        .expect("CLVM execution failed");

    // Generate nullifier using program hash if needed
    let computed_nullifier = match private_inputs.spend_secret {
        Some(spend_secret) => {
            // Use program hash for nullifier, not instance bytecode
            generate_nullifier(risc0_hash_data_guest, &spend_secret, &program_hash)
        }
        None => [0u8; 32],
    };

    // Conditions are validated internally but not exposed publicly
    let _validated_conditions = conditions;

    let end_cycles = env::cycle_count();
    let total_cycles = end_cycles.saturating_sub(start_cycles);

    let clvm_output = ClvmResult {
        output: output_bytes,
        cost: total_cycles,
    };

    // Commit result with program hash for verification
    env::commit(&ProofOutput {
        program_hash, // Key output for verification
        nullifier: if private_inputs.spend_secret.is_some() {
            Some(computed_nullifier)
        } else {
            None
        },
        clvm_res: clvm_output,
    });
}
