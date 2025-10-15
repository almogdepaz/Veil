#![no_main]

use sp1_zkvm::io;

extern crate alloc;

// Use our no-std Chialisp compiler and evaluation engine
use clvm_zk_core::{
    compile_chialisp_to_bytecode_with_table, generate_nullifier, ClvmEvaluator, ClvmResult, Input,
    ProofOutput, BLS_DST,
};

// BLS12-381 cryptographic operations with SP1 precompiles
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine};
use sha2_v09::Sha256 as BLSSha256;

sp1_zkvm::entrypoint!(main);

/// SP1-optimized SHA-256 hash function using standard hasher (SP1 will optimize internally)
fn sp1_hash_data_guest(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SP1 BLS verification using precompiled elliptic curve operations
fn sp1_verify_bls_signature_guest(
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
    let message_point = <G1Projective as HashToCurve<ExpandMsgXmd<BLSSha256>>>::hash_to_curve(
        message_bytes,
        BLS_DST,
    );

    // Verify using pairing equation: e(signature, g2) = e(message_point, public_key)
    let g2_generator = G2Affine::generator();
    let lhs = pairing(&signature, &g2_generator);
    let rhs = pairing(&message_point.into(), &public_key);

    Ok(lhs == rhs)
}

/// SP1 ECDSA verification using SP1-optimized hasher
fn sp1_verify_ecdsa_signature_guest(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    clvm_zk_core::verify_ecdsa_signature_with_hasher(
        sp1_hash_data_guest,
        public_key_bytes,
        message_bytes,
        signature_bytes,
    )
}

fn main() {
    // Read private inputs with Chialisp source
    let private_inputs: Input = io::read();

    // Compile Chialisp source to bytecode WITH function table in the guest
    let (instance_bytecode, program_hash, function_table) =
        compile_chialisp_to_bytecode_with_table(
            sp1_hash_data_guest,
            &private_inputs.chialisp_source,
            &private_inputs.program_parameters,
        )
        .expect("Chialisp compilation failed");

    // Create evaluator with SP1-specific optimized implementations (guest-only)
    let mut evaluator = ClvmEvaluator::new(
        sp1_hash_data_guest,              // SP1 SHA-256 optimization
        sp1_verify_bls_signature_guest,   // SP1 BLS verification with precompiles
        sp1_verify_ecdsa_signature_guest, // SP1 ECDSA verification with optimized hasher
    );
    evaluator.function_table = function_table;

    // Execute the compiled bytecode using evaluator with injected SP1 backends
    let (output_bytes, conditions) = evaluator
        .evaluate_clvm_program(&instance_bytecode)
        .expect("CLVM execution failed");

    // Generate nullifier using program hash if needed
    let computed_nullifier = match private_inputs.spend_secret {
        Some(spend_secret) => {
            // Use program hash for nullifier, not instance bytecode
            generate_nullifier(sp1_hash_data_guest, &spend_secret, &program_hash)
        }
        None => [0u8; 32],
    };

    // Conditions are validated internally but not exposed publicly
    let _validated_conditions = conditions;

    let clvm_output = ClvmResult {
        output: output_bytes,
        cost: 0, // SP1 doesn't have cycle counting like RISC0
    };

    // Commit result with program hash for verification
    io::commit(&ProofOutput {
        program_hash, // Key output for verification
        nullifier: if private_inputs.spend_secret.is_some() {
            Some(computed_nullifier)
        } else {
            None
        },
        clvm_res: clvm_output,
    });
}
