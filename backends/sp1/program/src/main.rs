#![no_main]

use sp1_zkvm::io;

extern crate alloc;

use clvm_zk_core::{
    compile_chialisp_to_bytecode_with_table, generate_nullifier, ClvmEvaluator, ClvmResult, Input,
    ProofOutput, BLS_DST,
};

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine};
use sha2_v09::Sha256 as BLSSha256;

sp1_zkvm::entrypoint!(main);

fn sp1_hasher(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sp1_verify_bls(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    let mut pk_padded = [0u8; 96];
    if public_key_bytes.len() > 96 {
        return Err("invalid public key size - too large (max 96 bytes for BLS12-381 G2)");
    }
    let pk_start = 96 - public_key_bytes.len();
    pk_padded[pk_start..].copy_from_slice(public_key_bytes);

    let mut sig_padded = [0u8; 48];
    if signature_bytes.len() > 48 {
        return Err("invalid signature size - too large (max 48 bytes for BLS12-381 G1)");
    }
    let sig_start = 48 - signature_bytes.len();
    sig_padded[sig_start..].copy_from_slice(signature_bytes);

    let public_key = G2Affine::from_compressed(&pk_padded);
    let public_key = if public_key.is_some().into() {
        public_key.unwrap()
    } else {
        return Err("invalid BLS public key format");
    };

    let signature = G1Affine::from_compressed(&sig_padded);
    let signature = if signature.is_some().into() {
        signature.unwrap()
    } else {
        return Err("invalid BLS signature format");
    };

    let message_point = <G1Projective as HashToCurve<ExpandMsgXmd<BLSSha256>>>::hash_to_curve(
        message_bytes,
        BLS_DST,
    );

    let g2_generator = G2Affine::generator();
    let lhs = pairing(&signature, &g2_generator);
    let rhs = pairing(&message_point.into(), &public_key);

    Ok(lhs == rhs)
}

fn sp1_verify_ecdsa(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    clvm_zk_core::verify_ecdsa_signature_with_hasher(
        sp1_hasher,
        public_key_bytes,
        message_bytes,
        signature_bytes,
    )
}

fn main() {
    let private_inputs: Input = io::read();
    let (instance_bytecode, program_hash, function_table) =
        compile_chialisp_to_bytecode_with_table(
            sp1_hasher,
            &private_inputs.chialisp_source,
            &private_inputs.program_parameters,
        )
        .expect("Chialisp compilation failed");

    let mut evaluator = ClvmEvaluator::new(sp1_hasher, sp1_verify_bls, sp1_verify_ecdsa);
    evaluator.function_table = function_table;
    let (output_bytes, conditions) = evaluator
        .evaluate_clvm_program(&instance_bytecode)
        .expect("CLVM execution failed");

    let computed_nullifier = match private_inputs.spend_secret {
        Some(spend_secret) => generate_nullifier(sp1_hasher, &spend_secret, &program_hash),
        None => [0u8; 32],
    };

    let _validated_conditions = conditions;

    let clvm_output = ClvmResult {
        output: output_bytes,
        cost: 0,
    };

    io::commit(&ProofOutput {
        program_hash,
        nullifier: if private_inputs.spend_secret.is_some() {
            Some(computed_nullifier)
        } else {
            None
        },
        clvm_res: clvm_output,
    });
}
