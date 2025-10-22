#![no_main]

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256 as RiscSha256};

use clvm_zk_core::{
    compile_chialisp_to_bytecode_with_table, ClvmEvaluator, ClvmResult, Input, ProofOutput, BLS_DST,
};

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine};
use sha2::Sha256;

risc0_zkvm::guest::entry!(main);

fn risc0_hasher(data: &[u8]) -> [u8; 32] {
    let digest = Impl::hash_bytes(data);
    digest
        .as_bytes()
        .try_into()
        .expect("SHA-256 digest should be 32 bytes")
}

fn risc0_verify_bls(
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

    let message_parts = [message_bytes];
    let message_point = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        message_parts.iter().copied(),
        BLS_DST,
    );

    let g2_generator = G2Affine::generator();
    let lhs = pairing(&signature, &g2_generator);
    let rhs = pairing(&message_point.into(), &public_key);

    Ok(lhs == rhs)
}

fn risc0_verify_ecdsa(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    clvm_zk_core::verify_ecdsa_signature_with_hasher(
        risc0_hasher,
        public_key_bytes,
        message_bytes,
        signature_bytes,
    )
}

fn main() {
    let start_cycles = env::cycle_count();

    let private_inputs: Input = env::read();
    let (instance_bytecode, program_hash, function_table) =
        compile_chialisp_to_bytecode_with_table(
            risc0_hasher,
            &private_inputs.chialisp_source,
            &private_inputs.program_parameters,
        )
        .expect("Chialisp compilation failed");

    let mut evaluator = ClvmEvaluator::new(risc0_hasher, risc0_verify_bls, risc0_verify_ecdsa);
    evaluator.function_table = function_table;
    let (output_bytes, conditions) = evaluator
        .evaluate_clvm_program(&instance_bytecode)
        .expect("CLVM execution failed");

    // Serial commitment protocol for spending (optional)
    let nullifier = if let Some(serial_randomness) = private_inputs.serial_randomness {
        // Verify serial commitment and merkle membership
        let serial_commitment_expected = private_inputs
            .serial_commitment
            .expect("serial_commitment required with serial_randomness");
        let serial_number = private_inputs.spend_secret.expect("serial_number required with serial_randomness");

        let domain = b"clvm_zk_serial_v1.0";
        let mut commitment_data = [0u8; 83];
        commitment_data[..19].copy_from_slice(domain);
        commitment_data[19..51].copy_from_slice(&serial_number);
        commitment_data[51..83].copy_from_slice(&serial_randomness);
        let computed_serial_commitment = risc0_hasher(&commitment_data);

        assert_eq!(
            computed_serial_commitment, serial_commitment_expected,
            "serial commitment verification failed"
        );

        let coin_commitment = private_inputs
            .coin_commitment
            .expect("coin_commitment required");
        let merkle_path = private_inputs.merkle_path.expect("merkle_path required");
        let expected_root = private_inputs.merkle_root.expect("merkle_root required");

        let mut current_hash = coin_commitment;
        for sibling in merkle_path.iter() {
            let mut combined = [0u8; 64];
            if current_hash < *sibling {
                combined[..32].copy_from_slice(&current_hash);
                combined[32..].copy_from_slice(sibling);
            } else {
                combined[..32].copy_from_slice(sibling);
                combined[32..].copy_from_slice(&current_hash);
            }
            current_hash = risc0_hasher(&combined);
        }

        let computed_root = current_hash;
        assert_eq!(
            computed_root, expected_root,
            "merkle root mismatch: coin not in current tree state"
        );

        Some(serial_number)
    } else {
        // No nullifier (e.g., BLS tests, signature verification tests)
        private_inputs.spend_secret
    };

    let _validated_conditions = conditions;

    let end_cycles = env::cycle_count();
    let total_cycles = end_cycles.saturating_sub(start_cycles);

    let clvm_output = ClvmResult {
        output: output_bytes,
        cost: total_cycles,
    };

    env::commit(&ProofOutput {
        program_hash,
        nullifier,
        clvm_res: clvm_output,
    });
}
