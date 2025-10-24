#![no_main]

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256 as RiscSha256};

use clvm_zk_core::{
    compile_chialisp_to_bytecode_with_table, ClvmEvaluator, ClvmResult, Input, InputWithSerial,
    ProofOutput, BLS_DST,
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

    let private_inputs: InputWithSerial = env::read();
    let (instance_bytecode, program_hash, function_table) =
        compile_chialisp_to_bytecode_with_table(
            risc0_hasher,
            &private_inputs.chialisp_source,
            &private_inputs.program_parameters,
        )
        .expect("Chialisp compilation failed");

    let mut evaluator = ClvmEvaluator::new(risc0_hasher, risc0_verify_bls, risc0_verify_ecdsa);
    evaluator.function_table = function_table;
    let (output_bytes, _conditions) = evaluator
        .evaluate_clvm_program(&instance_bytecode)
        .expect("CLVM execution failed");
    // Serial commitment protocol for spending
    let expected_program_hash = private_inputs.program_hash;
    assert_eq!(
        program_hash, expected_program_hash,
        "program_hash mismatch: cannot spend coin with different program"
    );
    let serial_number = private_inputs.serial_number;
    let serial_randomness = private_inputs.serial_randomness;
    let domain = b"clvm_zk_serial_v1.0";
    let mut commitment_data = [0u8; 83];
    commitment_data[..19].copy_from_slice(domain);
    commitment_data[19..51].copy_from_slice(&serial_number);
    commitment_data[51..83].copy_from_slice(&serial_randomness);
    let computed_serial_commitment = risc0_hasher(&commitment_data);

    let serial_commitment_expected = private_inputs.serial_commitment;
    assert_eq!(
        computed_serial_commitment, serial_commitment_expected,
        "serial commitment verification failed"
    );
    let amount = private_inputs.amount;
    // 3. Reconstruct and verify coin_commitment = hash(domain || program_hash || serial_commitment)
    let coin_domain = b"clvm_zk_coin_v1.0";
    let mut coin_data = [0u8; 17 + 32 + 8 + 32];
    coin_data[..17].copy_from_slice(coin_domain);
    coin_data[17..25].copy_from_slice(&amount.to_be_bytes());
    coin_data[25..57].copy_from_slice(&program_hash);
    coin_data[57..89].copy_from_slice(&computed_serial_commitment);
    let computed_coin_commitment = risc0_hasher(&coin_data);
    let coin_commitment_provided = private_inputs.coin_commitment;
    assert_eq!(
        computed_coin_commitment, coin_commitment_provided,
        "coin commitment verification failed"
    );

    // 4. Verify merkle membership
    let merkle_path = private_inputs.merkle_path;
    let expected_root = private_inputs.merkle_root;
    let leaf_index = private_inputs.leaf_index;

    let mut current_hash = computed_coin_commitment;
    let mut current_index = leaf_index;
    for sibling in merkle_path.iter() {
        let mut combined = [0u8; 64];
        // position-based hashing: if index is even (left child), sibling goes right
        if current_index % 2 == 0 {
            combined[..32].copy_from_slice(&current_hash);
            combined[32..].copy_from_slice(sibling);
        } else {
            combined[..32].copy_from_slice(sibling);
            combined[32..].copy_from_slice(&current_hash);
        }
        current_hash = risc0_hasher(&combined);
        current_index /= 2; // move to parent level
    }

    let computed_root = current_hash;
    assert_eq!(
        computed_root, expected_root,
        "merkle root mismatch: coin not in current tree state"
    );

    // 5. Compute nullifier = hash(serial_number || program_hash)
    // Note: serial_randomness excluded to prevent linkability with coin_commitment
    let mut nullifier_data = Vec::with_capacity(64);
    nullifier_data.extend_from_slice(&serial_number);
    nullifier_data.extend_from_slice(&program_hash);
    let nullifier = risc0_hasher(&nullifier_data);
    let end_cycles = env::cycle_count();
    let total_cycles = end_cycles.saturating_sub(start_cycles);
    let clvm_output = ClvmResult {
        output: output_bytes,
        cost: total_cycles,
    };
    env::commit(&ProofOutput {
        program_hash,
        nullifier: Some(nullifier),
        clvm_res: clvm_output,
    });
}
