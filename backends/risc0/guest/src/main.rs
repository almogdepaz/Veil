#![no_main]

extern crate alloc;
use alloc::vec;

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
    let (output_bytes, mut conditions) = evaluator
        .evaluate_clvm_program(&instance_bytecode)
        .expect("CLVM execution failed");

    // Transform CREATE_COIN conditions for output privacy
    let mut has_transformations = false;
    for condition in conditions.iter_mut() {
        if condition.opcode == 51 {
            // CREATE_COIN opcode
            match condition.args.len() {
                2 => {
                    // Transparent mode: CREATE_COIN(puzzle_hash, amount)
                    // Leave as-is for testing/debugging
                }
                4 => {
                    // Private mode: CREATE_COIN(puzzle_hash, amount, serial_num, serial_rand)
                    let puzzle_hash = &condition.args[0];
                    let amount_bytes = &condition.args[1];
                    let serial_number = &condition.args[2];
                    let serial_randomness = &condition.args[3];

                    // Validate sizes
                    assert_eq!(puzzle_hash.len(), 32, "puzzle_hash must be 32 bytes");
                    assert_eq!(amount_bytes.len(), 8, "amount must be 8 bytes");
                    assert_eq!(serial_number.len(), 32, "serial_number must be 32 bytes");
                    assert_eq!(
                        serial_randomness.len(),
                        32,
                        "serial_randomness must be 32 bytes"
                    );

                    // Parse amount
                    let amount = u64::from_be_bytes(amount_bytes.as_slice().try_into().unwrap());

                    // Compute serial_commitment
                    let serial_domain = b"clvm_zk_serial_v1.0";
                    let mut serial_data = [0u8; 83];
                    serial_data[..19].copy_from_slice(serial_domain);
                    serial_data[19..51].copy_from_slice(serial_number);
                    serial_data[51..83].copy_from_slice(serial_randomness);
                    let serial_commitment = risc0_hasher(&serial_data);

                    // Compute coin_commitment
                    let coin_domain = b"clvm_zk_coin_v1.0";
                    let mut coin_data = [0u8; 89];
                    coin_data[..17].copy_from_slice(coin_domain);
                    coin_data[17..25].copy_from_slice(&amount.to_be_bytes());
                    coin_data[25..57].copy_from_slice(puzzle_hash);
                    coin_data[57..89].copy_from_slice(&serial_commitment);
                    let coin_commitment = risc0_hasher(&coin_data);

                    // Replace args: [puzzle, amount, serial, rand] → [commitment]
                    condition.args = vec![coin_commitment.to_vec()];
                    has_transformations = true;
                }
                n => panic!(
                    "CREATE_COIN must have 2 args (transparent) or 4 args (private), got {}",
                    n
                ),
            }
        }
    }

    // Only re-serialize if we actually transformed something
    let final_output = if has_transformations {
        clvm_zk_core::serialize_conditions_to_bytes(&conditions)
    } else {
        output_bytes
    };

    let nullifier = match private_inputs.serial_commitment_data {
        Some(commitment_data) => {
            let expected_program_hash = commitment_data.program_hash;
            assert_eq!(
                program_hash, expected_program_hash,
                "program_hash mismatch: cannot spend coin with different program"
            );

            let serial_number = commitment_data.serial_number;
            let serial_randomness = commitment_data.serial_randomness;
            let domain = b"clvm_zk_serial_v1.0";
            let mut serial_commit_data = [0u8; 83];
            serial_commit_data[..19].copy_from_slice(domain);
            serial_commit_data[19..51].copy_from_slice(&serial_number);
            serial_commit_data[51..83].copy_from_slice(&serial_randomness);
            let computed_serial_commitment = risc0_hasher(&serial_commit_data);

            let serial_commitment_expected = commitment_data.serial_commitment;
            assert_eq!(
                computed_serial_commitment, serial_commitment_expected,
                "serial commitment verification failed"
            );

            let amount = commitment_data.amount;
            let coin_domain = b"clvm_zk_coin_v1.0";
            let mut coin_data = [0u8; 17 + 8 + 32 + 32];
            coin_data[..17].copy_from_slice(coin_domain);
            coin_data[17..25].copy_from_slice(&amount.to_be_bytes());
            coin_data[25..57].copy_from_slice(&program_hash);
            coin_data[57..89].copy_from_slice(&computed_serial_commitment);
            let computed_coin_commitment = risc0_hasher(&coin_data);

            let coin_commitment_provided = commitment_data.coin_commitment;
            assert_eq!(
                computed_coin_commitment, coin_commitment_provided,
                "coin commitment verification failed"
            );

            let merkle_path = commitment_data.merkle_path;
            let expected_root = commitment_data.merkle_root;
            let leaf_index = commitment_data.leaf_index;

            let mut current_hash = computed_coin_commitment;
            let mut current_index = leaf_index;
            for sibling in merkle_path.iter() {
                let mut combined = [0u8; 64];
                if current_index % 2 == 0 {
                    combined[..32].copy_from_slice(&current_hash);
                    combined[32..].copy_from_slice(sibling);
                } else {
                    combined[..32].copy_from_slice(sibling);
                    combined[32..].copy_from_slice(&current_hash);
                }
                current_hash = risc0_hasher(&combined);
                current_index /= 2;
            }

            let computed_root = current_hash;
            assert_eq!(
                computed_root, expected_root,
                "merkle root mismatch: coin not in current tree state"
            );

            let mut nullifier_data = Vec::with_capacity(72);
            nullifier_data.extend_from_slice(&serial_number);
            nullifier_data.extend_from_slice(&program_hash);
            nullifier_data.extend_from_slice(&amount.to_be_bytes());
            Some(risc0_hasher(&nullifier_data))
        }
        None => None,
    };

    let end_cycles = env::cycle_count();
    let total_cycles = end_cycles.saturating_sub(start_cycles);
    let clvm_output = ClvmResult {
        output: final_output,
        cost: total_cycles,
    };

    env::commit(&ProofOutput {
        program_hash,
        nullifier,
        clvm_res: clvm_output,
        proof_type: 0, // Transaction type (default)
        public_values: vec![],
    });
}
