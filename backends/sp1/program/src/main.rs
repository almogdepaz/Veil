#![no_main]

use sp1_zkvm::io;

extern crate alloc;
use alloc::vec;

use clvm_zk_core::{
    compile_chialisp_to_bytecode, compute_coin_commitment, compute_nullifier,
    compute_serial_commitment, create_veil_evaluator, parse_variable_length_amount,
    run_clvm_with_conditions, serialize_params_to_clvm, verify_merkle_proof, ClvmResult, Input,
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

    // Compile chialisp to bytecode using the new VeilEvaluator-compatible compiler
    let (instance_bytecode, program_hash) =
        compile_chialisp_to_bytecode(sp1_hasher, &private_inputs.chialisp_source)
            .expect("Chialisp compilation failed");

    // Create VeilEvaluator with SP1 crypto functions
    let evaluator = create_veil_evaluator(sp1_hasher, sp1_verify_bls, sp1_verify_ecdsa);

    // Serialize parameters to CLVM args format
    let args = serialize_params_to_clvm(&private_inputs.program_parameters);

    // Run CLVM bytecode and parse conditions from output
    let max_cost = 1_000_000_000; // 1 billion cost units
    let (output_bytes, mut conditions) =
        run_clvm_with_conditions(&evaluator, &instance_bytecode, &args, max_cost)
            .expect("CLVM execution failed");

    // ============================================================================
    // BALANCE ENFORCEMENT (critical security check)
    // ============================================================================
    // verify sum(inputs) == sum(outputs) and tail_hash consistency
    // MUST run BEFORE CREATE_COIN transformation (which replaces args)
    clvm_zk_core::enforce_ring_balance(&private_inputs, &conditions)
        .expect("balance enforcement failed");

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
                    let puzzle_hash: &[u8; 32] = condition.args[0]
                        .as_slice()
                        .try_into()
                        .expect("puzzle_hash must be 32 bytes");
                    let amount = parse_variable_length_amount(&condition.args[1])
                        .expect("invalid amount encoding");
                    let serial_number: &[u8; 32] = condition.args[2]
                        .as_slice()
                        .try_into()
                        .expect("serial_number must be 32 bytes");
                    let serial_randomness: &[u8; 32] = condition.args[3]
                        .as_slice()
                        .try_into()
                        .expect("serial_randomness must be 32 bytes");

                    let serial_commitment =
                        compute_serial_commitment(sp1_hasher, serial_number, serial_randomness);

                    let tail_hash = private_inputs.tail_hash.unwrap_or([0u8; 32]);
                    let coin_commitment = compute_coin_commitment(
                        sp1_hasher,
                        tail_hash,
                        amount,
                        puzzle_hash,
                        &serial_commitment,
                    );

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

    let nullifier = match &private_inputs.serial_commitment_data {
        Some(commitment_data) => {
            assert_eq!(
                program_hash, commitment_data.program_hash,
                "program_hash mismatch: cannot spend coin with different program"
            );

            let computed_serial_commitment = compute_serial_commitment(
                sp1_hasher,
                &commitment_data.serial_number,
                &commitment_data.serial_randomness,
            );
            assert_eq!(
                computed_serial_commitment, commitment_data.serial_commitment,
                "serial commitment verification failed"
            );

            let tail_hash = private_inputs.tail_hash.unwrap_or([0u8; 32]);
            let computed_coin_commitment = compute_coin_commitment(
                sp1_hasher,
                tail_hash,
                commitment_data.amount,
                &program_hash,
                &computed_serial_commitment,
            );
            assert_eq!(
                computed_coin_commitment, commitment_data.coin_commitment,
                "coin commitment verification failed"
            );

            verify_merkle_proof(
                sp1_hasher,
                computed_coin_commitment,
                &commitment_data.merkle_path,
                commitment_data.leaf_index,
                commitment_data.merkle_root,
            )
            .expect("merkle root mismatch: coin not in current tree state");

            Some(compute_nullifier(
                sp1_hasher,
                &commitment_data.serial_number,
                &program_hash,
                commitment_data.amount,
            ))
        }
        None => None,
    };

    // collect nullifiers: primary coin + additional coins for ring spends
    let mut nullifiers = nullifier.map(|n| vec![n]).unwrap_or_default();

    // process additional coins for ring spends
    if let Some(additional_coins) = &private_inputs.additional_coins {
        for coin in additional_coins {
            let coin_data = &coin.serial_commitment_data;

            let (_, coin_program_hash) =
                compile_chialisp_to_bytecode(sp1_hasher, &coin.chialisp_source)
                    .expect("additional coin chialisp compilation failed");

            assert_eq!(
                coin_program_hash, coin_data.program_hash,
                "additional coin: program_hash mismatch"
            );

            let computed_serial_commitment = compute_serial_commitment(
                sp1_hasher,
                &coin_data.serial_number,
                &coin_data.serial_randomness,
            );
            assert_eq!(
                computed_serial_commitment, coin_data.serial_commitment,
                "additional coin: serial commitment verification failed"
            );

            let computed_coin_commitment = compute_coin_commitment(
                sp1_hasher,
                coin.tail_hash,
                coin_data.amount,
                &coin_program_hash,
                &computed_serial_commitment,
            );
            assert_eq!(
                computed_coin_commitment, coin_data.coin_commitment,
                "additional coin: coin commitment verification failed"
            );

            verify_merkle_proof(
                sp1_hasher,
                computed_coin_commitment,
                &coin_data.merkle_path,
                coin_data.leaf_index,
                coin_data.merkle_root,
            )
            .expect("additional coin: merkle root mismatch");

            nullifiers.push(compute_nullifier(
                sp1_hasher,
                &coin_data.serial_number,
                &coin_program_hash,
                coin_data.amount,
            ));
        }
    }

    let clvm_output = ClvmResult {
        output: final_output,
        cost: 0,
    };

    io::commit(&ProofOutput {
        program_hash,
        nullifiers,
        clvm_res: clvm_output,
        proof_type: 0, // Transaction type (default)
        public_values: vec![],
    });
}
