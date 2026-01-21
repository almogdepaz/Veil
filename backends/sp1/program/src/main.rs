#![no_main]

use sp1_zkvm::io;

extern crate alloc;
use alloc::vec;

use clvm_zk_core::{
    compile_chialisp_to_bytecode, create_veil_evaluator, run_clvm_with_conditions,
    serialize_params_to_clvm, ClvmResult, Input, ProofOutput, BLS_DST,
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
                    let serial_commitment = sp1_hasher(&serial_data);

                    // Compute coin_commitment (v2.0 format with tail_hash)
                    let coin_domain = b"clvm_zk_coin_v2.0";
                    let tail_hash = private_inputs.tail_hash.unwrap_or([0u8; 32]);
                    let mut coin_data = [0u8; 121];
                    coin_data[..17].copy_from_slice(coin_domain);
                    coin_data[17..49].copy_from_slice(&tail_hash);
                    coin_data[49..57].copy_from_slice(&amount.to_be_bytes());
                    coin_data[57..89].copy_from_slice(puzzle_hash);
                    coin_data[89..121].copy_from_slice(&serial_commitment);
                    let coin_commitment = sp1_hasher(&coin_data);

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

    let nullifier = match &private_inputs.serial_commitment_data {
        Some(commitment_data) => {
            let expected_program_hash = commitment_data.program_hash;
            assert_eq!(
                program_hash, expected_program_hash,
                "program_hash mismatch: cannot spend coin with different program"
            );

            let serial_randomness = commitment_data.serial_randomness;
            let serial_number = commitment_data.serial_number;
            let domain = b"clvm_zk_serial_v1.0";
            let mut serial_commit_data = [0u8; 83];
            serial_commit_data[..19].copy_from_slice(domain);
            serial_commit_data[19..51].copy_from_slice(&serial_number);
            serial_commit_data[51..83].copy_from_slice(&serial_randomness);
            let computed_serial_commitment = sp1_hasher(&serial_commit_data);

            let serial_commitment_expected = commitment_data.serial_commitment;
            assert_eq!(
                computed_serial_commitment, serial_commitment_expected,
                "serial commitment verification failed"
            );

            let amount = commitment_data.amount;
            // v2.0 format: domain(17) || tail_hash(32) || amount_be(8) || puzzle_hash(32) || serial_commitment(32) = 121 bytes
            let coin_domain = b"clvm_zk_coin_v2.0";
            let tail_hash = private_inputs.tail_hash.unwrap_or([0u8; 32]); // XCH = zeros
            let mut coin_data = [0u8; 121];
            coin_data[..17].copy_from_slice(coin_domain);
            coin_data[17..49].copy_from_slice(&tail_hash);
            coin_data[49..57].copy_from_slice(&amount.to_be_bytes());
            coin_data[57..89].copy_from_slice(&program_hash);
            coin_data[89..121].copy_from_slice(&computed_serial_commitment);
            let computed_coin_commitment = sp1_hasher(&coin_data);

            let coin_commitment = commitment_data.coin_commitment;
            assert_eq!(
                computed_coin_commitment, coin_commitment,
                "coin commitment verification failed"
            );

            let merkle_path = &commitment_data.merkle_path;
            let expected_root = &commitment_data.merkle_root;
            let leaf_index = commitment_data.leaf_index;

            let mut current_hash = coin_commitment;
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
                current_hash = sp1_hasher(&combined);
                current_index /= 2;
            }

            let computed_root = current_hash;
            assert_eq!(
                computed_root, *expected_root,
                "merkle root mismatch: coin not in current tree state"
            );

            let mut nullifier_data = Vec::with_capacity(72);
            nullifier_data.extend_from_slice(&serial_number);
            nullifier_data.extend_from_slice(&program_hash);
            nullifier_data.extend_from_slice(&amount.to_be_bytes());
            Some(sp1_hasher(&nullifier_data))
        }
        None => None,
    };

    // collect nullifiers: primary coin + additional coins for ring spends
    let mut nullifiers = nullifier.map(|n| vec![n]).unwrap_or_default();

    // process additional coins for ring spends
    if let Some(additional_coins) = &private_inputs.additional_coins {
        for coin in additional_coins {
            let coin_data = &coin.serial_commitment_data;

            // compile coin's puzzle to get program_hash
            let (_, coin_program_hash) =
                compile_chialisp_to_bytecode(sp1_hasher, &coin.chialisp_source)
                    .expect("additional coin chialisp compilation failed");

            // verify program_hash matches puzzle_hash
            assert_eq!(
                coin_program_hash, coin_data.program_hash,
                "additional coin: program_hash mismatch"
            );

            // verify serial commitment
            let domain = b"clvm_zk_serial_v1.0";
            let mut serial_commit_data = [0u8; 83];
            serial_commit_data[..19].copy_from_slice(domain);
            serial_commit_data[19..51].copy_from_slice(&coin_data.serial_number);
            serial_commit_data[51..83].copy_from_slice(&coin_data.serial_randomness);
            let computed_serial_commitment = sp1_hasher(&serial_commit_data);

            assert_eq!(
                computed_serial_commitment, coin_data.serial_commitment,
                "additional coin: serial commitment verification failed"
            );

            // verify coin commitment (v2.0 format)
            let coin_domain = b"clvm_zk_coin_v2.0";
            let mut coin_commit_data = [0u8; 121];
            coin_commit_data[..17].copy_from_slice(coin_domain);
            coin_commit_data[17..49].copy_from_slice(&coin.tail_hash);
            coin_commit_data[49..57].copy_from_slice(&coin_data.amount.to_be_bytes());
            coin_commit_data[57..89].copy_from_slice(&coin_program_hash);
            coin_commit_data[89..121].copy_from_slice(&computed_serial_commitment);
            let computed_coin_commitment = sp1_hasher(&coin_commit_data);

            assert_eq!(
                computed_coin_commitment, coin_data.coin_commitment,
                "additional coin: coin commitment verification failed"
            );

            // verify merkle proof
            let mut current_hash = computed_coin_commitment;
            let mut current_index = coin_data.leaf_index;
            for sibling in coin_data.merkle_path.iter() {
                let mut combined = [0u8; 64];
                if current_index % 2 == 0 {
                    combined[..32].copy_from_slice(&current_hash);
                    combined[32..].copy_from_slice(sibling);
                } else {
                    combined[..32].copy_from_slice(sibling);
                    combined[32..].copy_from_slice(&current_hash);
                }
                current_hash = sp1_hasher(&combined);
                current_index /= 2;
            }

            assert_eq!(
                current_hash, coin_data.merkle_root,
                "additional coin: merkle root mismatch"
            );

            // compute nullifier for this coin
            let mut nullifier_data = Vec::with_capacity(72);
            nullifier_data.extend_from_slice(&coin_data.serial_number);
            nullifier_data.extend_from_slice(&coin_program_hash);
            nullifier_data.extend_from_slice(&coin_data.amount.to_be_bytes());
            nullifiers.push(sp1_hasher(&nullifier_data));
        }
    }

    // ============================================================================
    // BALANCE ENFORCEMENT (critical security check)
    // ============================================================================
    // verify sum(inputs) == sum(outputs) and tail_hash consistency
    let _ = clvm_zk_core::enforce_ring_balance(&private_inputs, &conditions);

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
