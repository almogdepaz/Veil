#![no_main]

use sp1_zkvm::io;

extern crate alloc;
use alloc::vec;

use clvm_zk_core::{
    coin_commitment::build_coin_commitment_preimage,
    compile_chialisp_to_bytecode_with_table, process_announcements, ClvmEvaluator, ClvmResult,
    Input, ProofOutput, BLS_DST,
};

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine};
use sha2_v09::Sha256 as BLSSha256;

sp1_zkvm::entrypoint!(main);

struct CoinEvaluation {
    conditions: Vec<clvm_zk_core::Condition>,
    nullifier: Option<[u8; 32]>,
    program_hash: [u8; 32],
}

/// Process a single coin: compile, execute, verify commitment, compute nullifier
fn process_coin(
    chialisp_source: &str,
    program_parameters: &[clvm_zk_core::ProgramParameter],
    serial_commitment_data: Option<&clvm_zk_core::SerialCommitmentData>,
    tail_hash: &[u8; 32],
    evaluator: &mut ClvmEvaluator,
) -> CoinEvaluation {
    let (instance_bytecode, program_hash, function_table) =
        compile_chialisp_to_bytecode_with_table(
            sp1_hasher,
            chialisp_source,
            program_parameters,
        )
        .expect("Chialisp compilation failed");

    evaluator.function_table = function_table;
    let (_, mut conditions) = evaluator
        .evaluate_clvm_program(&instance_bytecode)
        .expect("CLVM execution failed");

    // Transform CREATE_COIN conditions for output privacy
    for condition in conditions.iter_mut() {
        if condition.opcode == 51 && condition.args.len() == 4 {
            // Private mode: CREATE_COIN(puzzle_hash, amount, serial_num, serial_rand)
            let puzzle_hash = &condition.args[0];
            let amount_bytes = &condition.args[1];
            let serial_number = &condition.args[2];
            let serial_randomness = &condition.args[3];

            assert_eq!(puzzle_hash.len(), 32, "puzzle_hash must be 32 bytes");
            assert_eq!(amount_bytes.len(), 8, "amount must be 8 bytes");
            assert_eq!(serial_number.len(), 32, "serial_number must be 32 bytes");
            assert_eq!(serial_randomness.len(), 32, "serial_randomness must be 32 bytes");

            let amount = u64::from_be_bytes(amount_bytes.as_slice().try_into().unwrap());

            // Compute serial_commitment
            let serial_domain = b"clvm_zk_serial_v1.0";
            let mut serial_data = [0u8; 83];
            serial_data[..19].copy_from_slice(serial_domain);
            serial_data[19..51].copy_from_slice(serial_number);
            serial_data[51..83].copy_from_slice(serial_randomness);
            let serial_commitment = sp1_hasher(&serial_data);

            // Compute coin_commitment v2
            let mut puzzle_hash_arr = [0u8; 32];
            puzzle_hash_arr.copy_from_slice(puzzle_hash);
            let coin_data = build_coin_commitment_preimage(
                tail_hash,
                amount,
                &puzzle_hash_arr,
                &serial_commitment,
            );
            let coin_commitment = sp1_hasher(&coin_data);

            // Replace args: [puzzle, amount, serial, rand] → [commitment]
            condition.args = vec![coin_commitment.to_vec()];
        }
    }

    // Compute nullifier if serial commitment data provided
    let nullifier = serial_commitment_data.map(|commitment_data| {
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
        let computed_serial_commitment = sp1_hasher(&serial_commit_data);

        let serial_commitment_expected = commitment_data.serial_commitment;
        assert_eq!(
            computed_serial_commitment, serial_commitment_expected,
            "serial commitment verification failed"
        );

        // Compute coin_commitment v2 using shared function
        let amount = commitment_data.amount;
        let coin_data = build_coin_commitment_preimage(
            tail_hash,
            amount,
            &program_hash,
            &computed_serial_commitment,
        );
        let computed_coin_commitment = sp1_hasher(&coin_data);

        let coin_commitment_provided = commitment_data.coin_commitment;
        assert_eq!(
            computed_coin_commitment, coin_commitment_provided,
            "coin commitment verification failed"
        );

        let merkle_path = &commitment_data.merkle_path;
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
            current_hash = sp1_hasher(&combined);
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
        sp1_hasher(&nullifier_data)
    });

    CoinEvaluation {
        conditions,
        nullifier,
        program_hash,
    }
}

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

    // Get tail_hash for asset type (XCH = [0u8; 32], CAT = hash of TAIL program)
    let tail_hash = private_inputs.tail_hash.unwrap_or([0u8; 32]);

    let mut evaluator = ClvmEvaluator::new(sp1_hasher, sp1_verify_bls, sp1_verify_ecdsa);

    // Process primary coin
    let primary_eval = process_coin(
        &private_inputs.chialisp_source,
        &private_inputs.program_parameters,
        private_inputs.serial_commitment_data.as_ref(),
        &tail_hash,
        &mut evaluator,
    );

    let primary_program_hash = primary_eval.program_hash;
    let mut all_conditions = primary_eval.conditions;
    let mut all_nullifiers = Vec::new();
    if let Some(n) = primary_eval.nullifier {
        all_nullifiers.push(n);
    }

    // Process additional coins (ring spend)
    if let Some(additional_coins) = &private_inputs.additional_coins {
        for additional_coin in additional_coins {
            // Verify all coins in ring share same tail_hash
            assert_eq!(
                additional_coin.tail_hash, tail_hash,
                "all coins in ring must have same tail_hash"
            );

            let coin_eval = process_coin(
                &additional_coin.chialisp_source,
                &additional_coin.program_parameters,
                Some(&additional_coin.serial_commitment_data),
                &tail_hash,
                &mut evaluator,
            );

            // Merge conditions from this coin
            all_conditions.extend(coin_eval.conditions);

            // Add nullifier (additional coins always have serial commitment data)
            if let Some(n) = coin_eval.nullifier {
                all_nullifiers.push(n);
            }
        }
    }

    // Process announcements across ALL coins: verify assertions, suppress from output
    // This is critical for CAT ring verification - all coins' announcements must match
    let all_conditions = process_announcements(
        all_conditions,
        &primary_program_hash,  // puzzle_hash for puzzle announcements
        None,                   // coin_id not available in this context
        sp1_hasher,
    )
    .expect("announcement verification failed");

    // Serialize final conditions (CREATE_COIN transformed, announcements removed)
    let final_output = clvm_zk_core::serialize_conditions_to_bytes(&all_conditions);

    let clvm_output = ClvmResult {
        output: final_output,
        cost: 0,
    };

    io::commit(&ProofOutput {
        program_hash: primary_program_hash,
        nullifiers: all_nullifiers,
        clvm_res: clvm_output,
    });
}
