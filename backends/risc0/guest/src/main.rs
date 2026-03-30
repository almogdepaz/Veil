#![no_main]

extern crate alloc;
use alloc::vec;

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256 as RiscSha256};

use clvm_zk_core::{
    compile_chialisp_to_bytecode, compute_coin_commitment, compute_genesis_nullifier,
    compute_nullifier_v2, compute_serial_commitment, create_veil_evaluator, is_clvm_nil,
    parse_variable_length_amount, run_clvm_with_conditions, serialize_params_to_clvm,
    verify_merkle_proof, ClvmResult, CoinMode, Input, ProofOutput, BLS_DST,
};

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine};
use sha2::Sha256;

risc0_zkvm::guest::entry!(main);

// precompiled standard puzzles for performance optimization
// bypasses guest-side compilation for known puzzles (580s -> ~10s improvement)

const DELEGATED_PUZZLE_SOURCE: &str = r#"(mod (offered requested maker_pubkey change_amount change_puzzle change_serial change_rand)
  (c
    (c 51 (c change_puzzle (c change_amount (c change_serial (c change_rand ())))))
    (c offered (c requested (c maker_pubkey ())))
  )
)"#;

const DELEGATED_PUZZLE_BYTECODE: &[u8] = &[
    0xff, 0x02, 0xff, 0xff, 0x01, 0xff, 0x04, 0xff, 0xff, 0x04, 0xff, 0xff, 0x01, 0x33, 0xff, 0xff,
    0x04, 0xff, 0x5f, 0xff, 0xff, 0x04, 0xff, 0x2f, 0xff, 0xff, 0x04, 0xff, 0x82, 0x00, 0xbf, 0xff,
    0xff, 0x04, 0xff, 0x82, 0x01, 0x7f, 0xff, 0xff, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xff,
    0xff, 0x04, 0xff, 0x05, 0xff, 0xff, 0x04, 0xff, 0x0b, 0xff, 0xff, 0x04, 0xff, 0x17, 0xff, 0xff,
    0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0xff, 0xff, 0x04, 0xff, 0xff, 0x01, 0x80, 0xff, 0x01, 0x80,
    0x80,
];

const DELEGATED_PUZZLE_HASH: [u8; 32] = [
    0x26, 0x24, 0x38, 0x09, 0xc2, 0x14, 0xb0, 0x80, 0x00, 0x4c, 0x48, 0x36, 0x05, 0x75, 0x7a, 0xa7,
    0xb3, 0xfc, 0xd5, 0x24, 0x34, 0xad, 0xd2, 0x4f, 0xe8, 0x20, 0x69, 0x7b, 0xfd, 0x8a, 0x63, 0x81,
];

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

    // // PROFILING: measure compilation cycles
    // let compile_start = env::cycle_count();

    // optimize: check if this is a known precompiled puzzle
    // avoids expensive guest-side compilation for standard puzzles
    let (instance_bytecode, program_hash) =
        if private_inputs.chialisp_source == DELEGATED_PUZZLE_SOURCE {
            // use precompiled bytecode - saves ~500-570s of compilation time
            (DELEGATED_PUZZLE_BYTECODE.to_vec(), DELEGATED_PUZZLE_HASH)
        } else {
            // compile chialisp to bytecode for custom puzzles
            compile_chialisp_to_bytecode(risc0_hasher, &private_inputs.chialisp_source)
                .expect("Chialisp compilation failed")
        };

    // let compile_cycles = env::cycle_count().saturating_sub(compile_start);

    // Create VeilEvaluator with RISC-0 crypto functions
    let evaluator = create_veil_evaluator(risc0_hasher, risc0_verify_bls, risc0_verify_ecdsa);

    // Serialize parameters to CLVM args format
    let args = serialize_params_to_clvm(&private_inputs.program_parameters);

    // // PROFILING: measure execution cycles
    // let exec_start = env::cycle_count();

    // Run CLVM bytecode and parse conditions from output
    let max_cost = 1_000_000_000; // 1 billion cost units
    let (output_bytes, mut conditions) =
        run_clvm_with_conditions(&evaluator, &instance_bytecode, &args, max_cost)
            .expect("CLVM execution failed");

    // let exec_cycles = env::cycle_count().saturating_sub(exec_start);

    // ============================================================================
    // BALANCE ENFORCEMENT (critical security check)
    // ============================================================================
    // verify sum(inputs) == sum(outputs) and tail_hash consistency
    // MUST run BEFORE CREATE_COIN transformation (which replaces args)
    // skipped for Mint: no input coin, balance enforced by TAIL program instead
    if !matches!(private_inputs.coin_mode, CoinMode::Mint(_)) {
        clvm_zk_core::enforce_ring_balance(&private_inputs, &conditions)
            .expect("balance enforcement failed");
    }

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
                        compute_serial_commitment(risc0_hasher, serial_number, serial_randomness);

                    let tail_hash = private_inputs.tail_hash.unwrap_or([0u8; 32]);
                    let coin_commitment = compute_coin_commitment(
                        risc0_hasher,
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

    let nullifier = match &private_inputs.coin_mode {
        CoinMode::Spend(commitment_data) => {
            assert_eq!(
                program_hash, commitment_data.program_hash,
                "program_hash mismatch: cannot spend coin with different program"
            );

            let computed_serial_commitment = compute_serial_commitment(
                risc0_hasher,
                &commitment_data.serial_number,
                &commitment_data.serial_randomness,
            );
            assert_eq!(
                computed_serial_commitment, commitment_data.serial_commitment,
                "serial commitment verification failed"
            );

            let tail_hash = private_inputs.tail_hash.unwrap_or([0u8; 32]);
            let computed_coin_commitment = compute_coin_commitment(
                risc0_hasher,
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
                risc0_hasher,
                computed_coin_commitment,
                &commitment_data.merkle_path,
                usize::try_from(commitment_data.leaf_index)
                    .expect("leaf_index exceeds usize — tree larger than platform supports"),
                commitment_data.merkle_root,
            )
            .expect("merkle root mismatch: coin not in current tree state");

            // TAIL enforcement: run for all CAT coins (tail_hash != [0;32])
            // tail_hash is committed in the coin commitment, so we verify the
            // provided tail_source compiles to that exact hash, then execute it.
            let effective_tail_hash = private_inputs.tail_hash.unwrap_or([0u8; 32]);
            if effective_tail_hash != [0u8; 32] {
                let tail_src = private_inputs.tail_source
                    .as_deref()
                    .expect("CAT spend requires tail_source: tail_hash is committed but tail_source was not provided");

                let (tail_bytecode, tail_program_hash) =
                    compile_chialisp_to_bytecode(risc0_hasher, tail_src)
                        .expect("TAIL program compilation failed");

                assert_eq!(
                    tail_program_hash, effective_tail_hash,
                    "tail_hash mismatch: tail_source does not compile to the committed tail_hash"
                );

                let tail_args = serialize_params_to_clvm(&private_inputs.tail_params);
                let (tail_output, _) =
                    run_clvm_with_conditions(&evaluator, &tail_bytecode, &tail_args, max_cost)
                        .expect("TAIL authorization failed: TAIL program rejected this CAT spend");
                assert!(
                    !is_clvm_nil(&tail_output),
                    "TAIL authorization failed: TAIL returned nil/0 — must return a truthy value to authorize"
                );
            }

            Some(compute_nullifier_v2(
                risc0_hasher,
                &tail_hash,
                &commitment_data.serial_number,
                &program_hash,
                commitment_data.amount,
            ))
        }
        CoinMode::Execute => None,
        CoinMode::Mint(mint_data) => {
            // Step 1: compile tail_source and verify hash matches private_inputs.tail_hash
            let (tail_bytecode, tail_program_hash) =
                compile_chialisp_to_bytecode(risc0_hasher, &mint_data.tail_source)
                    .expect("TAIL compilation failed");

            if let Some(expected_tail_hash) = private_inputs.tail_hash {
                assert_eq!(
                    tail_program_hash, expected_tail_hash,
                    "tail_hash mismatch: tail_source does not compile to the committed tail_hash"
                );
            }

            // Step 2: execute TAIL — must return truthy to authorize mint
            let tail_args = serialize_params_to_clvm(&mint_data.tail_params);
            let (tail_output, _) =
                run_clvm_with_conditions(&evaluator, &tail_bytecode, &tail_args, max_cost)
                    .expect("TAIL execution failed");
            assert!(
                !is_clvm_nil(&tail_output),
                "TAIL authorization failed: TAIL returned nil — must return truthy to authorize mint"
            );

            // Step 3: handle genesis coin (single-issuance enforcement)
            let genesis_nullifier = if let Some(genesis) = &mint_data.genesis_coin {
                let computed_serial = compute_serial_commitment(
                    risc0_hasher,
                    &genesis.serial_number,
                    &genesis.serial_randomness,
                );
                assert_eq!(
                    computed_serial, genesis.serial_commitment,
                    "genesis coin: serial commitment verification failed"
                );

                let computed_coin = compute_coin_commitment(
                    risc0_hasher,
                    genesis.tail_hash,
                    genesis.amount,
                    &genesis.puzzle_hash,
                    &computed_serial,
                );
                assert_eq!(
                    computed_coin, genesis.coin_commitment,
                    "genesis coin: coin commitment verification failed"
                );

                verify_merkle_proof(
                    risc0_hasher,
                    computed_coin,
                    &genesis.merkle_path,
                    usize::try_from(genesis.leaf_index)
                        .expect("genesis leaf_index exceeds usize"),
                    genesis.merkle_root,
                )
                .expect("genesis coin merkle verification failed");

                Some(compute_genesis_nullifier(
                    risc0_hasher,
                    &genesis.serial_number,
                    &genesis.tail_hash,
                ))
            } else {
                None
            };

            // Steps 4-6: compute output serial_commitment and coin_commitment
            let output_serial_commitment = compute_serial_commitment(
                risc0_hasher,
                &mint_data.output_serial,
                &mint_data.output_rand,
            );
            let tail_hash = private_inputs.tail_hash.unwrap_or(tail_program_hash);
            let output_coin_commitment = compute_coin_commitment(
                risc0_hasher,
                tail_hash,
                mint_data.output_amount,
                &mint_data.output_puzzle_hash,
                &output_serial_commitment,
            );

            // Step 7: emit — genesis_nullifier in nullifiers, coin_commitment in public_values
            let nullifiers = genesis_nullifier.map(|n| vec![n]).unwrap_or_default();
            let end_cycles = env::cycle_count();
            let total_cycles = end_cycles.saturating_sub(start_cycles);
            env::commit(&ProofOutput {
                program_hash,
                nullifiers,
                clvm_res: ClvmResult {
                    output: final_output,
                    cost: total_cycles,
                },
                proof_type: 3, // Mint
                public_values: vec![output_coin_commitment.to_vec()],
            });
            return;
        }
    };

    // collect nullifiers: primary coin + additional coins for ring spends
    let mut nullifiers = nullifier.map(|n| vec![n]).unwrap_or_default();

    // process additional coins for ring spends
    if let Some(additional_coins) = &private_inputs.additional_coins {
        for coin in additional_coins {
            let coin_data = &coin.serial_commitment_data;

            // optimize: check if this coin uses a precompiled puzzle
            let coin_program_hash = if coin.chialisp_source == DELEGATED_PUZZLE_SOURCE {
                DELEGATED_PUZZLE_HASH
            } else {
                let (_, hash) = compile_chialisp_to_bytecode(risc0_hasher, &coin.chialisp_source)
                    .expect("additional coin chialisp compilation failed");
                hash
            };

            assert_eq!(
                coin_program_hash, coin_data.program_hash,
                "additional coin: program_hash mismatch"
            );

            let computed_serial_commitment = compute_serial_commitment(
                risc0_hasher,
                &coin_data.serial_number,
                &coin_data.serial_randomness,
            );
            assert_eq!(
                computed_serial_commitment, coin_data.serial_commitment,
                "additional coin: serial commitment verification failed"
            );

            let computed_coin_commitment = compute_coin_commitment(
                risc0_hasher,
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
                risc0_hasher,
                computed_coin_commitment,
                &coin_data.merkle_path,
                usize::try_from(coin_data.leaf_index)
                    .expect("leaf_index exceeds usize — tree larger than platform supports"),
                coin_data.merkle_root,
            )
            .expect("additional coin: merkle root mismatch");

            // TAIL enforcement for ring coins: same rules as primary coin
            if coin.tail_hash != [0u8; 32] {
                let ring_tail_src = coin.tail_source
                    .as_deref()
                    .expect("CAT ring coin requires tail_source: tail_hash is committed but tail_source was not provided");

                let (ring_tail_bytecode, ring_tail_program_hash) =
                    compile_chialisp_to_bytecode(risc0_hasher, ring_tail_src)
                        .expect("ring coin TAIL compilation failed");

                assert_eq!(
                    ring_tail_program_hash, coin.tail_hash,
                    "ring coin tail_hash mismatch: tail_source does not compile to the committed tail_hash"
                );

                let ring_tail_args = serialize_params_to_clvm(&coin.tail_params);
                let (ring_tail_output, _) = run_clvm_with_conditions(
                    &evaluator,
                    &ring_tail_bytecode,
                    &ring_tail_args,
                    max_cost,
                )
                .expect("ring coin TAIL authorization failed");
                assert!(
                    !is_clvm_nil(&ring_tail_output),
                    "ring coin TAIL authorization failed: TAIL returned nil/0 — must return a truthy value to authorize"
                );
            }

            nullifiers.push(compute_nullifier_v2(
                risc0_hasher,
                &coin.tail_hash,
                &coin_data.serial_number,
                &coin_program_hash,
                coin_data.amount,
            ));
        }
    }

    let end_cycles = env::cycle_count();
    let total_cycles = end_cycles.saturating_sub(start_cycles);
    let clvm_output = ClvmResult {
        output: final_output,
        cost: total_cycles,
    };

    // // PROFILING: encode cycle counts in public_values for analysis
    // // format: single vec containing [compile_cycles (8 bytes), exec_cycles (8 bytes), total_cycles (8 bytes)]
    // let mut profiling_data = Vec::new();
    // profiling_data.extend_from_slice(&compile_cycles.to_le_bytes());
    // profiling_data.extend_from_slice(&exec_cycles.to_le_bytes());
    // profiling_data.extend_from_slice(&total_cycles.to_le_bytes());

    env::commit(&ProofOutput {
        program_hash,
        nullifiers,
        clvm_res: clvm_output,
        proof_type: 0, // Transaction type (default)
        public_values: vec![],
    });
}
