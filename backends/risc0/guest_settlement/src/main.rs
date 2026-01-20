#![no_main]

risc0_zkvm::guest::entry!(main);

extern crate alloc;
use alloc::vec::Vec;

use clvm_zk_core::types::ClvmValue;
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// settlement output committed by taker's proof
#[derive(serde::Serialize)]
struct SettlementOutput {
    maker_nullifier: [u8; 32],
    taker_nullifier: [u8; 32],
    maker_change_commitment: [u8; 32], // maker's change (asset A)
    payment_commitment: [u8; 32],      // taker → maker (asset B)
    taker_goods_commitment: [u8; 32],  // maker → taker (asset A)
    taker_change_commitment: [u8; 32], // taker's change (asset B)
}

/// taker's private coin data
#[derive(serde::Deserialize)]
struct TakerCoinData {
    amount: u64,
    puzzle_hash: [u8; 32],
    serial_commitment: [u8; 32],
    serial_number: [u8; 32],
    serial_randomness: [u8; 32],
    merkle_path: Vec<[u8; 32]>,
    leaf_index: usize,
}

/// settlement parameters
#[derive(serde::Deserialize)]
struct SettlementInput {
    /// IMAGE_ID of the standard guest (passed from host to avoid hardcoding)
    standard_guest_image_id: [u8; 32],

    // maker's journal bytes for env::verify() (risc0 composition pattern)
    maker_journal_bytes: Vec<u8>,

    // PRIVATE
    taker_coin: TakerCoinData,
    merkle_root: [u8; 32],
    taker_ephemeral_privkey: [u8; 32],
    taker_goods_puzzle: [u8; 32], // for receiving offered goods (asset A)
    taker_change_puzzle: [u8; 32], // for receiving change (asset B)
    payment_serial: [u8; 32],     // for payment to maker
    payment_rand: [u8; 32],
    goods_serial: [u8; 32], // for taker receiving goods
    goods_rand: [u8; 32],
    change_serial: [u8; 32], // for taker's change
    change_rand: [u8; 32],
    // v2.0 coin commitment format: tail_hash identifies asset type
    taker_tail_hash: [u8; 32], // taker's coin asset (XCH = zeros)
    goods_tail_hash: [u8; 32], // offered goods asset (maker's asset)
}

fn main() {
    let input: SettlementInput = env::read();

    // risc0 proof composition pattern: call env::verify() with journal
    // Use IMAGE_ID from input (passed by host, stays in sync with compiled guest)
    risc0_zkvm::guest::env::verify(input.standard_guest_image_id, &input.maker_journal_bytes)
        .expect("maker's proof verification failed");

    // deserialize maker's journal to extract data (uses risc0's bincode format, not borsh)
    let maker_output: clvm_zk_core::ProofOutput =
        risc0_zkvm::serde::from_slice(&input.maker_journal_bytes)
            .expect("failed to deserialize maker's journal");

    let maker_nullifier = maker_output
        .nullifiers
        .first()
        .copied()
        .expect("maker must have nullifier");

    // parse maker's clvm output: [CREATE_COIN, settlement_terms]
    // expected format: ((51 change_puzzle change_amount change_serial change_rand) (offered requested maker_pubkey))
    // maker's change uses goods_tail_hash since it's the same asset maker started with
    let (maker_change_commitment, offered, requested, maker_pubkey) =
        parse_maker_output(&maker_output.clvm_res.output, &input.goods_tail_hash);

    // 5. verify taker's coin ownership (v2.0 format with tail_hash)
    verify_taker_coin(&input.taker_coin, input.merkle_root, &input.taker_tail_hash);

    // 6. assert taker has enough funds
    assert!(
        input.taker_coin.amount >= requested,
        "taker has insufficient funds"
    );

    // 7. compute ECDH for payment address
    let taker_secret = StaticSecret::from(input.taker_ephemeral_privkey);
    let maker_public = PublicKey::from(maker_pubkey);
    let shared_secret = taker_secret.diffie_hellman(&maker_public);

    // 8. derive payment puzzle from ECDH
    let mut payment_puzzle_data = Vec::new();
    payment_puzzle_data.extend_from_slice(b"ecdh_payment_v1");
    payment_puzzle_data.extend_from_slice(shared_secret.as_bytes());
    let payment_puzzle = Impl::hash_bytes(&payment_puzzle_data);
    let payment_puzzle_bytes: [u8; 32] = payment_puzzle
        .as_bytes()
        .try_into()
        .expect("sha256 digest must be 32 bytes");

    // 9. create payment commitment (taker → maker, asset B = taker's asset)
    let payment_commitment = create_coin_commitment(
        requested,
        &payment_puzzle_bytes,
        &input.payment_serial,
        &input.payment_rand,
        &input.taker_tail_hash,
    );

    // 10. create taker goods commitment (maker → taker, asset A = goods asset)
    let taker_goods_commitment = create_coin_commitment(
        offered,
        &input.taker_goods_puzzle,
        &input.goods_serial,
        &input.goods_rand,
        &input.goods_tail_hash,
    );

    // 11. create taker's change commitment (taker's leftover, asset B = taker's asset)
    let taker_change_amount = input.taker_coin.amount - requested;
    let taker_change_commitment = create_coin_commitment(
        taker_change_amount,
        &input.taker_change_puzzle,
        &input.change_serial,
        &input.change_rand,
        &input.taker_tail_hash,
    );

    // 12. compute taker's nullifier
    // use taker's coin puzzle_hash (not settlement IMAGE_ID)
    let taker_nullifier = compute_nullifier(
        &input.taker_coin.serial_number,
        &input.taker_coin.puzzle_hash,
        input.taker_coin.amount,
    );

    // 13. commit settlement output
    let output = SettlementOutput {
        maker_nullifier,
        taker_nullifier,
        maker_change_commitment,
        payment_commitment,
        taker_goods_commitment,
        taker_change_commitment,
    };

    env::commit(&output);
}

/// parse maker's clvm output to extract change CREATE_COIN and settlement terms
fn parse_maker_output(clvm_output: &[u8], tail_hash: &[u8; 32]) -> ([u8; 32], u64, u64, [u8; 32]) {
    use clvm_zk_core::clvm_parser::ClvmParser;

    // parse CLVM bytecode
    let mut parser = ClvmParser::new(clvm_output);
    let value = parser.parse().expect("failed to parse CLVM output");

    // expected: ((51 change_puzzle change_amount change_serial change_rand) (offered requested maker_pubkey))
    match value {
        ClvmValue::Cons(create_coin_box, settlement_terms_box) => {
            // extract maker_change_commitment from CREATE_COIN (v2.0 format)
            let maker_change_commitment =
                extract_create_coin_commitment(&create_coin_box, tail_hash);

            // extract settlement terms
            let (offered, requested, maker_pubkey) =
                extract_settlement_terms(&settlement_terms_box);

            (maker_change_commitment, offered, requested, maker_pubkey)
        }
        _ => panic!("invalid maker output structure - expected cons pair"),
    }
}

/// extract CREATE_COIN commitment from (51 change_puzzle change_amount change_serial change_rand)
fn extract_create_coin_commitment(create_coin: &ClvmValue, tail_hash: &[u8; 32]) -> [u8; 32] {
    // parse (51 change_puzzle change_amount change_serial change_rand)
    match create_coin {
        ClvmValue::Cons(opcode_box, args_box) => {
            // verify opcode is 51 (CREATE_COIN)
            match opcode_box.as_ref() {
                ClvmValue::Atom(opcode) if opcode.as_slice() == &[51u8] => {
                    // extract (change_puzzle change_amount change_serial change_rand)
                    match args_box.as_ref() {
                        ClvmValue::Cons(puzzle_box, rest1) => {
                            let change_puzzle = extract_bytes_32(puzzle_box.as_ref());

                            match rest1.as_ref() {
                                ClvmValue::Cons(amount_box, rest2) => {
                                    let change_amount = extract_u64(amount_box.as_ref());

                                    match rest2.as_ref() {
                                        ClvmValue::Cons(serial_box, rest3) => {
                                            let change_serial =
                                                extract_bytes_32(serial_box.as_ref());

                                            match rest3.as_ref() {
                                                ClvmValue::Cons(rand_box, _) => {
                                                    let change_rand =
                                                        extract_bytes_32(rand_box.as_ref());

                                                    // compute commitment (v2.0 format)
                                                    create_coin_commitment(
                                                        change_amount,
                                                        &change_puzzle,
                                                        &change_serial,
                                                        &change_rand,
                                                        tail_hash,
                                                    )
                                                }
                                                _ => panic!("invalid CREATE_COIN: missing rand"),
                                            }
                                        }
                                        _ => panic!("invalid CREATE_COIN: missing serial"),
                                    }
                                }
                                _ => panic!("invalid CREATE_COIN: missing amount"),
                            }
                        }
                        _ => panic!("invalid CREATE_COIN: missing puzzle"),
                    }
                }
                _ => panic!("invalid CREATE_COIN opcode"),
            }
        }
        _ => panic!("invalid CREATE_COIN structure"),
    }
}

/// extract settlement terms from (offered requested maker_pubkey)
fn extract_settlement_terms(terms: &ClvmValue) -> (u64, u64, [u8; 32]) {
    match terms {
        ClvmValue::Cons(offered_box, rest1) => {
            let offered = extract_u64(offered_box.as_ref());

            match rest1.as_ref() {
                ClvmValue::Cons(requested_box, rest2) => {
                    let requested = extract_u64(requested_box.as_ref());

                    match rest2.as_ref() {
                        ClvmValue::Cons(pubkey_box, _) => {
                            let maker_pubkey = extract_bytes_32(pubkey_box.as_ref());
                            (offered, requested, maker_pubkey)
                        }
                        _ => panic!("invalid settlement terms: missing maker_pubkey"),
                    }
                }
                _ => panic!("invalid settlement terms: missing requested"),
            }
        }
        _ => panic!("invalid settlement terms structure"),
    }
}

/// extract [u8; 32] from ClvmValue::Atom
fn extract_bytes_32(value: &ClvmValue) -> [u8; 32] {
    match value {
        ClvmValue::Atom(bytes) => {
            if bytes.len() != 32 {
                panic!("expected 32 bytes, got {}", bytes.len());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr
        }
        _ => panic!("expected atom for bytes"),
    }
}

/// extract u64 from ClvmValue::Atom (big-endian encoding)
fn extract_u64(value: &ClvmValue) -> u64 {
    match value {
        ClvmValue::Atom(bytes) => {
            if bytes.is_empty() {
                return 0;
            }
            if bytes.len() > 8 {
                panic!("u64 value too large: {} bytes", bytes.len());
            }

            // CLVM uses big-endian encoding
            let mut result: u64 = 0;
            for &byte in bytes {
                result = (result << 8) | (byte as u64);
            }
            result
        }
        _ => panic!("expected atom for u64"),
    }
}

/// verify taker's coin ownership via merkle membership (v2.0 format with tail_hash)
fn verify_taker_coin(coin: &TakerCoinData, merkle_root: [u8; 32], tail_hash: &[u8; 32]) {
    // 1. verify serial commitment
    let mut serial_commit_data = Vec::new();
    serial_commit_data.extend_from_slice(b"clvm_zk_serial_v1.0");
    serial_commit_data.extend_from_slice(&coin.serial_number);
    serial_commit_data.extend_from_slice(&coin.serial_randomness);
    let computed_serial_commitment = Impl::hash_bytes(&serial_commit_data);
    let computed_serial_bytes: [u8; 32] = computed_serial_commitment
        .as_bytes()
        .try_into()
        .expect("sha256 digest must be 32 bytes");

    assert_eq!(
        computed_serial_bytes, coin.serial_commitment,
        "invalid serial commitment"
    );

    // 2. compute coin_commitment v2.0: domain(17) || tail_hash(32) || amount(8) || puzzle(32) || serial(32)
    let mut coin_commit_data = [0u8; 121];
    coin_commit_data[..17].copy_from_slice(b"clvm_zk_coin_v2.0");
    coin_commit_data[17..49].copy_from_slice(tail_hash);
    coin_commit_data[49..57].copy_from_slice(&coin.amount.to_be_bytes());
    coin_commit_data[57..89].copy_from_slice(&coin.puzzle_hash);
    coin_commit_data[89..121].copy_from_slice(&coin.serial_commitment);
    let coin_commitment_hash = Impl::hash_bytes(&coin_commit_data);
    let coin_commitment: [u8; 32] = coin_commitment_hash
        .as_bytes()
        .try_into()
        .expect("sha256 digest must be 32 bytes");

    // 3. verify merkle membership
    let mut current_hash = coin_commitment;
    let mut index = coin.leaf_index;

    for sibling in &coin.merkle_path {
        let mut concat = Vec::new();
        if index % 2 == 0 {
            concat.extend_from_slice(&current_hash);
            concat.extend_from_slice(sibling);
        } else {
            concat.extend_from_slice(sibling);
            concat.extend_from_slice(&current_hash);
        }
        let hash_result = Impl::hash_bytes(&concat);
        current_hash = hash_result
            .as_bytes()
            .try_into()
            .expect("sha256 digest must be 32 bytes");
        index /= 2;
    }

    assert_eq!(
        current_hash, merkle_root,
        "merkle proof verification failed"
    );
}

/// create coin commitment v2.0: hash(domain || tail_hash || amount || puzzle || serial_commitment)
fn create_coin_commitment(
    amount: u64,
    puzzle: &[u8; 32],
    serial: &[u8; 32],
    rand: &[u8; 32],
    tail_hash: &[u8; 32],
) -> [u8; 32] {
    // first create serial commitment
    let mut serial_commit_data = [0u8; 83];
    serial_commit_data[..19].copy_from_slice(b"clvm_zk_serial_v1.0");
    serial_commit_data[19..51].copy_from_slice(serial);
    serial_commit_data[51..83].copy_from_slice(rand);
    let serial_commitment = Impl::hash_bytes(&serial_commit_data);

    // v2.0 coin commitment: domain(17) || tail_hash(32) || amount(8) || puzzle(32) || serial(32)
    let mut coin_commit_data = [0u8; 121];
    coin_commit_data[..17].copy_from_slice(b"clvm_zk_coin_v2.0");
    coin_commit_data[17..49].copy_from_slice(tail_hash);
    coin_commit_data[49..57].copy_from_slice(&amount.to_be_bytes());
    coin_commit_data[57..89].copy_from_slice(puzzle);
    coin_commit_data[89..121].copy_from_slice(serial_commitment.as_bytes());

    let coin_commitment = Impl::hash_bytes(&coin_commit_data);
    coin_commitment
        .as_bytes()
        .try_into()
        .expect("sha256 digest must be 32 bytes")
}

/// compute nullifier: hash(serial_number || program_hash || amount)
/// matches standard guest nullifier format
fn compute_nullifier(serial_number: &[u8; 32], program_hash: &[u8; 32], amount: u64) -> [u8; 32] {
    let mut nullifier_data = Vec::new();
    nullifier_data.extend_from_slice(serial_number);
    nullifier_data.extend_from_slice(program_hash);
    nullifier_data.extend_from_slice(&amount.to_be_bytes());
    let nullifier = Impl::hash_bytes(&nullifier_data);
    nullifier
        .as_bytes()
        .try_into()
        .expect("sha256 digest must be 32 bytes")
}
