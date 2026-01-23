#![no_main]

risc0_zkvm::guest::entry!(main);

extern crate alloc;
use alloc::vec::Vec;

use clvm_zk_core::{
    compute_coin_commitment, compute_nullifier, compute_serial_commitment, verify_merkle_proof,
};
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

fn risc0_hasher(data: &[u8]) -> [u8; 32] {
    Impl::hash_bytes(data)
        .as_bytes()
        .try_into()
        .expect("sha256 digest must be 32 bytes")
}

/// settlement output committed by taker's proof
/// maker_pubkey is PUBLIC so validator can check it matches the offer
#[derive(serde::Serialize)]
struct SettlementOutput {
    maker_nullifier: [u8; 32],
    taker_nullifier: [u8; 32],
    maker_change_commitment: [u8; 32], // maker's change (asset A)
    payment_commitment: [u8; 32],      // taker → maker (asset B)
    taker_goods_commitment: [u8; 32],  // maker → taker (asset A)
    taker_change_commitment: [u8; 32], // taker's change (asset B)
    // PUBLIC: validator checks this matches offer's maker_pubkey
    maker_pubkey: [u8; 32],
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
    // maker's proof outputs (PUBLIC, extracted by host from verified journal)
    maker_nullifier: [u8; 32],
    maker_change_commitment: [u8; 32],
    offered: u64,
    requested: u64,
    maker_pubkey: [u8; 32],

    // PRIVATE
    taker_coin: TakerCoinData,
    merkle_root: [u8; 32],
    // hash-based stealth: nonce instead of ephemeral privkey
    // payment_puzzle = hash("stealth_v1" || maker_pubkey || nonce)
    // host encrypts nonce to maker_pubkey, includes in tx for maker to decrypt
    payment_nonce: [u8; 32],
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
    // let start_cycles = env::cycle_count();

    let input: SettlementInput = env::read();
    // let read_cycles = env::cycle_count();

    // V2 optimization: maker's proof outputs extracted by HOST (not in guest)
    // Host deserializes maker's journal and extracts these values
    // Guest receives them as simple public inputs, no deserialization overhead
    // Validator verifies maker's proof separately to ensure these values are correct
    let maker_nullifier = input.maker_nullifier;
    let maker_change_commitment = input.maker_change_commitment;
    let offered = input.offered;
    let requested = input.requested;
    let maker_pubkey = input.maker_pubkey;

    // verify taker's coin ownership (v2.0 format with tail_hash)
    verify_taker_coin(&input.taker_coin, input.merkle_root, &input.taker_tail_hash);
    // let verify_cycles = env::cycle_count();

    // assert taker has enough funds
    assert!(
        input.taker_coin.amount >= requested,
        "taker has insufficient funds"
    );

    // HASH-BASED STEALTH ADDRESS (replaces ECDH - ~10K cycles vs ~2M cycles)
    // payment_puzzle = sha256("stealth_v1" || maker_pubkey || nonce)
    // - maker_pubkey is from the offer (public, validated by blockchain)
    // - nonce is random, encrypted to maker_pubkey by host (outside zkVM)
    // - maker decrypts nonce from tx metadata to derive same puzzle
    let mut payment_puzzle_data = [0u8; 74]; // 10 + 32 + 32
    payment_puzzle_data[..10].copy_from_slice(b"stealth_v1");
    payment_puzzle_data[10..42].copy_from_slice(&maker_pubkey);
    payment_puzzle_data[42..74].copy_from_slice(&input.payment_nonce);
    let payment_puzzle = Impl::hash_bytes(&payment_puzzle_data);
    let payment_puzzle_bytes: [u8; 32] = payment_puzzle
        .as_bytes()
        .try_into()
        .expect("sha256 digest must be 32 bytes");
    // let stealth_cycles = env::cycle_count();

    // create payment commitment (taker → maker, asset B = taker's asset)
    let payment_commitment = create_coin_commitment(
        requested,
        &payment_puzzle_bytes,
        &input.payment_serial,
        &input.payment_rand,
        &input.taker_tail_hash,
    );

    // create taker goods commitment (maker → taker, asset A = goods asset)
    let taker_goods_commitment = create_coin_commitment(
        offered,
        &input.taker_goods_puzzle,
        &input.goods_serial,
        &input.goods_rand,
        &input.goods_tail_hash,
    );

    // create taker's change commitment (taker's leftover, asset B = taker's asset)
    let taker_change_amount = input.taker_coin.amount - requested;
    let taker_change_commitment = create_coin_commitment(
        taker_change_amount,
        &input.taker_change_puzzle,
        &input.change_serial,
        &input.change_rand,
        &input.taker_tail_hash,
    );
    // let commitments_cycles = env::cycle_count();

    // compute taker's nullifier
    let taker_nullifier = compute_nullifier(
        risc0_hasher,
        &input.taker_coin.serial_number,
        &input.taker_coin.puzzle_hash,
        input.taker_coin.amount,
    );

    // let end_cycles = env::cycle_count();

    // // PROFILING: log cycle breakdown
    // let total_cycles = end_cycles.saturating_sub(start_cycles);
    // let read_delta = read_cycles.saturating_sub(start_cycles);
    // let verify_delta = verify_cycles.saturating_sub(read_cycles);
    // let stealth_delta = stealth_cycles.saturating_sub(verify_cycles);
    // let commitments_delta = commitments_cycles.saturating_sub(stealth_cycles);
    // let nullifier_delta = end_cycles.saturating_sub(commitments_cycles);
    //
    // risc0_zkvm::guest::env::log(&alloc::format!(
    //     "SETTLEMENT_PROFILING: total={}K read={}K verify={}K stealth={}K commits={}K nullifier={}K",
    //     total_cycles / 1_000,
    //     read_delta / 1_000,
    //     verify_delta / 1_000,
    //     stealth_delta / 1_000,
    //     commitments_delta / 1_000,
    //     nullifier_delta / 1_000,
    // ));

    // commit settlement output
    // maker_pubkey is PUBLIC so validator can assert it matches offer
    let output = SettlementOutput {
        maker_nullifier,
        taker_nullifier,
        maker_change_commitment,
        payment_commitment,
        taker_goods_commitment,
        taker_change_commitment,
        maker_pubkey, // echoed for validation
    };

    env::commit(&output);
}

/// verify taker's coin ownership via merkle membership (v2.0 format with tail_hash)
fn verify_taker_coin(coin: &TakerCoinData, merkle_root: [u8; 32], tail_hash: &[u8; 32]) {
    let start = env::cycle_count();

    // 1. verify serial commitment using clvm_zk_core (optimized fixed-size arrays)
    let computed_serial =
        compute_serial_commitment(risc0_hasher, &coin.serial_number, &coin.serial_randomness);
    let serial_cycles = env::cycle_count();

    assert_eq!(
        computed_serial, coin.serial_commitment,
        "invalid serial commitment"
    );

    // 2. compute coin_commitment using clvm_zk_core (optimized fixed-size arrays)
    let coin_commitment = compute_coin_commitment(
        risc0_hasher,
        *tail_hash,
        coin.amount,
        &coin.puzzle_hash,
        &computed_serial,
    );
    let coin_commit_cycles = env::cycle_count();

    // 3. verify merkle membership using clvm_zk_core (optimized fixed-size arrays)
    verify_merkle_proof(
        risc0_hasher,
        coin_commitment,
        &coin.merkle_path,
        coin.leaf_index,
        merkle_root,
    )
    .expect("merkle proof verification failed");

    let merkle_cycles = env::cycle_count();

    risc0_zkvm::guest::env::log(&alloc::format!(
        "verify_taker_coin: serial={}K coin_commit={}K merkle={}K total={}K",
        (serial_cycles - start) / 1000,
        (coin_commit_cycles - serial_cycles) / 1000,
        (merkle_cycles - coin_commit_cycles) / 1000,
        (merkle_cycles - start) / 1000,
    ));
}

/// create coin commitment v2.0: hash(domain || tail_hash || amount || puzzle || serial_commitment)
fn create_coin_commitment(
    amount: u64,
    puzzle: &[u8; 32],
    serial: &[u8; 32],
    rand: &[u8; 32],
    tail_hash: &[u8; 32],
) -> [u8; 32] {
    let start = env::cycle_count();
    // use clvm_zk_core optimized implementations (fixed-size arrays, no Vec allocations)
    let serial_commitment = compute_serial_commitment(risc0_hasher, serial, rand);
    let serial_cycles = env::cycle_count();
    let result =
        compute_coin_commitment(risc0_hasher, *tail_hash, amount, puzzle, &serial_commitment);
    let coin_cycles = env::cycle_count();

    risc0_zkvm::guest::env::log(&alloc::format!(
        "create_coin_commitment: serial={}K coin={}K total={}K",
        (serial_cycles - start) / 1000,
        (coin_cycles - serial_cycles) / 1000,
        (coin_cycles - start) / 1000,
    ));

    result
}
