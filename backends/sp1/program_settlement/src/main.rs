#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;
use alloc::vec::Vec;

use clvm_zk_core::{
    compute_coin_commitment, compute_nullifier, compute_serial_commitment, verify_merkle_proof,
};
use sha2::{Digest, Sha256};

fn sp1_hasher(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
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
    let input: SettlementInput = sp1_zkvm::io::read();

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
    let mut payment_puzzle_hasher = Sha256::new();
    payment_puzzle_hasher.update(b"stealth_v1");
    payment_puzzle_hasher.update(&maker_pubkey);
    payment_puzzle_hasher.update(&input.payment_nonce);
    let payment_puzzle_bytes: [u8; 32] = payment_puzzle_hasher.finalize().into();

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

    // compute taker's nullifier
    let taker_nullifier = compute_nullifier(
        sp1_hasher,
        &input.taker_coin.serial_number,
        &input.taker_coin.puzzle_hash,
        input.taker_coin.amount,
    );

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

    sp1_zkvm::io::commit(&output);
}

/// verify taker's coin ownership via merkle membership (v2.0 format with tail_hash)
fn verify_taker_coin(coin: &TakerCoinData, merkle_root: [u8; 32], tail_hash: &[u8; 32]) {
    // 1. verify serial commitment using clvm_zk_core (optimized fixed-size arrays)
    let computed_serial =
        compute_serial_commitment(sp1_hasher, &coin.serial_number, &coin.serial_randomness);

    assert_eq!(
        computed_serial, coin.serial_commitment,
        "invalid serial commitment"
    );

    // 2. compute coin_commitment using clvm_zk_core (optimized fixed-size arrays)
    let coin_commitment = compute_coin_commitment(
        sp1_hasher,
        *tail_hash,
        coin.amount,
        &coin.puzzle_hash,
        &computed_serial,
    );

    // 3. verify merkle membership using clvm_zk_core (optimized fixed-size arrays)
    verify_merkle_proof(
        sp1_hasher,
        coin_commitment,
        &coin.merkle_path,
        coin.leaf_index,
        merkle_root,
    )
    .expect("merkle proof verification failed");
}

/// create coin commitment v2.0: hash(domain || tail_hash || amount || puzzle || serial_commitment)
fn create_coin_commitment(
    amount: u64,
    puzzle: &[u8; 32],
    serial: &[u8; 32],
    rand: &[u8; 32],
    tail_hash: &[u8; 32],
) -> [u8; 32] {
    // use clvm_zk_core optimized implementations (fixed-size arrays, no Vec allocations)
    let serial_commitment = compute_serial_commitment(sp1_hasher, serial, rand);
    compute_coin_commitment(sp1_hasher, *tail_hash, amount, puzzle, &serial_commitment)
}
