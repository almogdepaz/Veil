//! end-to-end tests with real risc0 proofs
//!
//! these tests generate actual ZK proofs via the risc0 backend.
//! run: cargo test-risc0 --test test_e2e_risc0

#![cfg(feature = "risc0")]

use clvm_zk::protocol::settlement::{prove_settlement, SettlementParams};
use clvm_zk::protocol::{PrivateCoin, ProofType, Spender};
use clvm_zk::simulator::*;
use clvm_zk_core::coin_commitment::{CoinCommitment, CoinSecrets};
use clvm_zk_core::merkle::SparseMerkleTree;
use clvm_zk_core::{
    compile_chialisp_template_hash_default, compute_nullifier, with_standard_conditions,
    GenesisSpend, Input, MintData, ProgramParameter, XCH_TAIL,
};
use clvm_zk_risc0::Risc0Backend;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

fn hash_data(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn meta(owner: &str, notes: &str) -> CoinMetadata {
    CoinMetadata {
        owner: owner.to_string(),
        coin_type: CoinType::Regular,
        notes: notes.to_string(),
    }
}

fn cat_meta(owner: &str, notes: &str) -> CoinMetadata {
    CoinMetadata {
        owner: owner.to_string(),
        coin_type: CoinType::Cat,
        notes: notes.to_string(),
    }
}

const UNLIMITED_TAIL: &str = "(mod () 1)";

// ============================================================================
// 1. XCH mint → spend → double-spend rejection
// ============================================================================

#[test]
fn test_e2e_xch_mint_spend_verify() {
    let mut sim = CLVMZkSimulator::new();

    // simple identity puzzle: returns its argument
    let puzzle = "(mod (x) x)";
    let puzzle_hash = compile_chialisp_template_hash_default(puzzle).unwrap();

    // mint XCH coin
    let (coin, secrets) = PrivateCoin::new_with_secrets(puzzle_hash, 1000);
    sim.add_coin(coin.clone(), &secrets, meta("alice", "xch coin"));

    // spend it
    let result = sim.spend_coins_with_params(vec![(
        coin.clone(),
        puzzle.to_string(),
        vec![ProgramParameter::Int(42)],
        secrets.clone(),
    )]);

    let tx = result.expect("first spend should succeed");

    // verify proof properties
    assert!(!tx.spend_bundles.is_empty(), "should have spend bundles");
    assert!(!tx.spend_bundles[0].zk_proof.is_empty(), "proof bytes should be non-empty");
    assert_eq!(tx.nullifiers.len(), 1, "should produce exactly 1 nullifier");
    assert_ne!(tx.nullifiers[0], [0u8; 32], "nullifier should be non-zero");

    // nullifier tracked in simulator
    assert!(sim.has_nullifier(&tx.nullifiers[0]));

    // double-spend must fail
    let result2 = sim.spend_coins_with_params(vec![(
        coin,
        puzzle.to_string(),
        vec![ProgramParameter::Int(42)],
        secrets,
    )]);

    match result2 {
        Err(SimulatorError::DoubleSpend(_)) => {} // expected
        Err(e) => panic!("expected DoubleSpend, got: {:?}", e),
        Ok(_) => panic!("double-spend should have been rejected"),
    }
}

// ============================================================================
// 2. CAT mint proof → add to sim → spend
// ============================================================================

#[test]
fn test_e2e_cat_mint_spend() {
    let backend = Risc0Backend::new().expect("risc0 init");
    let mut sim = CLVMZkSimulator::new();

    let tail_hash = compile_chialisp_template_hash_default(UNLIMITED_TAIL).unwrap();

    // puzzle for the minted coin - balanced spend that outputs full amount
    let spend_puzzle = with_standard_conditions(
        "(mod (out_puzzle out_serial out_rand)
            (list (list CREATE_COIN out_puzzle 500 out_serial out_rand)))",
    );
    let puzzle_hash = compile_chialisp_template_hash_default(&spend_puzzle).unwrap();

    // generate mint proof via backend
    let output_serial = [10u8; 32];
    let output_rand = [11u8; 32];

    let mint_data = MintData {
        tail_source: UNLIMITED_TAIL.to_string(),
        tail_params: vec![],
        output_puzzle_hash: puzzle_hash,
        output_amount: 500,
        output_serial,
        output_rand,
        genesis_coin: None,
    };

    let input = Input {
        chialisp_source: "".to_string(),
        program_parameters: vec![],
        serial_commitment_data: None,
        tail_hash: None,
        additional_coins: None,
        mint_data: Some(mint_data),
        tail_source: None,
    };

    let zk_result = backend.prove_with_input(input).expect("mint proof");

    // verify mint proof structure
    assert_eq!(zk_result.proof_output.proof_type, 3, "should be Mint type");
    assert!(
        zk_result.proof_output.nullifiers.is_empty(),
        "mint should have no nullifiers"
    );
    assert_eq!(zk_result.proof_output.public_values.len(), 2);

    let proof_tail_hash: [u8; 32] = zk_result.proof_output.public_values[0]
        .clone()
        .try_into()
        .unwrap();
    assert_eq!(proof_tail_hash, tail_hash);

    let coin_commitment_bytes: [u8; 32] = zk_result.proof_output.public_values[1]
        .clone()
        .try_into()
        .unwrap();

    // reconstruct the minted coin and add to simulator
    let secrets = CoinSecrets::new(output_serial, output_rand);
    let serial_commitment = secrets.serial_commitment(hash_data);
    // build the coin with the exact serial commitment from the mint
    let cat_coin = PrivateCoin::new_with_tail(puzzle_hash, 500, serial_commitment, tail_hash);

    // verify coin commitment matches proof
    let expected_commitment =
        CoinCommitment::compute(&tail_hash, 500, &puzzle_hash, &cat_coin.serial_commitment, hash_data);
    assert_eq!(*expected_commitment.as_bytes(), coin_commitment_bytes);

    sim.add_coin(cat_coin.clone(), &secrets, cat_meta("alice", "minted CAT"));

    // spend the CAT coin
    let out_puzzle = [1u8; 32];
    let out_serial = [2u8; 32];
    let out_rand = [3u8; 32];

    let tx = sim
        .spend_coins_with_params(vec![(
            cat_coin,
            spend_puzzle,
            vec![
                ProgramParameter::Bytes(out_puzzle.to_vec()),
                ProgramParameter::Bytes(out_serial.to_vec()),
                ProgramParameter::Bytes(out_rand.to_vec()),
            ],
            secrets,
        )])
        .expect("CAT spend should succeed");

    assert_eq!(tx.nullifiers.len(), 1);
    assert!(sim.has_nullifier(&tx.nullifiers[0]));
}

// ============================================================================
// 3. genesis-linked mint: no double mint
// ============================================================================

#[test]
fn test_e2e_genesis_mint_no_double_mint() {
    let backend = Risc0Backend::new().expect("risc0 init");
    let mut sim = CLVMZkSimulator::new();

    // create genesis XCH coin in simulator
    let genesis_puzzle_hash = [13u8; 32];
    let (genesis_coin, genesis_secrets) =
        PrivateCoin::new_with_secrets(genesis_puzzle_hash, 0);
    sim.add_coin(
        genesis_coin.clone(),
        &genesis_secrets,
        meta("issuer", "genesis coin"),
    );

    // compute genesis commitments for mint
    let genesis_serial_commitment = genesis_secrets.serial_commitment(hash_data);
    let genesis_coin_commitment = CoinCommitment::compute(
        &XCH_TAIL,
        0,
        &genesis_puzzle_hash,
        &genesis_serial_commitment,
        hash_data,
    );

    // build merkle tree with genesis coin
    let mut merkle_tree = SparseMerkleTree::new(20, hash_data);
    let leaf_index = merkle_tree.insert(*genesis_coin_commitment.as_bytes(), hash_data);
    let merkle_root = merkle_tree.root();
    let merkle_proof = merkle_tree.generate_proof(leaf_index, hash_data).unwrap();

    let tail_source = "(mod (genesis_nullifier) 1)";

    // first mint — should succeed
    let mint_data = MintData {
        tail_source: tail_source.to_string(),
        tail_params: vec![],
        output_puzzle_hash: [42u8; 32],
        output_amount: 5000,
        output_serial: [50u8; 32],
        output_rand: [51u8; 32],
        genesis_coin: Some(GenesisSpend {
            serial_number: genesis_secrets.serial_number,
            serial_randomness: genesis_secrets.serial_randomness,
            puzzle_hash: genesis_puzzle_hash,
            amount: 0,
            tail_hash: XCH_TAIL,
            serial_commitment: *genesis_serial_commitment.as_bytes(),
            coin_commitment: *genesis_coin_commitment.as_bytes(),
            merkle_path: merkle_proof.path.clone(),
            merkle_root,
            leaf_index,
        }),
    };

    let input = Input {
        chialisp_source: "".to_string(),
        program_parameters: vec![],
        serial_commitment_data: None,
        tail_hash: None,
        additional_coins: None,
        mint_data: Some(mint_data),
        tail_source: None,
    };

    let result = backend.prove_with_input(input).expect("first genesis mint should succeed");
    assert_eq!(result.proof_output.nullifiers.len(), 1);

    let genesis_nullifier = result.proof_output.nullifiers[0];

    // verify nullifier is deterministic
    let expected_nullifier =
        compute_nullifier(hash_data, &genesis_secrets.serial_number, &genesis_puzzle_hash, 0);
    assert_eq!(genesis_nullifier, expected_nullifier);

    // track nullifier externally (simulating validator behavior)
    // the simulator only tracks nullifiers via spend_coins internally,
    // so for genesis mints we use a local set
    let mut nullifier_set = HashSet::new();
    nullifier_set.insert(genesis_nullifier);

    // second mint with same genesis → nullifier already spent
    let mint_data2 = MintData {
        tail_source: tail_source.to_string(),
        tail_params: vec![],
        output_puzzle_hash: [99u8; 32],
        output_amount: 9999,
        output_serial: [60u8; 32],
        output_rand: [61u8; 32],
        genesis_coin: Some(GenesisSpend {
            serial_number: genesis_secrets.serial_number,
            serial_randomness: genesis_secrets.serial_randomness,
            puzzle_hash: genesis_puzzle_hash,
            amount: 0,
            tail_hash: XCH_TAIL,
            serial_commitment: *genesis_serial_commitment.as_bytes(),
            coin_commitment: *genesis_coin_commitment.as_bytes(),
            merkle_path: merkle_proof.path,
            merkle_root,
            leaf_index,
        }),
    };

    let input2 = Input {
        chialisp_source: "".to_string(),
        program_parameters: vec![],
        serial_commitment_data: None,
        tail_hash: None,
        additional_coins: None,
        mint_data: Some(mint_data2),
        tail_source: None,
    };

    // the proof itself will succeed (guest doesn't know about global nullifier set)
    // but the nullifier will be the SAME → validator rejects
    let result2 = backend.prove_with_input(input2).expect("proof generation succeeds");
    let nullifier2 = result2.proof_output.nullifiers[0];
    assert_eq!(
        nullifier2, genesis_nullifier,
        "same genesis → same nullifier"
    );
    assert!(
        nullifier_set.contains(&nullifier2),
        "validator rejects: nullifier already spent"
    );
}

// ============================================================================
// 4. CAT ring spend (2 coins, same tail_hash)
// ============================================================================

#[test]
fn test_e2e_cat_ring_spend() {
    let mut sim = CLVMZkSimulator::new();
    let tail_hash = compile_chialisp_template_hash_default(UNLIMITED_TAIL).unwrap();

    // balanced puzzles — total output = 100 + 200 = 300
    let puzzle1 = with_standard_conditions(
        "(mod () (list (list CREATE_COIN 0x0101010101010101010101010101010101010101010101010101010101010101 150)))",
    );
    let puzzle2 = with_standard_conditions(
        "(mod () (list (list CREATE_COIN 0x0202020202020202020202020202020202020202020202020202020202020202 150)))",
    );

    let hash1 = compile_chialisp_template_hash_default(&puzzle1).unwrap();
    let hash2 = compile_chialisp_template_hash_default(&puzzle2).unwrap();

    let (coin1, secrets1) = PrivateCoin::new_with_secrets_and_tail(hash1, 100, tail_hash);
    let (coin2, secrets2) = PrivateCoin::new_with_secrets_and_tail(hash2, 200, tail_hash);

    sim.add_coin(coin1.clone(), &secrets1, cat_meta("alice", "cat1"));
    sim.add_coin(coin2.clone(), &secrets2, cat_meta("alice", "cat2"));

    let merkle_root = sim.get_merkle_root().unwrap();
    let (path1, idx1) = sim.get_merkle_path_and_index(&coin1).unwrap();
    let (path2, idx2) = sim.get_merkle_path_and_index(&coin2).unwrap();

    let coins = vec![
        (&coin1, puzzle1.as_str(), &[][..], &secrets1, path1, idx1),
        (&coin2, puzzle2.as_str(), &[][..], &secrets2, path2, idx2),
    ];

    let bundle = Spender::create_ring_spend(coins, merkle_root).expect("ring spend should succeed");

    // verify 2 nullifiers
    assert_eq!(bundle.nullifiers.len(), 2);
    assert_ne!(bundle.nullifiers[0], bundle.nullifiers[1]);
    assert!(!bundle.zk_proof.is_empty());

    // verify both nullifiers are unique and non-zero (validator would track these)
    let mut nullifier_set = HashSet::new();
    for nul in &bundle.nullifiers {
        assert_ne!(*nul, [0u8; 32]);
        assert!(nullifier_set.insert(*nul), "nullifiers should be unique");
    }
}

// ============================================================================
// 5. offer: alice XCH → bob CAT (conditional spend + settlement)
// ============================================================================

#[test]
fn test_e2e_offer_create_take() {
    let mut sim = CLVMZkSimulator::new();
    let tail_hash = compile_chialisp_template_hash_default(UNLIMITED_TAIL).unwrap();

    // alice has XCH coin
    // maker puzzle outputs: ((51 change_puzzle change_amount change_serial change_rand) (offered requested maker_pubkey))
    // alice offers 1000 XCH, requests 500 CAT, change = 0
    let maker_pubkey = [77u8; 32];
    let change_puzzle = [88u8; 32];
    let change_serial = [89u8; 32];
    let change_rand = [90u8; 32];

    let offer_puzzle = with_standard_conditions(&format!(
        r#"(mod ()
            (c
                (list CREATE_COIN
                    0x{}
                    0
                    0x{}
                    0x{})
                (c 1000 (c 500 (c 0x{} ())))))"#,
        hex::encode(change_puzzle),
        hex::encode(change_serial),
        hex::encode(change_rand),
        hex::encode(maker_pubkey),
    ));

    let offer_puzzle_hash = compile_chialisp_template_hash_default(&offer_puzzle).unwrap();
    let (alice_coin, alice_secrets) = PrivateCoin::new_with_secrets(offer_puzzle_hash, 1000);
    sim.add_coin(
        alice_coin.clone(),
        &alice_secrets,
        meta("alice", "xch for offer"),
    );

    // bob has CAT coin (puzzle just returns its amount for simplicity)
    let bob_puzzle = with_standard_conditions(
        "(mod (out_puzzle out_serial out_rand)
            (list (list CREATE_COIN out_puzzle 500 out_serial out_rand)))",
    );
    let bob_puzzle_hash = compile_chialisp_template_hash_default(&bob_puzzle).unwrap();
    let (bob_coin, bob_secrets) =
        PrivateCoin::new_with_secrets_and_tail(bob_puzzle_hash, 500, tail_hash);
    sim.add_coin(bob_coin.clone(), &bob_secrets, cat_meta("bob", "cat for offer"));

    // alice creates conditional spend (offer)
    let merkle_root = sim.get_merkle_root().unwrap();
    let (alice_path, alice_idx) = sim.get_merkle_path_and_index(&alice_coin).unwrap();

    let maker_proof = Spender::create_conditional_spend(
        &alice_coin,
        &offer_puzzle,
        &[],
        &alice_secrets,
        alice_path,
        merkle_root,
        alice_idx,
    )
    .expect("conditional spend should succeed");

    assert_eq!(maker_proof.proof_type, ProofType::ConditionalSpend);
    assert!(!maker_proof.nullifiers.is_empty());

    // bob takes the offer via settlement proof
    let (bob_path, bob_idx) = sim.get_merkle_path_and_index(&bob_coin).unwrap();

    let settlement_params = SettlementParams {
        maker_proof: maker_proof.clone(),
        taker_coin: bob_coin.clone(),
        taker_secrets: bob_secrets.clone(),
        taker_merkle_path: bob_path,
        merkle_root,
        taker_leaf_index: bob_idx,
        payment_nonce: [33u8; 32],
        taker_goods_puzzle: [44u8; 32],
        taker_change_puzzle: [55u8; 32],
        payment_serial: [60u8; 32],
        payment_rand: [61u8; 32],
        goods_serial: [62u8; 32],
        goods_rand: [63u8; 32],
        change_serial: [64u8; 32],
        change_rand: [65u8; 32],
        taker_tail_hash: tail_hash,
        goods_tail_hash: XCH_TAIL, // alice's asset is XCH
    };

    let settlement = prove_settlement(settlement_params).expect("settlement should succeed");

    assert_eq!(settlement.proof_type, ProofType::Settlement);
    assert!(!settlement.zk_proof.is_empty());

    // verify both nullifiers produced
    assert_ne!(settlement.output.maker_nullifier, [0u8; 32]);
    assert_ne!(settlement.output.taker_nullifier, [0u8; 32]);

    // process settlement in simulator (registers nullifiers + adds commitments to merkle tree)
    sim.process_settlement(&settlement.output);

    assert!(sim.has_nullifier(&settlement.output.maker_nullifier));
    assert!(sim.has_nullifier(&settlement.output.taker_nullifier));

    // verify new coin commitments are non-zero
    assert_ne!(settlement.output.payment_commitment, [0u8; 32]);
    assert_ne!(settlement.output.taker_goods_commitment, [0u8; 32]);
}

// ============================================================================
// 6. TAIL-on-delta melt: burn CAT with permissive TAIL
// ============================================================================

#[test]
fn test_e2e_tail_on_delta_melt() {
    let mut sim = CLVMZkSimulator::new();
    let tail_hash = compile_chialisp_template_hash_default(UNLIMITED_TAIL).unwrap();

    // puzzle that outputs less than input (melt/burn)
    // input = 1000, output = 500 → delta = -500
    let melt_puzzle = with_standard_conditions(
        "(mod (out_puzzle out_serial out_rand)
            (list (list CREATE_COIN out_puzzle 500 out_serial out_rand)))",
    );
    let puzzle_hash = compile_chialisp_template_hash_default(&melt_puzzle).unwrap();

    let (coin, secrets) = PrivateCoin::new_with_secrets_and_tail(puzzle_hash, 1000, tail_hash);
    sim.add_coin(coin.clone(), &secrets, cat_meta("alice", "cat to melt"));

    let merkle_root = sim.get_merkle_root().unwrap();
    let (path, idx) = sim.get_merkle_path_and_index(&coin).unwrap();

    let coin_commitment = CoinCommitment::compute(
        &tail_hash,
        coin.amount,
        &coin.puzzle_hash,
        &coin.serial_commitment,
        hash_data,
    );

    let out_puzzle = [1u8; 32];
    let out_serial = [2u8; 32];
    let out_rand = [3u8; 32];

    // use prove_with_input directly so we can pass tail_source for delta authorization
    let backend = Risc0Backend::new().expect("risc0 init");

    let input = Input {
        chialisp_source: melt_puzzle.clone(),
        program_parameters: vec![
            ProgramParameter::Bytes(out_puzzle.to_vec()),
            ProgramParameter::Bytes(out_serial.to_vec()),
            ProgramParameter::Bytes(out_rand.to_vec()),
        ],
        serial_commitment_data: Some(clvm_zk_core::SerialCommitmentData {
            serial_number: secrets.serial_number,
            serial_randomness: secrets.serial_randomness,
            merkle_path: path,
            coin_commitment: *coin_commitment.as_bytes(),
            serial_commitment: *coin.serial_commitment.as_bytes(),
            merkle_root,
            leaf_index: idx,
            program_hash: puzzle_hash,
            amount: 1000,
        }),
        tail_hash: Some(tail_hash),
        tail_source: Some(UNLIMITED_TAIL.to_string()), // TAIL authorizes the negative delta
        additional_coins: None,
        mint_data: None,
    };

    let result = backend.prove_with_input(input).expect("melt proof should succeed with permissive TAIL");

    // verify proof succeeded
    assert!(!result.proof_bytes.is_empty());
    assert_eq!(result.proof_output.nullifiers.len(), 1);
    assert_ne!(result.proof_output.nullifiers[0], [0u8; 32]);

    // the TAIL authorized the delta, so proof generation succeeded
    // in production, a restrictive TAIL would reject unauthorized burns
}
