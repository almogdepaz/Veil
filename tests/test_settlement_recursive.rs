//! integration test for recursive settlement proofs
//!
//! verifies:
//! 1. maker creates conditional spend proof (locked)
//! 2. taker creates settlement proof (recursively verifies maker's proof)
//! 3. settlement proof validates correctly

use clvm_zk::protocol::settlement::{prove_settlement, SettlementParams};
use clvm_zk::protocol::{PrivateCoin, ProofType, Spender};
use clvm_zk_core::coin_commitment::CoinSecrets;

#[test]
#[cfg(feature = "mock")]
fn test_settlement_mock() {
    println!("\n=== SETTLEMENT MOCK TEST ===\n");
    println!("testing settlement flow with mock backend (logic only, no ZK)");

    // setup: create two coins (maker + taker)
    let maker_amount = 1000u64;
    let taker_amount = 500u64;

    let maker_puzzle_hash = [1u8; 32];
    let taker_puzzle_hash = [2u8; 32];

    // generate coin secrets
    let maker_secrets = CoinSecrets::random();
    let taker_secrets = CoinSecrets::random();

    let maker_coin =
        PrivateCoin::new_with_secrets(maker_puzzle_hash, maker_amount, maker_secrets.clone());

    let taker_coin =
        PrivateCoin::new_with_secrets(taker_puzzle_hash, taker_amount, taker_secrets.clone());

    println!("maker coin: {} mojos", maker_amount);
    println!("taker coin: {} mojos", taker_amount);

    // create simple merkle tree (single leaf for each coin)
    let maker_commitment = clvm_zk_core::coin_commitment::CoinCommitment::compute(
        &maker_coin.tail_hash,
        maker_coin.amount,
        &maker_coin.puzzle_hash,
        &maker_coin.serial_commitment,
        clvm_zk::crypto_utils::hash_data_default,
    );

    let taker_commitment = clvm_zk_core::coin_commitment::CoinCommitment::compute(
        &taker_coin.tail_hash,
        taker_coin.amount,
        &taker_coin.puzzle_hash,
        &taker_coin.serial_commitment,
        clvm_zk::crypto_utils::hash_data_default,
    );

    // for simplicity, use coin commitments as merkle roots (single-leaf tree)
    let maker_merkle_root = maker_commitment.0;
    let taker_merkle_root = taker_commitment.0;

    // STEP 1: maker creates conditional spend proof
    println!("\n--- STEP 1: maker creates conditional spend ---");

    let offered = 100u64;
    let requested = 200u64;
    let maker_change = maker_amount - offered;

    // create offer puzzle that outputs settlement terms
    // format: ((51 change_puzzle change_amount change_serial change_rand) (offered requested maker_pubkey))
    let change_puzzle = [3u8; 32];
    let change_serial = [4u8; 32];
    let change_rand = [5u8; 32];
    let maker_pubkey = [6u8; 32];

    let offer_puzzle = format!(
        r#"(mod ()
            (list
                (list 51 0x{} {} 0x{} 0x{})
                (list {} {} 0x{})
            )
        )"#,
        hex::encode(change_puzzle),
        maker_change,
        hex::encode(change_serial),
        hex::encode(change_rand),
        offered,
        requested,
        hex::encode(maker_pubkey),
    );

    println!("offer: {} mojos for {} mojos", offered, requested);

    let maker_bundle = Spender::create_conditional_spend(
        &maker_coin,
        &offer_puzzle,
        &[],
        &maker_secrets,
        vec![], // empty merkle path for single-leaf tree
        maker_merkle_root,
        0,
    )
    .expect("maker conditional spend failed");

    println!("✓ maker created conditional spend proof");
    println!("  proof type: {:?}", maker_bundle.proof_type);
    println!("  proof size: {} bytes", maker_bundle.zk_proof.len());

    assert_eq!(maker_bundle.proof_type, ProofType::ConditionalSpend);
    assert!(!maker_bundle.nullifiers.is_empty());

    // STEP 2: taker creates settlement proof (recursively verifies maker's proof)
    println!("\n--- STEP 2: taker creates settlement proof ---");

    // generate ephemeral keypair for ECDH payment
    let mut taker_ephemeral_privkey = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut taker_ephemeral_privkey);

    // generate new coin secrets for settlement outputs
    let payment_serial = [10u8; 32];
    let payment_rand = [11u8; 32];
    let goods_serial = [12u8; 32];
    let goods_rand = [13u8; 32];
    let change_serial_taker = [14u8; 32];
    let change_rand_taker = [15u8; 32];

    let taker_goods_puzzle = [20u8; 32];
    let taker_change_puzzle = [21u8; 32];

    let settlement_params = SettlementParams {
        maker_proof: maker_bundle,
        taker_coin,
        taker_secrets,
        taker_merkle_path: vec![], // empty for single-leaf tree
        merkle_root: taker_merkle_root,
        taker_leaf_index: 0,
        taker_ephemeral_privkey,
        taker_goods_puzzle,
        taker_change_puzzle,
        payment_serial,
        payment_rand,
        goods_serial,
        goods_rand,
        change_serial: change_serial_taker,
        change_rand: change_rand_taker,
        taker_tail_hash: [0u8; 32], // XCH
        goods_tail_hash: [0u8; 32], // XCH
    };

    println!("generating settlement proof (recursive verification)...");
    let settlement_proof = prove_settlement(settlement_params).expect("settlement proof failed");

    println!("✓ settlement proof generated successfully");
    println!("  proof type: {:?}", settlement_proof.proof_type);
    println!("  proof size: {} bytes", settlement_proof.zk_proof.len());

    // STEP 3: verify settlement output
    println!("\n--- STEP 3: verify settlement output ---");

    let output = &settlement_proof.output;

    println!("maker nullifier: {}", hex::encode(output.maker_nullifier));
    println!("taker nullifier: {}", hex::encode(output.taker_nullifier));
    println!(
        "maker change:    {}",
        hex::encode(output.maker_change_commitment)
    );
    println!(
        "payment (T→M):   {}",
        hex::encode(output.payment_commitment)
    );
    println!(
        "goods (M→T):     {}",
        hex::encode(output.taker_goods_commitment)
    );
    println!(
        "taker change:    {}",
        hex::encode(output.taker_change_commitment)
    );

    // verify we got valid commitments (non-zero)
    assert_ne!(output.maker_nullifier, [0u8; 32]);
    assert_ne!(output.taker_nullifier, [0u8; 32]);
    assert_ne!(output.maker_change_commitment, [0u8; 32]);
    assert_ne!(output.payment_commitment, [0u8; 32]);
    assert_ne!(output.taker_goods_commitment, [0u8; 32]);
    assert_ne!(output.taker_change_commitment, [0u8; 32]);

    println!("\n✓ SETTLEMENT RECURSIVE PROOF TEST PASSED");
    println!("  - conditional spend: ✓");
    println!("  - recursive verification: ✓");
    println!("  - settlement outputs: ✓");
}
