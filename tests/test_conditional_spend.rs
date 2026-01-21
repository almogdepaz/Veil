//! test conditional spend proof creation
//!
//! verifies maker can create locked conditional spend proofs

use clvm_zk::protocol::{PrivateCoin, ProofType, Spender};

#[test]
#[cfg(feature = "mock")]
fn test_conditional_spend_creation() {
    println!("\n=== CONDITIONAL SPEND TEST (MOCK) ===\n");

    // create a coin for maker
    let maker_amount = 1000u64;
    let maker_puzzle_hash = [1u8; 32];

    let (maker_coin, maker_secrets) =
        PrivateCoin::new_with_secrets(maker_puzzle_hash, maker_amount);

    println!("maker coin: {} mojos", maker_amount);

    // create simple merkle tree (single leaf)
    let maker_commitment = clvm_zk_core::coin_commitment::CoinCommitment::compute(
        &maker_coin.tail_hash,
        maker_coin.amount,
        &maker_coin.puzzle_hash,
        &maker_coin.serial_commitment,
        clvm_zk::crypto_utils::hash_data_default,
    );

    let maker_merkle_root = maker_commitment.0;

    // create offer puzzle that outputs settlement terms
    // balance: input (1000) = change (900) + offered (100) sent to taker later
    let offered = 100u64;
    let requested = 200u64;
    let maker_change = maker_amount - offered; // 900

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

    println!("creating conditional spend:");
    println!("  offering: {} mojos", offered);
    println!("  requesting: {} mojos", requested);
    println!("  change: {} mojos", maker_change);

    // create conditional spend proof
    let result = Spender::create_conditional_spend(
        &maker_coin,
        &offer_puzzle,
        &[],
        &maker_secrets,
        vec![], // empty merkle path for single-leaf tree
        maker_merkle_root,
        0,
    );

    match result {
        Ok(bundle) => {
            println!("\n✓ conditional spend created successfully");
            println!("  proof type: {:?}", bundle.proof_type);
            println!("  proof size: {} bytes", bundle.zk_proof.len());
            println!("  nullifiers: {}", bundle.nullifiers.len());
            println!("  output size: {} bytes", bundle.public_conditions.len());

            // verify proof type is ConditionalSpend
            assert_eq!(
                bundle.proof_type,
                ProofType::ConditionalSpend,
                "proof should be ConditionalSpend type"
            );

            // verify we have exactly one nullifier
            assert_eq!(
                bundle.nullifiers.len(),
                1,
                "should have exactly one nullifier"
            );
            assert_ne!(
                bundle.nullifiers[0], [0u8; 32],
                "nullifier should be non-zero"
            );

            // verify output is not empty (contains settlement terms)
            assert!(
                !bundle.public_conditions.is_empty(),
                "output should contain settlement terms"
            );

            println!("\n✓ ALL CHECKS PASSED");
            println!("  - proof type: ConditionalSpend ✓");
            println!("  - nullifier present: ✓");
            println!("  - settlement terms in output: ✓");
        }
        Err(e) => {
            panic!("conditional spend failed: {:?}", e);
        }
    }
}

#[test]
#[cfg(feature = "mock")]
fn test_conditional_vs_regular_spend() {
    println!("\n=== CONDITIONAL VS REGULAR SPEND TEST ===\n");

    let coin_amount = 1000u64;
    let puzzle_hash = [1u8; 32];

    let (coin, secrets) = PrivateCoin::new_with_secrets(puzzle_hash, coin_amount);

    let commitment = clvm_zk_core::coin_commitment::CoinCommitment::compute(
        &coin.tail_hash,
        coin.amount,
        &coin.puzzle_hash,
        &coin.serial_commitment,
        clvm_zk::crypto_utils::hash_data_default,
    );

    let merkle_root = commitment.0;

    // puzzle that creates balanced output (51 = CREATE_COIN, outputs full amount back to self)
    let balanced_puzzle = format!(
        "(mod () (list (list 51 0x{} {})))",
        hex::encode(puzzle_hash),
        coin_amount
    );

    // create regular spend
    let regular_bundle = Spender::create_spend_with_serial(
        &coin,
        &balanced_puzzle,
        &[],
        &secrets,
        vec![],
        merkle_root,
        0,
    )
    .expect("regular spend failed");

    // create conditional spend
    let conditional_bundle = Spender::create_conditional_spend(
        &coin,
        &balanced_puzzle,
        &[],
        &secrets,
        vec![],
        merkle_root,
        0,
    )
    .expect("conditional spend failed");

    println!("regular spend:");
    println!("  proof type: {:?}", regular_bundle.proof_type);
    println!("  nullifiers: {}", regular_bundle.nullifiers.len());

    println!("\nconditional spend:");
    println!("  proof type: {:?}", conditional_bundle.proof_type);
    println!("  nullifiers: {}", conditional_bundle.nullifiers.len());

    // verify proof types are different
    assert_eq!(regular_bundle.proof_type, ProofType::Transaction);
    assert_eq!(conditional_bundle.proof_type, ProofType::ConditionalSpend);

    println!("\n✓ proof types correctly differentiated");
}
