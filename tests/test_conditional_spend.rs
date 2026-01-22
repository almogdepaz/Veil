//! test conditional spend proof creation
//!
//! verifies maker can create locked conditional spend proofs

#[cfg(feature = "mock")]
use clvm_zk::protocol::{PrivateCoin, ProofType, Spender};
#[cfg(feature = "mock")]
use clvm_zk_core::{
    compile_chialisp_template_hash_default, with_standard_conditions, ProgramParameter,
};

#[test]
#[cfg(feature = "mock")]
fn test_conditional_spend_creation() {
    println!("\n=== CONDITIONAL SPEND TEST (MOCK) ===\n");

    // create a coin for maker
    let maker_amount = 1000u64;
    let maker_change = 900u64; // change back to maker

    // output coin parameters
    let change_puzzle = [3u8; 32];
    let change_serial = [4u8; 32];
    let change_rand = [5u8; 32];

    // use with_standard_conditions for proper CREATE_COIN macro
    // this puzzle creates a single output coin (the change)
    let offer_puzzle = with_standard_conditions(
        "(mod (change_puzzle change_amount change_serial change_rand)
            (list (list CREATE_COIN change_puzzle change_amount change_serial change_rand)))",
    );

    // compute the puzzle hash FIRST, then create coin with it
    let maker_puzzle_hash =
        compile_chialisp_template_hash_default(&offer_puzzle).expect("compile puzzle");

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

    // solution parameters for the puzzle
    let solution_params = vec![
        ProgramParameter::Bytes(change_puzzle.to_vec()),
        ProgramParameter::Int(maker_change),
        ProgramParameter::Bytes(change_serial.to_vec()),
        ProgramParameter::Bytes(change_rand.to_vec()),
    ];

    println!("creating conditional spend:");
    println!("  change: {} mojos", maker_change);

    // create conditional spend proof
    let result = Spender::create_conditional_spend(
        &maker_coin,
        &offer_puzzle,
        &solution_params,
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
    let out_puzzle_hash = [1u8; 32]; // destination puzzle

    // puzzle that creates balanced output (51 = CREATE_COIN, outputs full amount back)
    let balanced_puzzle = format!(
        "(mod () (list (list 51 0x{} {})))",
        hex::encode(out_puzzle_hash),
        coin_amount
    );

    // compute puzzle hash FIRST
    let puzzle_hash =
        compile_chialisp_template_hash_default(&balanced_puzzle).expect("compile puzzle");

    let (coin, secrets) = PrivateCoin::new_with_secrets(puzzle_hash, coin_amount);

    let commitment = clvm_zk_core::coin_commitment::CoinCommitment::compute(
        &coin.tail_hash,
        coin.amount,
        &coin.puzzle_hash,
        &coin.serial_commitment,
        clvm_zk::crypto_utils::hash_data_default,
    );

    let merkle_root = commitment.0;

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
