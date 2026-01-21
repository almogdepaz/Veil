// test ring spend balance enforcement
//
// CRITICAL: these tests expose a security vulnerability where ring spends
// don't enforce balance checking. the guest verifies merkle membership but
// doesn't check sum(inputs) == sum(outputs).

use clvm_zk::protocol::{PrivateCoin, Spender};
use clvm_zk::simulator::*;
use clvm_zk_core::compile_chialisp_template_hash_default;

#[tokio::test]
async fn test_ring_spend_rejects_inflation_attack() {
    // EXPLOIT TEST: spend 300 XCH, create 1000 XCH
    // this should FAIL but currently PASSES (exposing the bug)

    let mut sim = CLVMZkSimulator::new();

    // puzzle that creates 1000 XCH output regardless of input
    // note: CREATE_COIN args must be proper byte lengths (32, 8, 32, 32)
    let exploit_puzzle = format!(
        r#"(mod ()
            (list
                (list 51
                    (q . {})
                    1000
                    (q . {})
                    (q . {})
                )
            )
        )"#,
        hex::encode([0x11u8; 32]),
        hex::encode([0xaau8; 32]),
        hex::encode([0xbbu8; 32]),
    );

    let puzzle_hash = compile_chialisp_template_hash_default(&exploit_puzzle.as_str())
        .expect("puzzle compilation failed");

    // create 3 coins: 100 + 200 + 150 = 450 XCH input
    let (coin1, secrets1) = PrivateCoin::new_with_secrets(puzzle_hash, 100);
    let (coin2, secrets2) = PrivateCoin::new_with_secrets(puzzle_hash, 200);
    let (coin3, secrets3) = PrivateCoin::new_with_secrets(puzzle_hash, 150);

    sim.add_coin(
        coin1.clone(),
        &secrets1,
        CoinMetadata {
            owner: "attacker".to_string(),
            coin_type: CoinType::Regular,
            notes: "coin1".to_string(),
        },
    );
    sim.add_coin(
        coin2.clone(),
        &secrets2,
        CoinMetadata {
            owner: "attacker".to_string(),
            coin_type: CoinType::Regular,
            notes: "coin2".to_string(),
        },
    );
    sim.add_coin(
        coin3.clone(),
        &secrets3,
        CoinMetadata {
            owner: "attacker".to_string(),
            coin_type: CoinType::Regular,
            notes: "coin3".to_string(),
        },
    );

    let merkle_root = sim.get_merkle_root().expect("no merkle root");
    let (path1, idx1) = sim.get_merkle_path_and_index(&coin1).expect("no path");
    let (path2, idx2) = sim.get_merkle_path_and_index(&coin2).expect("no path");
    let (path3, idx3) = sim.get_merkle_path_and_index(&coin3).expect("no path");

    let coins = vec![
        (&coin1, &exploit_puzzle, &[][..], &secrets1, path1, idx1),
        (&coin2, &exploit_puzzle, &[][..], &secrets2, path2, idx2),
        (&coin3, &exploit_puzzle, &[][..], &secrets3, path3, idx3),
    ];

    let result = Spender::create_ring_spend(coins, merkle_root);

    // this SHOULD fail with balance error
    // but will currently SUCCEED (the bug)
    match result {
        Ok(_) => {
            eprintln!("❌ BUG EXPOSED: inflation attack succeeded!");
            eprintln!("   spent 450 XCH, created 1000 XCH");
            eprintln!("   balance enforcement is MISSING");
            panic!("ring spend should reject unbalanced transaction");
        }
        Err(e) => {
            eprintln!("✓ correctly rejected: {}", e);
            assert!(
                e.to_string().contains("balance"),
                "should fail with balance error"
            );
        }
    }
}

#[tokio::test]
async fn test_ring_spend_rejects_no_outputs() {
    // spend 300 XCH, create 0 outputs
    // should FAIL

    let mut sim = CLVMZkSimulator::new();

    // puzzle that creates no outputs
    let puzzle = "1000"; // just returns number, no CREATE_COIN

    let puzzle_hash =
        compile_chialisp_template_hash_default(puzzle).expect("puzzle compilation failed");

    let (coin1, secrets1) = PrivateCoin::new_with_secrets(puzzle_hash, 100);
    let (coin2, secrets2) = PrivateCoin::new_with_secrets(puzzle_hash, 200);

    sim.add_coin(
        coin1.clone(),
        &secrets1,
        CoinMetadata {
            owner: "test".to_string(),
            coin_type: CoinType::Regular,
            notes: "coin1".to_string(),
        },
    );
    sim.add_coin(
        coin2.clone(),
        &secrets2,
        CoinMetadata {
            owner: "test".to_string(),
            coin_type: CoinType::Regular,
            notes: "coin2".to_string(),
        },
    );

    let merkle_root = sim.get_merkle_root().expect("no merkle root");
    let (path1, idx1) = sim.get_merkle_path_and_index(&coin1).expect("no path");
    let (path2, idx2) = sim.get_merkle_path_and_index(&coin2).expect("no path");

    let coins = vec![
        (&coin1, puzzle, &[][..], &secrets1, path1, idx1),
        (&coin2, puzzle, &[][..], &secrets2, path2, idx2),
    ];

    let result = Spender::create_ring_spend(coins, merkle_root);

    match result {
        Ok(_) => {
            eprintln!("❌ BUG: accepted transaction with no outputs");
            panic!("should reject transaction with 0 outputs");
        }
        Err(e) => {
            eprintln!("✓ correctly rejected: {}", e);
            assert!(e.to_string().contains("balance"));
        }
    }
}

#[tokio::test]
async fn test_ring_spend_accepts_balanced() {
    // spend 300 XCH, create 300 XCH (balanced)
    // should PASS

    let mut sim = CLVMZkSimulator::new();

    // puzzle that creates exactly 300 XCH output (matching 100+200 input)
    let balanced_puzzle = format!(
        r#"(mod ()
            (list
                (list 51
                    (q . {})
                    150
                    (q . {})
                    (q . {})
                )
                (list 51
                    (q . {})
                    150
                    (q . {})
                    (q . {})
                )
            )
        )"#,
        hex::encode([0x11u8; 32]),
        hex::encode([0xaau8; 32]),
        hex::encode([0xbbu8; 32]),
        hex::encode([0x22u8; 32]),
        hex::encode([0xccu8; 32]),
        hex::encode([0xddu8; 32]),
    );

    let puzzle_hash = compile_chialisp_template_hash_default(&balanced_puzzle.as_str())
        .expect("puzzle compilation failed");

    let (coin1, secrets1) = PrivateCoin::new_with_secrets(puzzle_hash, 100);
    let (coin2, secrets2) = PrivateCoin::new_with_secrets(puzzle_hash, 200);

    sim.add_coin(
        coin1.clone(),
        &secrets1,
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "coin1".to_string(),
        },
    );
    sim.add_coin(
        coin2.clone(),
        &secrets2,
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "coin2".to_string(),
        },
    );

    let merkle_root = sim.get_merkle_root().expect("no merkle root");
    let (path1, idx1) = sim.get_merkle_path_and_index(&coin1).expect("no path");
    let (path2, idx2) = sim.get_merkle_path_and_index(&coin2).expect("no path");

    let coins = vec![
        (&coin1, &balanced_puzzle, &[][..], &secrets1, path1, idx1),
        (&coin2, &balanced_puzzle, &[][..], &secrets2, path2, idx2),
    ];

    let result = Spender::create_ring_spend(coins, merkle_root);

    match result {
        Ok(bundle) => {
            eprintln!("✓ balanced transaction accepted");
            eprintln!("  nullifiers: {}", bundle.nullifiers.len());
        }
        Err(e) => {
            eprintln!("❌ rejected valid balanced transaction: {}", e);
            panic!("should accept balanced transaction");
        }
    }
}

#[tokio::test]
async fn test_ring_spend_rejects_deflation() {
    // spend 300 XCH, create 100 XCH
    // should FAIL (burning without authorization)

    let mut sim = CLVMZkSimulator::new();

    let deflation_puzzle = format!(
        r#"(mod ()
            (list
                (list 51
                    (q . {})
                    100
                    (q . {})
                    (q . {})
                )
            )
        )"#,
        hex::encode([0x11u8; 32]),
        hex::encode([0xaau8; 32]),
        hex::encode([0xbbu8; 32]),
    );

    let puzzle_hash = compile_chialisp_template_hash_default(&deflation_puzzle.as_str())
        .expect("puzzle compilation failed");

    let (coin1, secrets1) = PrivateCoin::new_with_secrets(puzzle_hash, 100);
    let (coin2, secrets2) = PrivateCoin::new_with_secrets(puzzle_hash, 200);

    sim.add_coin(
        coin1.clone(),
        &secrets1,
        CoinMetadata {
            owner: "test".to_string(),
            coin_type: CoinType::Regular,
            notes: "coin1".to_string(),
        },
    );
    sim.add_coin(
        coin2.clone(),
        &secrets2,
        CoinMetadata {
            owner: "test".to_string(),
            coin_type: CoinType::Regular,
            notes: "coin2".to_string(),
        },
    );

    let merkle_root = sim.get_merkle_root().expect("no merkle root");
    let (path1, idx1) = sim.get_merkle_path_and_index(&coin1).expect("no path");
    let (path2, idx2) = sim.get_merkle_path_and_index(&coin2).expect("no path");

    let coins = vec![
        (&coin1, &deflation_puzzle, &[][..], &secrets1, path1, idx1),
        (&coin2, &deflation_puzzle, &[][..], &secrets2, path2, idx2),
    ];

    let result = Spender::create_ring_spend(coins, merkle_root);

    match result {
        Ok(_) => {
            eprintln!("❌ BUG: accepted deflation (300 → 100)");
            panic!("should reject unbalanced transaction");
        }
        Err(e) => {
            eprintln!("✓ correctly rejected: {}", e);
            assert!(e.to_string().contains("balance"));
        }
    }
}
