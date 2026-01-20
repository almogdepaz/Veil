// Ring Spend Debug Test
// Tests the multi-coin ring spend path with detailed debug output

use clvm_zk::protocol::{PrivateCoin, Spender};
use clvm_zk::simulator::*;
use clvm_zk_core::chialisp::compile_chialisp_template_hash_default;
use clvm_zk_core::coin_commitment::XCH_TAIL;

/// Simple test puzzle that returns a fixed value
fn simple_puzzle() -> &'static str {
    "1000"
}

/// Create a CAT tail hash for testing
fn test_cat_tail_hash() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(b"test_cat_tail_v1").into()
}

#[test]
fn test_ring_spend_merkle_debug() {
    eprintln!("\n\n========================================");
    eprintln!("      RING SPEND MERKLE DEBUG TEST      ");
    eprintln!("========================================\n");

    let mut sim = CLVMZkSimulator::new();

    // Use CAT coins (non-XCH) so we exercise the ring spend path
    let tail_hash = test_cat_tail_hash();
    eprintln!("Using CAT tail_hash: {}", hex::encode(tail_hash));

    let puzzle_code = simple_puzzle();
    let puzzle_hash =
        compile_chialisp_template_hash_default(puzzle_code).expect("failed to compile puzzle");
    eprintln!("Puzzle code: {}", puzzle_code);
    eprintln!("Puzzle hash: {}", hex::encode(puzzle_hash));

    // Create 2 CAT coins
    let (coin1, secrets1) = PrivateCoin::new_with_secrets_and_tail(puzzle_hash, 100, tail_hash);
    let (coin2, secrets2) = PrivateCoin::new_with_secrets_and_tail(puzzle_hash, 200, tail_hash);

    eprintln!("\n--- COIN 1 ---");
    eprintln!("  amount: {}", coin1.amount);
    eprintln!("  puzzle_hash: {}", hex::encode(coin1.puzzle_hash));
    eprintln!(
        "  serial_commitment: {}",
        hex::encode(coin1.serial_commitment.as_bytes())
    );
    eprintln!("  tail_hash: {}", hex::encode(coin1.tail_hash));
    eprintln!(
        "  secrets1.serial_number: {}",
        hex::encode(secrets1.serial_number)
    );

    eprintln!("\n--- COIN 2 ---");
    eprintln!("  amount: {}", coin2.amount);
    eprintln!("  puzzle_hash: {}", hex::encode(coin2.puzzle_hash));
    eprintln!(
        "  serial_commitment: {}",
        hex::encode(coin2.serial_commitment.as_bytes())
    );
    eprintln!("  tail_hash: {}", hex::encode(coin2.tail_hash));
    eprintln!(
        "  secrets2.serial_number: {}",
        hex::encode(secrets2.serial_number)
    );

    // Add coins to simulator
    eprintln!("\n--- ADDING COINS TO SIMULATOR ---");
    sim.add_coin(
        coin1.clone(),
        &secrets1,
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Cat,
            notes: "CAT coin 1".to_string(),
        },
    );

    sim.add_coin(
        coin2.clone(),
        &secrets2,
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Cat,
            notes: "CAT coin 2".to_string(),
        },
    );

    // Dump tree state
    sim.debug_dump_tree_state();

    // Verify merkle proofs for each coin individually
    eprintln!("\n--- VERIFYING MERKLE PROOFS INDIVIDUALLY ---");

    let result1 = sim.debug_verify_merkle_path(&coin1, "COIN 1");
    match result1 {
        Ok(()) => eprintln!("Coin 1 merkle proof: OK"),
        Err(e) => eprintln!("Coin 1 merkle proof: FAILED - {}", e),
    }

    let result2 = sim.debug_verify_merkle_path(&coin2, "COIN 2");
    match result2 {
        Ok(()) => eprintln!("Coin 2 merkle proof: OK"),
        Err(e) => eprintln!("Coin 2 merkle proof: FAILED - {}", e),
    }

    // Get merkle paths and root
    let merkle_root = sim.get_merkle_root().expect("no merkle root");
    eprintln!("\n--- PREPARING RING SPEND ---");
    eprintln!("merkle_root: {}", hex::encode(merkle_root));

    let (path1, idx1) = sim
        .get_merkle_path_and_index(&coin1)
        .expect("no path for coin1");
    let (path2, idx2) = sim
        .get_merkle_path_and_index(&coin2)
        .expect("no path for coin2");

    eprintln!("coin1: leaf_index={}, path_len={}", idx1, path1.len());
    eprintln!("coin2: leaf_index={}, path_len={}", idx2, path2.len());

    // Now attempt the ring spend
    eprintln!("\n--- EXECUTING RING SPEND ---");

    let coins = vec![
        (&coin1, puzzle_code, &[][..], &secrets1, path1, idx1),
        (&coin2, puzzle_code, &[][..], &secrets2, path2, idx2),
    ];

    match Spender::create_ring_spend(coins, merkle_root) {
        Ok(bundle) => {
            eprintln!("\n✓ RING SPEND SUCCEEDED!");
            eprintln!("  nullifiers: {}", bundle.nullifiers.len());
            for (i, n) in bundle.nullifiers.iter().enumerate() {
                eprintln!("    [{}]: {}", i, hex::encode(n));
            }
            eprintln!("  proof_size: {} bytes", bundle.proof_size());
        }
        Err(e) => {
            eprintln!("\n✗ RING SPEND FAILED: {:?}", e);
        }
    }

    eprintln!("\n========================================");
    eprintln!("          TEST COMPLETE                 ");
    eprintln!("========================================\n");
}

#[test]
fn test_ring_spend_xch_debug() {
    eprintln!("\n\n========================================");
    eprintln!("      RING SPEND XCH DEBUG TEST         ");
    eprintln!("========================================\n");

    let mut sim = CLVMZkSimulator::new();

    // Use XCH coins (tail_hash = all zeros)
    let tail_hash = XCH_TAIL;
    eprintln!("Using XCH tail_hash: {}", hex::encode(tail_hash));

    let puzzle_code = simple_puzzle();
    let puzzle_hash =
        compile_chialisp_template_hash_default(puzzle_code).expect("failed to compile puzzle");

    // Create 2 XCH coins
    let (coin1, secrets1) = PrivateCoin::new_with_secrets(puzzle_hash, 100);
    let (coin2, secrets2) = PrivateCoin::new_with_secrets(puzzle_hash, 200);

    eprintln!("coin1: amount={}, is_xch={}", coin1.amount, coin1.is_xch());
    eprintln!("coin2: amount={}, is_xch={}", coin2.amount, coin2.is_xch());

    // Add coins to simulator
    sim.add_coin(
        coin1.clone(),
        &secrets1,
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "XCH coin 1".to_string(),
        },
    );

    sim.add_coin(
        coin2.clone(),
        &secrets2,
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "XCH coin 2".to_string(),
        },
    );

    // Dump tree state
    sim.debug_dump_tree_state();

    // Verify merkle proofs
    let _ = sim.debug_verify_merkle_path(&coin1, "XCH COIN 1");
    let _ = sim.debug_verify_merkle_path(&coin2, "XCH COIN 2");

    // Get merkle paths and root
    let merkle_root = sim.get_merkle_root().expect("no merkle root");
    let (path1, idx1) = sim
        .get_merkle_path_and_index(&coin1)
        .expect("no path for coin1");
    let (path2, idx2) = sim
        .get_merkle_path_and_index(&coin2)
        .expect("no path for coin2");

    // Execute ring spend
    eprintln!("\n--- EXECUTING XCH RING SPEND ---");

    let coins = vec![
        (&coin1, puzzle_code, &[][..], &secrets1, path1, idx1),
        (&coin2, puzzle_code, &[][..], &secrets2, path2, idx2),
    ];

    match Spender::create_ring_spend(coins, merkle_root) {
        Ok(bundle) => {
            eprintln!("\n✓ XCH RING SPEND SUCCEEDED!");
            eprintln!("  nullifiers: {}", bundle.nullifiers.len());
        }
        Err(e) => {
            eprintln!("\n✗ XCH RING SPEND FAILED: {:?}", e);
        }
    }
}

#[test]
fn test_single_coin_vs_ring_merkle() {
    eprintln!("\n\n========================================");
    eprintln!("   SINGLE vs RING MERKLE COMPARISON     ");
    eprintln!("========================================\n");

    let mut sim = CLVMZkSimulator::new();

    let puzzle_code = simple_puzzle();
    let puzzle_hash =
        compile_chialisp_template_hash_default(puzzle_code).expect("failed to compile puzzle");

    // Create 3 coins
    let (coin1, secrets1) = PrivateCoin::new_with_secrets(puzzle_hash, 100);
    let (coin2, secrets2) = PrivateCoin::new_with_secrets(puzzle_hash, 200);
    let (coin3, secrets3) = PrivateCoin::new_with_secrets(puzzle_hash, 300);

    // Add all coins
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
    sim.add_coin(
        coin3.clone(),
        &secrets3,
        CoinMetadata {
            owner: "test".to_string(),
            coin_type: CoinType::Regular,
            notes: "coin3".to_string(),
        },
    );

    sim.debug_dump_tree_state();

    // Test single-coin spend first
    eprintln!("\n--- SINGLE COIN SPEND (coin1) ---");
    let single_result = sim.spend_coins(vec![(
        coin1.clone(),
        puzzle_code.to_string(),
        secrets1.clone(),
    )]);

    match single_result {
        Ok(tx) => {
            eprintln!(
                "✓ Single spend succeeded, nullifier: {}",
                hex::encode(&tx.nullifiers[0])
            );
        }
        Err(e) => {
            eprintln!("✗ Single spend failed: {:?}", e);
        }
    }

    // Now test ring spend with remaining coins
    eprintln!("\n--- RING SPEND (coin2 + coin3) ---");
    let merkle_root = sim.get_merkle_root().expect("no merkle root");
    let (path2, idx2) = sim
        .get_merkle_path_and_index(&coin2)
        .expect("no path for coin2");
    let (path3, idx3) = sim
        .get_merkle_path_and_index(&coin3)
        .expect("no path for coin3");

    eprintln!("After single spend:");
    eprintln!("  coin2: idx={}, path_len={}", idx2, path2.len());
    eprintln!("  coin3: idx={}, path_len={}", idx3, path3.len());

    // Debug verify the paths
    let _ = sim.debug_verify_merkle_path(&coin2, "COIN 2 (after single spend)");
    let _ = sim.debug_verify_merkle_path(&coin3, "COIN 3 (after single spend)");

    let coins = vec![
        (&coin2, puzzle_code, &[][..], &secrets2, path2, idx2),
        (&coin3, puzzle_code, &[][..], &secrets3, path3, idx3),
    ];

    match Spender::create_ring_spend(coins, merkle_root) {
        Ok(bundle) => {
            eprintln!("\n✓ Ring spend succeeded!");
            eprintln!("  nullifiers: {}", bundle.nullifiers.len());
        }
        Err(e) => {
            eprintln!("\n✗ Ring spend failed: {:?}", e);
        }
    }
}
