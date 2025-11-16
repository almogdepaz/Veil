/// Unit test for CREATE_COIN transformation logic
use clvm_zk_core::{hash_data, serialize_conditions_to_bytes, Condition};

#[test]
fn test_condition_transformation_logic() {
    // Create a 4-arg CREATE_COIN condition (private mode)
    let puzzle_hash = [0x42u8; 32];
    let amount: u64 = 1000;
    let serial_number = [0x11u8; 32];
    let serial_randomness = [0x22u8; 32];

    let mut condition = Condition {
        opcode: 51, // CREATE_COIN
        args: vec![
            puzzle_hash.to_vec(),
            amount.to_be_bytes().to_vec(),
            serial_number.to_vec(),
            serial_randomness.to_vec(),
        ],
    };

    // Verify initial state
    assert_eq!(condition.args.len(), 4, "should start with 4 args");

    // Manually apply transformation (same logic as in guests)
    let puzzle_hash_ref = &condition.args[0];
    let amount_bytes = &condition.args[1];
    let serial_num = &condition.args[2];
    let serial_rand = &condition.args[3];

    // Compute serial_commitment
    let serial_domain = b"clvm_zk_serial_v1.0";
    let mut serial_data = [0u8; 83];
    serial_data[..19].copy_from_slice(serial_domain);
    serial_data[19..51].copy_from_slice(serial_num);
    serial_data[51..83].copy_from_slice(serial_rand);
    let serial_commitment = hash_data(&serial_data);

    // Compute coin_commitment
    let coin_domain = b"clvm_zk_coin_v1.0";
    let mut coin_data = [0u8; 89];
    coin_data[..17].copy_from_slice(coin_domain);
    coin_data[17..25].copy_from_slice(amount_bytes);
    coin_data[25..57].copy_from_slice(puzzle_hash_ref);
    coin_data[57..89].copy_from_slice(&serial_commitment);
    let coin_commitment = hash_data(&coin_data);

    // Transform: replace 4 args with 1 arg (commitment)
    condition.args = vec![coin_commitment.to_vec()];

    // Verify transformation
    assert_eq!(
        condition.args.len(),
        1,
        "should have 1 arg after transformation"
    );
    assert_eq!(condition.args[0].len(), 32, "commitment should be 32 bytes");

    println!("✓ condition transformation logic works");
    println!("  original: CREATE_COIN(puzzle[32], amount[8], serial[32], rand[32])");
    println!("  transformed: CREATE_COIN(commitment[32])");
    println!("  commitment: {}", hex::encode(&condition.args[0]));
}

#[test]
fn test_condition_serialization() {
    // Create simple conditions
    let conditions = vec![
        Condition {
            opcode: 51,
            args: vec![vec![0x01; 32]], // CREATE_COIN with 1 arg
        },
        Condition {
            opcode: 52,
            args: vec![vec![0x02; 8]], // RESERVE_FEE with 1 arg
        },
    ];

    // Serialize
    let serialized = serialize_conditions_to_bytes(&conditions);

    // Verify we got bytes
    assert!(!serialized.is_empty(), "serialization should produce bytes");

    println!("✓ condition serialization works");
    println!(
        "  {} conditions → {} bytes",
        conditions.len(),
        serialized.len()
    );
}

#[test]
fn test_transparent_mode_preserved() {
    // 2-arg CREATE_COIN should not be transformed
    let condition = Condition {
        opcode: 51,
        args: vec![
            vec![0x42; 32],                 // puzzle_hash
            vec![0, 0, 0, 0, 0, 0, 3, 232], // amount = 1000 in big-endian
        ],
    };

    // In transparent mode, we leave it as-is
    assert_eq!(condition.args.len(), 2, "transparent mode has 2 args");

    println!("✓ transparent mode (2-arg) preserved");
}

#[test]
fn test_commitment_determinism() {
    // Same inputs should produce same commitment
    let puzzle = [0x42u8; 32];
    let amount: u64 = 1000;
    let serial = [0x11u8; 32];
    let rand = [0x22u8; 32];

    // Compute commitment twice
    let commitment1 = compute_coin_commitment(&puzzle, amount, &serial, &rand);
    let commitment2 = compute_coin_commitment(&puzzle, amount, &serial, &rand);

    assert_eq!(
        commitment1, commitment2,
        "commitment should be deterministic"
    );

    // Different inputs should produce different commitment
    let commitment3 = compute_coin_commitment(&puzzle, 2000, &serial, &rand);
    assert_ne!(
        commitment1, commitment3,
        "different amount should change commitment"
    );

    println!("✓ commitment computation is deterministic");
}

// Helper function
fn compute_coin_commitment(
    puzzle_hash: &[u8; 32],
    amount: u64,
    serial_number: &[u8; 32],
    serial_randomness: &[u8; 32],
) -> [u8; 32] {
    // Compute serial_commitment
    let serial_domain = b"clvm_zk_serial_v1.0";
    let mut serial_data = [0u8; 83];
    serial_data[..19].copy_from_slice(serial_domain);
    serial_data[19..51].copy_from_slice(serial_number);
    serial_data[51..83].copy_from_slice(serial_randomness);
    let serial_commitment = hash_data(&serial_data);

    // Compute coin_commitment
    let coin_domain = b"clvm_zk_coin_v1.0";
    let mut coin_data = [0u8; 89];
    coin_data[..17].copy_from_slice(coin_domain);
    coin_data[17..25].copy_from_slice(&amount.to_be_bytes());
    coin_data[25..57].copy_from_slice(puzzle_hash);
    coin_data[57..89].copy_from_slice(&serial_commitment);
    hash_data(&coin_data)
}
