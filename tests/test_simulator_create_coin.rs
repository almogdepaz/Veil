/// test simulator integration with 4-arg 51 (output privacy)
#[cfg(feature = "mock")]
use clvm_zk::protocol::PrivateCoin;
#[cfg(feature = "mock")]
use clvm_zk::simulator::*;
#[cfg(feature = "mock")]
use clvm_zk_core::chialisp::compile_chialisp_template_hash_default;
#[cfg(feature = "mock")]
use clvm_zk_core::coin_commitment::{CoinSecrets, SerialCommitment};

#[test]
#[cfg(feature = "mock")]
fn test_create_and_spend_coins() {
    let mut sim = CLVMZkSimulator::new();

    // program that creates 2 new coins
    let alice_program = r#"
        (mod (puzzle1 puzzle2 serial1 rand1 serial2 rand2)
            (list
                (list 51 puzzle1 600 serial1 rand1)
                (list 51 puzzle2 300 serial2 rand2)))
    "#;

    // compute actual puzzle hash for alice's coin
    let puzzle_hash = compile_chialisp_template_hash_default(alice_program)
        .expect("failed to compile alice program");

    let (alice_coin, alice_secrets) = PrivateCoin::new_with_secrets(puzzle_hash, 1000);

    sim.add_coin(
        alice_coin.clone(),
        &alice_secrets,
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "genesis".to_string(),
        },
    );

    // alice sends 600 to bob, 300 to charlie (100 implicit fee)
    // bob will spend with an empty program
    let bob_program = "(mod () ())";
    let bob_puzzle =
        compile_chialisp_template_hash_default(bob_program).expect("failed to compile bob program");

    // charlie uses dummy puzzle for now (not spending)
    let charlie_puzzle = [0x33u8; 32];

    // generate new coins for bob and charlie
    let bob_serial: [u8; 32] = rand::random();
    let bob_rand: [u8; 32] = rand::random();
    let bob_secrets = CoinSecrets::new(bob_serial, bob_rand);
    let bob_serial_commitment = SerialCommitment::compute(
        &bob_serial,
        &bob_rand,
        clvm_zk::crypto_utils::hash_data_default,
    );
    let bob_coin = PrivateCoin {
        puzzle_hash: bob_puzzle,
        amount: 600,
        serial_commitment: bob_serial_commitment,
    };

    let charlie_serial: [u8; 32] = rand::random();
    let charlie_rand: [u8; 32] = rand::random();
    let charlie_secrets = CoinSecrets::new(charlie_serial, charlie_rand);
    let charlie_serial_commitment = SerialCommitment::compute(
        &charlie_serial,
        &charlie_rand,
        clvm_zk::crypto_utils::hash_data_default,
    );
    let charlie_coin = PrivateCoin {
        puzzle_hash: charlie_puzzle,
        amount: 300,
        serial_commitment: charlie_serial_commitment,
    };

    let params = vec![
        clvm_zk::ProgramParameter::Bytes(bob_puzzle.to_vec()),
        clvm_zk::ProgramParameter::Bytes(charlie_puzzle.to_vec()),
        clvm_zk::ProgramParameter::Bytes(bob_serial.to_vec()),
        clvm_zk::ProgramParameter::Bytes(bob_rand.to_vec()),
        clvm_zk::ProgramParameter::Bytes(charlie_serial.to_vec()),
        clvm_zk::ProgramParameter::Bytes(charlie_rand.to_vec()),
    ];

    let output_coins = vec![
        (
            bob_coin.clone(),
            bob_secrets.clone(),
            CoinMetadata {
                owner: "bob".to_string(),
                coin_type: CoinType::Regular,
                notes: "payment from alice".to_string(),
            },
        ),
        (
            charlie_coin.clone(),
            charlie_secrets.clone(),
            CoinMetadata {
                owner: "charlie".to_string(),
                coin_type: CoinType::Regular,
                notes: "payment from alice".to_string(),
            },
        ),
    ];

    // spend alice's coin, creating bob's and charlie's coins
    let alice_serial_num = alice_secrets.serial_number;
    let result = sim.spend_coins_with_params_and_outputs(
        vec![(alice_coin, alice_program.to_string(), params, alice_secrets)],
        output_coins,
    );

    assert!(result.is_ok(), "spend should succeed: {:?}", result.err());
    let tx = result.unwrap();

    println!("✓ alice → bob(600) + charlie(300)");
    println!("  tx: {}", hex::encode(tx.id));
    println!("  nullifiers: {}", tx.nullifiers.len());

    // verify simulator state
    assert!(
        sim.has_nullifier(&tx.nullifiers[0]),
        "alice's nullifier should be tracked"
    );
    assert!(
        sim.get_coin_info(&alice_serial_num).is_none(),
        "alice's coin should be spent"
    );
    assert!(
        sim.get_coin_info(&bob_serial).is_some(),
        "bob's coin should exist"
    );
    assert!(
        sim.get_coin_info(&charlie_serial).is_some(),
        "charlie's coin should exist"
    );

    println!("✓ coins tracked in simulator");

    // now bob spends his coin
    let result2 = sim.spend_coins_with_params_and_outputs(
        vec![(bob_coin, bob_program.to_string(), vec![], bob_secrets)],
        vec![],
    );

    assert!(
        result2.is_ok(),
        "bob should be able to spend his coin: {:?}",
        result2.err()
    );
    let tx2 = result2.unwrap();

    println!("✓ bob spent his coin");
    println!("  tx: {}", hex::encode(tx2.id));

    assert!(
        sim.get_coin_info(&bob_serial).is_none(),
        "bob's coin should be spent"
    );
    assert!(
        sim.get_coin_info(&charlie_serial).is_some(),
        "charlie's coin still exists"
    );

    println!("✓ full create → spend cycle working");
}

#[test]
#[cfg(feature = "mock")]
fn test_create_coin_adds_to_merkle_tree() {
    let mut sim = CLVMZkSimulator::new();

    // program that creates 2 new coins using 4-arg 51
    let program = r#"
        (mod (puzzle1 puzzle2 serial1 rand1 serial2 rand2)
            (list
                (list 51 puzzle1 500 serial1 rand1)
                (list 51 puzzle2 300 serial2 rand2)))
    "#;

    // compute actual puzzle hash for alice's coin
    let puzzle_hash =
        compile_chialisp_template_hash_default(program).expect("failed to compile program");

    let (alice_coin, alice_secrets) = PrivateCoin::new_with_secrets(puzzle_hash, 1000);

    sim.add_coin(
        alice_coin.clone(),
        &alice_secrets,
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "genesis".to_string(),
        },
    );

    // recipient puzzle hashes
    let puzzle1 = [0x22u8; 32];
    let puzzle2 = [0x33u8; 32];

    // generate random serials for output coins
    let serial1: [u8; 32] = rand::random();
    let rand1: [u8; 32] = rand::random();
    let serial2: [u8; 32] = rand::random();
    let rand2: [u8; 32] = rand::random();

    let params = vec![
        clvm_zk::ProgramParameter::Bytes(puzzle1.to_vec()),
        clvm_zk::ProgramParameter::Bytes(puzzle2.to_vec()),
        clvm_zk::ProgramParameter::Bytes(serial1.to_vec()),
        clvm_zk::ProgramParameter::Bytes(rand1.to_vec()),
        clvm_zk::ProgramParameter::Bytes(serial2.to_vec()),
        clvm_zk::ProgramParameter::Bytes(rand2.to_vec()),
    ];

    // spend alice's coin, creating 2 new coins
    let result = sim.spend_coins_with_params(vec![(
        alice_coin,
        program.to_string(),
        params,
        alice_secrets,
    )]);

    assert!(result.is_ok(), "spend should succeed: {:?}", result.err());
    let tx = result.unwrap();

    println!(
        "✓ spend succeeded, created transaction {}",
        hex::encode(tx.id)
    );
    println!("  nullifiers: {}", tx.nullifiers.len());
    println!("  spend bundles: {}", tx.spend_bundles.len());

    // verify nullifier was added
    let alice_nullifier = tx.nullifiers[0];
    assert!(
        sim.has_nullifier(&alice_nullifier),
        "nullifier should be in set"
    );

    println!("✓ simulator integration with 4-arg 51 working");
}

#[test]
#[cfg(feature = "mock")]
#[ignore = "simulator only supports private coins, not transparent mode"]
fn test_create_coin_transparent_mode() {
    let mut sim = CLVMZkSimulator::new();

    // program using 2-arg 51 (transparent mode)
    let program = r#"
        (mod (puzzle)
            (list (list 51 puzzle 1000)))
    "#;

    // compute actual puzzle hash
    let puzzle_hash =
        compile_chialisp_template_hash_default(program).expect("failed to compile program");

    let (coin, secrets) = PrivateCoin::new_with_secrets(puzzle_hash, 2000);

    sim.add_coin(
        coin.clone(),
        &secrets,
        CoinMetadata {
            owner: "test".to_string(),
            coin_type: CoinType::Regular,
            notes: "test".to_string(),
        },
    );

    let puzzle = [0x55u8; 32];
    let params = vec![clvm_zk::ProgramParameter::Bytes(puzzle.to_vec())];

    let result = sim.spend_coins_with_params(vec![(coin, program.to_string(), params, secrets)]);

    assert!(
        result.is_ok(),
        "transparent mode should work: {:?}",
        result.err()
    );

    println!("✓ transparent mode (2-arg 51) working");
}
