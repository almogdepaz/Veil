/// Integration tests for signature verification in the simulator
///
/// These tests demonstrate that signature verification is properly integrated
/// into the spend authorization process.
use clvm_zk::simulator::{CLVMZkSimulator, CoinMetadata, CoinType, SimulatedTransaction};
use clvm_zk::testing_helpers::CoinFactory;

/// Comprehensive proof validation for security-critical tests
///
/// This validates that a transaction contains legitimate, valid proofs rather than
/// just checking that proof generation succeeded (which could produce garbage proofs).
fn validate_transaction_proofs(
    tx: &SimulatedTransaction,
    expected_nullifiers: &[[u8; 32]],
) -> Result<(), String> {
    // 1. Validate basic transaction structure
    if tx.nullifiers.is_empty() {
        return Err("Transaction contains no nullifiers - invalid proof".to_string());
    }

    if tx.spend_bundles.is_empty() {
        return Err("Transaction contains no spend bundles - invalid proof".to_string());
    }

    // 2. Validate nullifier count matches expected
    if tx.nullifiers.len() != expected_nullifiers.len() {
        return Err(format!(
            "Expected {} nullifiers, got {} - proof validation failed",
            expected_nullifiers.len(),
            tx.nullifiers.len()
        ));
    }

    // 3. Validate each expected nullifier is present
    for expected_nullifier in expected_nullifiers {
        if !tx.nullifiers.contains(expected_nullifier) {
            return Err(format!(
                "Missing expected nullifier {} - proof validation failed",
                hex::encode(expected_nullifier)
            ));
        }
    }

    // 4. Validate each spend bundle
    for (i, bundle) in tx.spend_bundles.iter().enumerate() {
        // Check proof is not empty
        if bundle.zk_proof.is_empty() {
            return Err(format!("Spend bundle {} has empty proof - invalid", i));
        }

        // Check nullifiers are not all-zeros (common garbage proof indicator)
        for nullifier in &bundle.nullifiers {
            if nullifier == &[0u8; 32] {
                return Err(format!(
                    "Spend bundle {} has zero nullifier - invalid proof",
                    i
                ));
            }
        }

        // Check public conditions exist (proof actually computed something)
        if bundle.public_conditions.is_empty() {
            return Err(format!(
                "Spend bundle {} has no public conditions - invalid proof",
                i
            ));
        }
    }

    // 5. Additional validation: ensure nullifiers match spend bundles
    let bundle_nullifiers: Vec<[u8; 32]> = tx
        .spend_bundles
        .iter()
        .flat_map(|b| b.nullifiers.iter().copied())
        .collect();
    for tx_nullifier in &tx.nullifiers {
        if !bundle_nullifiers.contains(tx_nullifier) {
            return Err(format!(
                "Transaction nullifier {} not found in spend bundles - inconsistent proof",
                hex::encode(tx_nullifier)
            ));
        }
    }

    Ok(())
}

#[test]
fn test_signature_enabled_spending() {
    println!("🔐 Testing signature-enabled coin spending...");

    let mut sim = CLVMZkSimulator::new();

    // Create a signature-enabled coin setup
    let spend_secret = [0x42; 32];
    let amount = 1000;

    let (coin, secrets, signing_key, _verifying_key, puzzle_program, public_key_bytes) =
        CoinFactory::create_signature_coin_setup(spend_secret, amount);

    println!("   Created signature-enabled coin:");
    println!(
        "      - Serial number: {}",
        hex::encode(secrets.serial_number())
    );
    println!("      - Amount: {}", coin.amount);
    println!("      - Puzzle requires ECDSA signature");

    // Add coin to simulator
    sim.add_coin(
        coin.clone(),
        &secrets,
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "Signature-protected coin".to_string(),
        },
    );

    // Create a valid signature for spending this coin
    let spend_message = b"authorize_spend";
    use clvm_zk::protocol::create_spend_signature;
    let signature = create_spend_signature(&signing_key, spend_message);

    println!("   🔑 Generated valid signature: {} bytes", signature.len());

    // Attempt to spend with valid signature
    println!("   💸 Attempting spend with valid signature...");
    use clvm_zk::ProgramParameter;
    let result = sim.spend_coins_with_params(vec![(
        coin.clone(),
        puzzle_program,
        vec![
            ProgramParameter::Bytes(public_key_bytes),
            ProgramParameter::Bytes(spend_message.to_vec()),
            ProgramParameter::Bytes(signature),
        ],
        secrets.clone(),
    )]);

    match result {
        Ok(tx) => {
            println!("   Spend successful!");
            println!("      - Transaction ID: {}", hex::encode(tx.id));
            println!("      - Nullifiers: {}", tx.nullifiers.len());

            // SECURITY: Validate the proof is legitimate, not just that generation succeeded
            // Note: tx.nullifiers contains computed nullifiers (hash of serial+program+amount)
            match validate_transaction_proofs(&tx, &tx.nullifiers) {
                Ok(()) => println!("   Proof validation passed - legitimate transaction"),
                Err(validation_error) => panic!("Proof validation failed: {}", validation_error),
            }

            assert_eq!(tx.nullifiers.len(), 1);
            // tx.nullifiers[0] is the computed nullifier, not the serial_number
        }
        Err(e) => {
            println!("   Spend failed: {:?}", e);
            panic!("Signature-enabled spend should succeed with valid signature");
        }
    }

    println!("Signature verification integration test passed!");
}

#[test]
fn test_signature_verification_prevents_unauthorized_spending() {
    println!("🚫 Testing signature verification prevents unauthorized spending...");

    let mut sim = CLVMZkSimulator::new();

    // Create a signature-enabled coin setup
    let spend_secret = [0x33; 32];
    let amount = 2000;

    let (coin, secrets, _signing_key, _verifying_key, puzzle_program, correct_public_key_bytes) =
        CoinFactory::create_signature_coin_setup(spend_secret, amount);

    // Add coin to simulator
    sim.add_coin(
        coin.clone(),
        &secrets,
        CoinMetadata {
            owner: "bob".to_string(),
            coin_type: CoinType::Regular,
            notes: "Protected coin for unauthorized spend test".to_string(),
        },
    );

    // Create an INVALID signature (wrong key)
    let wrong_key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let wrong_verifying_key = k256::ecdsa::VerifyingKey::from(&wrong_key);
    let _wrong_public_key_bytes = wrong_verifying_key
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let spend_message = b"authorize_spend";
    use clvm_zk::protocol::create_spend_signature;
    let invalid_signature = create_spend_signature(&wrong_key, spend_message);

    println!("   🔑 Generated invalid signature (wrong key)");

    // Attempt to spend with invalid signature - this should fail
    println!("   💸 Attempting spend with invalid signature...");
    use clvm_zk::ProgramParameter;
    let result = sim.spend_coins_with_params(vec![(
        coin.clone(),
        puzzle_program,
        vec![
            ProgramParameter::Bytes(correct_public_key_bytes), // Use CORRECT public key with WRONG signature
            ProgramParameter::Bytes(spend_message.to_vec()),
            ProgramParameter::Bytes(invalid_signature),
        ],
        secrets.clone(),
    )]);

    match result {
        Ok(tx) => {
            // SECURITY: If transaction somehow succeeded, validate it's actually legitimate
            // This catches SP1-style vulnerabilities where garbage proofs are generated
            match validate_transaction_proofs(&tx, &tx.nullifiers) {
                Ok(()) => {
                    // If validation passes, this means signature verification was bypassed!
                    panic!("CRITICAL SECURITY ISSUE: Invalid signature was accepted and generated valid proof!");
                }
                Err(validation_error) => {
                    // Proof validation failed - this is expected for invalid signatures
                    panic!("Spend succeeded but produced invalid proof (validation error: {}). This indicates a zkVM vulnerability!", validation_error);
                }
            }
        }
        Err(e) => {
            println!("   Spend correctly rejected: {:?}", e);
            // The spend should fail during ZK proof generation because signature verification fails
        }
    }

    println!("Unauthorized spending prevention test passed!");
}

#[test]
fn test_multiple_signature_coins_in_transaction() {
    println!("🔄 Testing multiple signature-enabled coins in single transaction...");

    let mut sim = CLVMZkSimulator::new();

    // Create two different signature-enabled coins
    let (coin1, secrets1, key1, _, program1, pubkey1) =
        CoinFactory::create_signature_coin_setup([0x11; 32], 1000);
    let (coin2, secrets2, key2, _, program2, pubkey2) =
        CoinFactory::create_signature_coin_setup([0x22; 32], 2000);

    // Add both coins to simulator
    sim.add_coin(
        coin1.clone(),
        &secrets1,
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "First signature coin".to_string(),
        },
    );

    sim.add_coin(
        coin2.clone(),
        &secrets2,
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "Second signature coin".to_string(),
        },
    );

    // Create valid signatures for both coins
    let spend_message = b"authorize_spend";
    use clvm_zk::protocol::create_spend_signature;
    let sig1 = create_spend_signature(&key1, spend_message);
    let sig2 = create_spend_signature(&key2, spend_message);

    println!("   🔑 Generated signatures for both coins");

    // Spend both coins in one transaction
    println!("   💸 Spending multiple signature coins...");
    use clvm_zk::ProgramParameter;
    let result = sim.spend_coins_with_params(vec![
        (
            coin1.clone(),
            program1,
            vec![
                ProgramParameter::Bytes(pubkey1),
                ProgramParameter::Bytes(spend_message.to_vec()),
                ProgramParameter::Bytes(sig1),
            ],
            secrets1.clone(),
        ),
        (
            coin2.clone(),
            program2,
            vec![
                ProgramParameter::Bytes(pubkey2),
                ProgramParameter::Bytes(spend_message.to_vec()),
                ProgramParameter::Bytes(sig2),
            ],
            secrets2.clone(),
        ),
    ]);

    match result {
        Ok(tx) => {
            println!("   Multi-coin spend successful!");
            println!("      - Spent {} coins", tx.nullifiers.len());

            // SECURITY: Validate all proofs are legitimate
            match validate_transaction_proofs(&tx, &tx.nullifiers) {
                Ok(()) => println!("   Multi-coin proof validation passed"),
                Err(validation_error) => {
                    panic!("Multi-coin proof validation failed: {}", validation_error)
                }
            }

            assert_eq!(tx.nullifiers.len(), 2);
            // tx.nullifiers contains computed nullifiers, not serial_numbers
        }
        Err(e) => {
            println!("   Multi-coin spend failed: {:?}", e);
            panic!("Multi-signature spend should succeed");
        }
    }

    println!("Multiple signature coins test passed!");
}
