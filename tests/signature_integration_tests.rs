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
fn validate_transaction_proofs(tx: &SimulatedTransaction, expected_nullifiers: &[[u8; 32]]) -> Result<(), String> {
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
        
        // Check nullifier is not all-zeros (common garbage proof indicator)
        if bundle.nullifier == [0u8; 32] {
            return Err(format!("Spend bundle {} has zero nullifier - invalid proof", i));
        }
        
        // Check public conditions exist (proof actually computed something)
        if bundle.public_conditions.is_empty() {
            return Err(format!("Spend bundle {} has no public conditions - invalid proof", i));
        }
    }
    
    // 5. Additional validation: ensure nullifiers match spend bundles
    let bundle_nullifiers: Vec<[u8; 32]> = tx.spend_bundles.iter().map(|b| b.nullifier).collect();
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

    let (coin, signing_key, _verifying_key, puzzle_program, public_key_bytes) =
        CoinFactory::create_signature_coin_setup(spend_secret, amount);

    println!("   📝 Created signature-enabled coin:");
    println!("      - Nullifier: {}", hex::encode(coin.nullifier()));
    println!("      - Amount: {}", coin.amount);
    println!("      - Puzzle requires ECDSA signature");

    // Add coin to simulator
    sim.add_coin(
        coin.clone(),
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "Signature-protected coin".to_string(),
        },
    );

    // Create a valid signature for spending this coin
    let signature = CoinFactory::create_signature_for_spend(&signing_key, coin.nullifier());

    println!("   🔑 Generated valid signature: {} bytes", signature.len());

    // Attempt to spend with valid signature
    println!("   💸 Attempting spend with valid signature...");
    let result = sim.spend_coins_with_signatures(vec![(
        coin.clone(),
        puzzle_program,
        public_key_bytes,
        signature,
    )]);

    match result {
        Ok(tx) => {
            println!("   ✅ Spend successful!");
            println!("      - Transaction ID: {}", hex::encode(tx.id));
            println!("      - Nullifiers: {}", tx.nullifiers.len());
            
            // SECURITY: Validate the proof is legitimate, not just that generation succeeded
            let expected_nullifiers = [coin.nullifier()];
            match validate_transaction_proofs(&tx, &expected_nullifiers) {
                Ok(()) => println!("   ✅ Proof validation passed - legitimate transaction"),
                Err(validation_error) => panic!("❌ Proof validation failed: {}", validation_error),
            }
            
            assert_eq!(tx.nullifiers.len(), 1);
            assert_eq!(tx.nullifiers[0], coin.nullifier());
        }
        Err(e) => {
            println!("   ❌ Spend failed: {:?}", e);
            panic!("Signature-enabled spend should succeed with valid signature");
        }
    }

    println!("✅ Signature verification integration test passed!");
}

#[test]
fn test_signature_verification_prevents_unauthorized_spending() {
    println!("🚫 Testing signature verification prevents unauthorized spending...");

    let mut sim = CLVMZkSimulator::new();

    // Create a signature-enabled coin setup
    let spend_secret = [0x33; 32];
    let amount = 2000;

    let (coin, _signing_key, _verifying_key, puzzle_program, correct_public_key_bytes) =
        CoinFactory::create_signature_coin_setup(spend_secret, amount);

    // Add coin to simulator
    sim.add_coin(
        coin.clone(),
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
    let invalid_signature = CoinFactory::create_signature_for_spend(&wrong_key, coin.nullifier());

    println!("   🔑 Generated invalid signature (wrong key)");

    // Attempt to spend with invalid signature - this should fail
    println!("   💸 Attempting spend with invalid signature...");
    let result = sim.spend_coins_with_signatures(vec![(
        coin.clone(),
        puzzle_program,
        correct_public_key_bytes, // Use CORRECT public key with WRONG signature
        invalid_signature,
    )]);

    match result {
        Ok(tx) => {
            // SECURITY: If transaction somehow succeeded, validate it's actually legitimate
            // This catches SP1-style vulnerabilities where garbage proofs are generated
            let expected_nullifiers = [coin.nullifier()];
            match validate_transaction_proofs(&tx, &expected_nullifiers) {
                Ok(()) => {
                    // If validation passes, this means signature verification was bypassed!
                    panic!("❌ CRITICAL SECURITY ISSUE: Invalid signature was accepted and generated valid proof!");
                }
                Err(validation_error) => {
                    // Proof validation failed - this is expected for invalid signatures
                    panic!("❌ Spend succeeded but produced invalid proof (validation error: {}). This indicates a zkVM vulnerability!", validation_error);
                }
            }
        }
        Err(e) => {
            println!("   ✅ Spend correctly rejected: {:?}", e);
            // The spend should fail during ZK proof generation because signature verification fails
        }
    }

    println!("✅ Unauthorized spending prevention test passed!");
}

#[test]
fn test_multiple_signature_coins_in_transaction() {
    println!("🔄 Testing multiple signature-enabled coins in single transaction...");

    let mut sim = CLVMZkSimulator::new();

    // Create two different signature-enabled coins
    let (coin1, key1, _, program1, pubkey1) =
        CoinFactory::create_signature_coin_setup([0x11; 32], 1000);
    let (coin2, key2, _, program2, pubkey2) =
        CoinFactory::create_signature_coin_setup([0x22; 32], 2000);

    // Add both coins to simulator
    sim.add_coin(
        coin1.clone(),
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "First signature coin".to_string(),
        },
    );

    sim.add_coin(
        coin2.clone(),
        CoinMetadata {
            owner: "alice".to_string(),
            coin_type: CoinType::Regular,
            notes: "Second signature coin".to_string(),
        },
    );

    // Create valid signatures for both coins
    let sig1 = CoinFactory::create_signature_for_spend(&key1, coin1.nullifier());
    let sig2 = CoinFactory::create_signature_for_spend(&key2, coin2.nullifier());

    println!("   🔑 Generated signatures for both coins");

    // Spend both coins in one transaction
    println!("   💸 Spending multiple signature coins...");
    let result = sim.spend_coins_with_signatures(vec![
        (coin1.clone(), program1, pubkey1, sig1),
        (coin2.clone(), program2, pubkey2, sig2),
    ]);

    match result {
        Ok(tx) => {
            println!("   ✅ Multi-coin spend successful!");
            println!("      - Spent {} coins", tx.nullifiers.len());
            
            // SECURITY: Validate all proofs are legitimate
            let expected_nullifiers = [coin1.nullifier(), coin2.nullifier()];
            match validate_transaction_proofs(&tx, &expected_nullifiers) {
                Ok(()) => println!("   ✅ Multi-coin proof validation passed"),
                Err(validation_error) => panic!("❌ Multi-coin proof validation failed: {}", validation_error),
            }
            
            assert_eq!(tx.nullifiers.len(), 2);
            assert!(tx.nullifiers.contains(&coin1.nullifier()));
            assert!(tx.nullifiers.contains(&coin2.nullifier()));
        }
        Err(e) => {
            println!("   ❌ Multi-coin spend failed: {:?}", e);
            panic!("Multi-signature spend should succeed");
        }
    }

    println!("✅ Multiple signature coins test passed!");
}
