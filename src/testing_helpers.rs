//! Testing helpers for CLVM-ZK protocol testing
//!
//! This module contains utilities and helpers specifically designed for testing
//! the CLVM-ZK protocol, including coin factories, recovery simulators, and test scenarios.

use crate::protocol::{create_spend_signature, create_test_signature_setup, PrivateCoin};
use crate::simulator::{CLVMZkSimulator, CoinMetadata, CoinType, SimulatorError};
use sha2::{Digest, Sha256};

// ============================================================================
// Testing Helpers
// ============================================================================

/// Create test coins with user-supplied spend secrets
pub struct CoinFactory;

impl CoinFactory {
    /// Create coin with explicit spend secret
    pub fn create_coin(
        spend_secret: [u8; 32],
        puzzle_type: PuzzleType,
        amount: u64,
    ) -> PrivateCoin {
        let puzzle_hash = Self::puzzle_type_to_hash(puzzle_type);
        PrivateCoin::new(spend_secret, puzzle_hash, amount)
    }

    /// Create multiple coins for testing
    pub fn create_coins_batch(
        base_secret: [u8; 32],
        count: u32,
        puzzle_type: PuzzleType,
        amount: u64,
    ) -> Vec<PrivateCoin> {
        (0..count)
            .map(|i| {
                let mut hasher = Sha256::new();
                hasher.update(base_secret);
                hasher.update(i.to_le_bytes());
                let derived_secret: [u8; 32] = hasher.finalize().into();
                Self::create_coin(derived_secret, puzzle_type, amount)
            })
            .collect()
    }

    /// Create coins for different users with viewing tags
    pub fn create_user_coins(
        users: &[&str],
        amounts: &[u64],
        puzzle_type: PuzzleType,
    ) -> Vec<(String, PrivateCoin, [u8; 4])> {
        users
            .iter()
            .zip(amounts.iter())
            .enumerate()
            .map(|(i, (user, &amount))| {
                let secret = Self::derive_user_secret(user, i as u32);
                let coin = Self::create_coin(secret, puzzle_type, amount);
                let viewing_tag = Self::generate_viewing_tag(user, i as u32);
                (user.to_string(), coin, viewing_tag)
            })
            .collect()
    }

    /// Derive deterministic spend secret for a user and index
    pub fn derive_user_secret(user: &str, index: u32) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"user_spend_secret_v1");
        hasher.update(user.as_bytes());
        hasher.update(index.to_le_bytes());
        hasher.finalize().into()
    }

    /// Generate viewing tag for wallet discovery (delegated to crypto_utils)
    pub fn generate_viewing_tag(user: &str, index: u32) -> [u8; 4] {
        crate::crypto_utils::generate_viewing_tag_from_string(user, index)
    }

    fn puzzle_type_to_hash(puzzle_type: PuzzleType) -> [u8; 32] {
        let puzzle_code = match puzzle_type {
            PuzzleType::P2PK => "1000",
            PuzzleType::Multisig => "2000",
            PuzzleType::Timelock => "3000",
            PuzzleType::Atomic => "4000",
        };
        Sha256::digest(puzzle_code.as_bytes()).into()
    }

    /// Create a signature-enabled coin setup for testing
    ///
    /// Returns (coin, signing_key, verifying_key, puzzle_program, public_key_bytes) for complete signature testing
    pub fn create_signature_coin_setup(
        spend_secret: [u8; 32],
        amount: u64,
    ) -> (
        PrivateCoin,
        k256::ecdsa::SigningKey,
        k256::ecdsa::VerifyingKey,
        String,
        Vec<u8>,
    ) {
        // Generate signature setup
        let (signing_key, verifying_key, puzzle_program, puzzle_hash) =
            create_test_signature_setup().expect("Failed to create signature setup");

        // Get public key bytes
        let encoded_point = verifying_key.to_encoded_point(true);
        let public_key_bytes = encoded_point.as_bytes().to_vec();

        // Create coin with signature puzzle hash
        let coin = PrivateCoin::new(spend_secret, puzzle_hash, amount);

        (
            coin,
            signing_key,
            verifying_key,
            puzzle_program,
            public_key_bytes,
        )
    }

    /// Create a valid signature for spending a signature-enabled coin
    ///
    /// This creates the standardized spend authorization signature
    pub fn create_signature_for_spend(
        signing_key: &k256::ecdsa::SigningKey,
        coin_nullifier: [u8; 32],
    ) -> Vec<u8> {
        let spend_message = format!("authorize_spend_{}", hex::encode(coin_nullifier));
        create_spend_signature(signing_key, spend_message.as_bytes())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PuzzleType {
    P2PK,
    Multisig,
    Timelock,
    Atomic,
}

// ============================================================================
// Wallet Recovery Simulation (from wallet.rs)
// ============================================================================

/// Simulates wallet recovery using viewing tags and nullifier scanning
pub struct RecoverySimulator {
    simulator: CLVMZkSimulator,
}

impl RecoverySimulator {
    pub fn new(simulator: CLVMZkSimulator) -> Self {
        Self { simulator }
    }

    /// Recover coins using viewing tag hints (privacy-preserving)
    pub fn recover_with_viewing_tags(&self, user: &str, max_index: u32) -> Vec<RecoveredCoin> {
        let mut recovered = Vec::new();

        for index in 0..max_index {
            let expected_tag = CoinFactory::generate_viewing_tag(user, index);

            // Check if any coins in UTXO set match this tag
            for (nullifier, coin_info) in self.simulator.utxo_iter() {
                if coin_info.metadata.owner == user {
                    // In real implementation, you'd scan encrypted viewing tags
                    // Here we simulate by checking if this could be the user's coin
                    let derived_secret = CoinFactory::derive_user_secret(user, index);
                    let derived_coin = CoinFactory::create_coin(
                        derived_secret,
                        PuzzleType::P2PK, // Assume P2PK for recovery
                        coin_info.coin.amount,
                    );

                    if derived_coin.nullifier() == *nullifier {
                        recovered.push(RecoveredCoin {
                            user: user.to_string(),
                            index,
                            spend_secret: derived_secret,
                            viewing_tag: expected_tag,
                            nullifier: *nullifier,
                        });
                    }
                }
            }
        }

        recovered
    }

    /// Scan for spent coins by checking nullifier set
    pub fn scan_spent_coins(&self, user: &str, max_index: u32) -> Vec<RecoveredSpend> {
        let mut found = Vec::new();

        for index in 0..max_index {
            let derived_secret = CoinFactory::derive_user_secret(user, index);

            // Try different puzzle types
            for puzzle_type in [PuzzleType::P2PK, PuzzleType::Multisig, PuzzleType::Timelock] {
                let test_coin = CoinFactory::create_coin(derived_secret, puzzle_type, 0); // Amount doesn't affect nullifier
                let nullifier = test_coin.nullifier();

                if self.simulator.has_nullifier(&nullifier) {
                    found.push(RecoveredSpend {
                        user: user.to_string(),
                        index,
                        nullifier,
                        puzzle_type,
                    });
                }
            }
        }

        found
    }
}

#[derive(Debug)]
pub struct RecoveredCoin {
    pub user: String,
    pub index: u32,
    pub spend_secret: [u8; 32],
    pub viewing_tag: [u8; 4],
    pub nullifier: [u8; 32],
}

#[derive(Debug)]
pub struct RecoveredSpend {
    pub user: String,
    pub index: u32,
    pub nullifier: [u8; 32],
    pub puzzle_type: PuzzleType,
}

// ============================================================================
// Test Scenarios
// ============================================================================

/// Pre-built test scenarios for protocol validation
pub struct TestScenarios;

impl TestScenarios {
    /// Create test puzzle with matching hash for test scenarios
    pub fn create_test_puzzle_for_scenarios(amount: u64) -> (String, [u8; 32]) {
        let program = format!("{}", amount);
        let hash = sha2::Sha256::digest(program.as_bytes()).into();
        (program, hash)
    }

    /// Test double-spend prevention
    pub fn test_double_spend_prevention() -> Result<(), SimulatorError> {
        let mut sim = CLVMZkSimulator::new();

        // Create coin with matching puzzle
        let (puzzle_program, puzzle_hash) = Self::create_test_puzzle_for_scenarios(1000);
        let coin = PrivateCoin::new([1u8; 32], puzzle_hash, 1000);
        let _nullifier = sim.add_coin(
            coin.clone(),
            CoinMetadata {
                owner: "alice".to_string(),
                coin_type: CoinType::Regular,
                notes: "test coin".to_string(),
            },
        );

        // First spend should succeed
        let result1 = sim.spend_coins(vec![(coin.clone(), puzzle_program.clone())]);
        assert!(result1.is_ok(), "First spend should succeed");

        // Second spend should fail (double-spend)
        let result2 = sim.spend_coins(vec![(coin, puzzle_program)]);
        match result2 {
            Err(SimulatorError::DoubleSpend(_)) => println!("Double-spend correctly prevented"),
            _ => {
                return Err(SimulatorError::TestFailed(
                    "Double-spend not prevented".to_string(),
                ))
            }
        }

        Ok(())
    }

    /// Test nullifier uniqueness across puzzles
    pub fn test_cross_puzzle_nullifier_uniqueness() -> Result<(), SimulatorError> {
        let spend_secret = [42u8; 32];

        // Same spend secret, different puzzles
        let coin1 = CoinFactory::create_coin(spend_secret, PuzzleType::P2PK, 1000);
        let coin2 = CoinFactory::create_coin(spend_secret, PuzzleType::Multisig, 1000);

        // Should have different nullifiers
        let null1 = coin1.nullifier();
        let null2 = coin2.nullifier();

        if null1 == null2 {
            return Err(SimulatorError::TestFailed(
                "Cross-puzzle replay vulnerability".to_string(),
            ));
        }

        println!("Cross-puzzle nullifiers are unique");
        Ok(())
    }

    /// Test privacy mixing simulation
    pub fn test_privacy_mixing() -> Result<(), SimulatorError> {
        let mut sim = CLVMZkSimulator::new();

        let users = ["alice", "bob", "charlie"];
        let amounts = [1000, 1500, 800];

        // Create coins for multiple users with matching puzzle
        let (_, puzzle_hash) = Self::create_test_puzzle_for_scenarios(1000);

        let mut user_coins = Vec::new();
        for (i, (user, &amount)) in users.iter().zip(amounts.iter()).enumerate() {
            let secret = CoinFactory::derive_user_secret(user, i as u32);
            let coin = PrivateCoin::new(secret, puzzle_hash, amount);
            let viewing_tag = CoinFactory::generate_viewing_tag(user, i as u32);
            user_coins.push((user.to_string(), coin, viewing_tag));
        }

        // Add coins to simulator
        for (user, coin, _tag) in &user_coins {
            sim.add_coin(
                coin.clone(),
                CoinMetadata {
                    owner: user.clone(),
                    coin_type: CoinType::Regular,
                    notes: format!("{user} initial coin"),
                },
            );
        }

        // Mix all coins in one transaction
        let (puzzle_program, _) = Self::create_test_puzzle_for_scenarios(1000);
        let coins_to_spend: Vec<(PrivateCoin, String)> = user_coins
            .into_iter()
            .map(|(_, coin, _)| (coin, puzzle_program.clone()))
            .collect();
        let mix_tx = sim.spend_coins(coins_to_spend)?;

        println!(
            "Privacy mixing completed: {} inputs mixed",
            mix_tx.nullifiers.len()
        );
        Ok(())
    }

    /// Test wallet recovery simulation
    pub fn test_wallet_recovery_flows() -> Result<(), SimulatorError> {
        let mut sim = CLVMZkSimulator::new();

        // Simulate wallet with multiple coins with matching puzzle
        let base_secret = [7u8; 32];
        let (_, puzzle_hash) = Self::create_test_puzzle_for_scenarios(1000);

        let mut coins = Vec::new();
        let mut nullifiers = Vec::new();
        for i in 0u32..5 {
            let mut hasher = sha2::Sha256::new();
            hasher.update(base_secret);
            hasher.update(i.to_le_bytes());
            let derived_secret: [u8; 32] = hasher.finalize().into();
            let coin = PrivateCoin::new(derived_secret, puzzle_hash, 1000);

            let nullifier = sim.add_coin(
                coin.clone(),
                CoinMetadata {
                    owner: "alice".to_string(),
                    coin_type: CoinType::Regular,
                    notes: format!("wallet coin {i}"),
                },
            );

            coins.push(coin);
            nullifiers.push(nullifier);
        }

        // Simulate recovery
        let recovery_sim = RecoverySimulator::new(sim.clone());
        let recovered = recovery_sim.recover_with_viewing_tags("alice", 10);

        println!("Wallet recovery: found {} coins", recovered.len());
        Ok(())
    }

    /// Test atomic transaction patterns
    pub fn test_atomic_transactions() -> Result<(), SimulatorError> {
        let mut sim = CLVMZkSimulator::new();

        // Create coins for atomic swap with matching puzzle
        let (_, puzzle_hash) = Self::create_test_puzzle_for_scenarios(1000);
        let alice_coin = PrivateCoin::new([10u8; 32], puzzle_hash, 1000);
        let bob_coin = PrivateCoin::new([20u8; 32], puzzle_hash, 500);

        // Add to simulator
        sim.add_coin(
            alice_coin.clone(),
            CoinMetadata {
                owner: "alice".to_string(),
                coin_type: CoinType::Atomic,
                notes: "atomic swap input".to_string(),
            },
        );

        sim.add_coin(
            bob_coin.clone(),
            CoinMetadata {
                owner: "bob".to_string(),
                coin_type: CoinType::Atomic,
                notes: "atomic swap input".to_string(),
            },
        );

        // Execute atomic transaction
        let (atomic_program, _) = Self::create_test_puzzle_for_scenarios(1000);
        let atomic_tx = sim.spend_coins(vec![
            (alice_coin, atomic_program.clone()),
            (bob_coin, atomic_program),
        ])?;

        println!(
            "Atomic transaction completed: {} participants",
            atomic_tx.nullifiers.len()
        );
        Ok(())
    }

    /// Run all test scenarios
    pub fn run_all_tests() -> Result<(), SimulatorError> {
        println!("Running CLVM-ZK Protocol Test Suite...\n");

        Self::test_double_spend_prevention()?;
        Self::test_cross_puzzle_nullifier_uniqueness()?;
        Self::test_privacy_mixing()?;
        Self::test_wallet_recovery_flows()?;
        Self::test_atomic_transactions()?;

        println!("\nAll protocol tests passed!");
        Ok(())
    }
}
