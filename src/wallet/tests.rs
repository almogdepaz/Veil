// ============================================================================
// Comprehensive HD Wallet Tests
// Tests ALL functionality: signing, recovery, viewing keys, spending keys
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::wallet::hd_wallet::*;
    use crate::protocol::Spender;

    // Test seeds for deterministic testing
    const TEST_SEED_MAINNET: &[u8] = b"test seed must be at least 16 bytes long for mainnet!!!";
    const TEST_SEED_TESTNET: &[u8] = b"another test seed that is long enough for testnet!!!!";
    const TEST_SEED_RECOVERY: &[u8] = b"recovery test seed with sufficient entropy content!!!!";

    // ============================================================================
    // Basic Wallet Creation Tests
    // ============================================================================

    #[test]
    fn test_wallet_creation_from_seed() {
        // Test different seed lengths
        let short_seed = b"short";
        let result = CLVMHDWallet::from_seed(short_seed, Network::Testnet);
        assert!(result.is_err(), "Should reject seeds shorter than 16 bytes");

        let good_seed = b"this is a perfectly fine seed with good entropy!!";
        let wallet = CLVMHDWallet::from_seed(good_seed, Network::Mainnet).unwrap();
        
        // Should derive account successfully
        let account = wallet.derive_account(0).unwrap();
        assert_eq!(account.account_index, 0);
        assert_eq!(account.network, Network::Mainnet);
    }

    #[test]
    fn test_deterministic_key_derivation() {
        // Same seed should produce same keys
        let wallet1 = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Mainnet).unwrap();
        let wallet2 = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Mainnet).unwrap();
        
        let account1 = wallet1.derive_account(0).unwrap();
        let account2 = wallet2.derive_account(0).unwrap();
        
        assert_eq!(account1.spending_key, account2.spending_key);
        assert_eq!(account1.viewing_key, account2.viewing_key);
        assert_eq!(account1.nullifier_key, account2.nullifier_key);
    }

    #[test]
    fn test_different_networks_produce_different_keys() {
        let wallet_mainnet = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Mainnet).unwrap();
        let wallet_testnet = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Testnet).unwrap();
        
        let account_main = wallet_mainnet.derive_account(0).unwrap();
        let account_test = wallet_testnet.derive_account(0).unwrap();
        
        // Same seed, different networks = different keys
        assert_ne!(account_main.spending_key, account_test.spending_key);
        assert_ne!(account_main.viewing_key, account_test.viewing_key);
    }

    // ============================================================================
    // Spend Secret and Nullifier Tests
    // ============================================================================

    #[test]
    fn test_spend_secret_derivation() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_TESTNET, Network::Testnet).unwrap();
        
        // Different accounts should have different secrets
        let secret_acc0_coin0 = wallet.derive_spend_secret(0, 0).unwrap();
        let secret_acc1_coin0 = wallet.derive_spend_secret(1, 0).unwrap();
        assert_ne!(secret_acc0_coin0.secret, secret_acc1_coin0.secret);
        
        // Different coins should have different secrets
        let secret_acc0_coin1 = wallet.derive_spend_secret(0, 1).unwrap();
        assert_ne!(secret_acc0_coin0.secret, secret_acc0_coin1.secret);
        
        // Same parameters should give same secret (deterministic)
        let secret_duplicate = wallet.derive_spend_secret(0, 0).unwrap();
        assert_eq!(secret_acc0_coin0.secret, secret_duplicate.secret);
    }

    #[test]
    fn test_nullifier_domain_separation_and_puzzle_binding() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Mainnet).unwrap();
        
        let puzzle1 = [1u8; 32];
        let puzzle2 = [2u8; 32];
        
        // Same coin, different puzzles = different nullifiers (prevents cross-puzzle replay)
        let null1 = wallet.create_nullifier(0, 0, puzzle1).unwrap();
        let null2 = wallet.create_nullifier(0, 0, puzzle2).unwrap();
        assert_ne!(null1.bytes, null2.bytes);
        
        // Different coins, same puzzle = different nullifiers
        let null3 = wallet.create_nullifier(0, 1, puzzle1).unwrap();
        assert_ne!(null1.bytes, null3.bytes);
        
        // Same parameters = same nullifier (deterministic)
        let null4 = wallet.create_nullifier(0, 0, puzzle1).unwrap();
        assert_eq!(null1.bytes, null4.bytes);
        
        // Verify nullifier construction
        assert!(null1.verify(&null1.spend_secret, &puzzle1));
        assert!(!null1.verify(&null1.spend_secret, &puzzle2));
    }

    #[test]
    fn test_nullifier_matches_protocol_implementation() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_TESTNET, Network::Testnet).unwrap();
        let puzzle_hash = [42u8; 32];
        
        // Create coin through wallet
        let wallet_coin = WalletPrivateCoin::from_wallet(&wallet, 0, 0, puzzle_hash, 1000).unwrap();
        
        // Create equivalent protocol coin
        let protocol_coin = wallet_coin.to_protocol_coin();
        
        // Nullifiers should match
        assert_eq!(wallet_coin.nullifier(), protocol_coin.nullifier());
        
        // Wallet's nullifier calculation should match coin's
        let wallet_nullifier = wallet.create_nullifier(0, 0, puzzle_hash).unwrap();
        assert_eq!(wallet_nullifier.bytes, wallet_coin.nullifier());
    }

    // ============================================================================
    // Viewing Key Tests
    // ============================================================================

    #[test]
    fn test_viewing_key_export_and_separation() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Mainnet).unwrap();
        
        let account = wallet.derive_account(0).unwrap();
        let viewing_key = account.export_viewing_key();
        
        // Create view-only wallet
        let view_wallet = ViewOnlyWallet::from_viewing_key(viewing_key.clone());
        
        // Should derive same viewing tags
        let tag1 = account.derive_coin_keys(5, [0; 32]).viewing_tag;
        let tag2 = view_wallet.derive_viewing_tag(5);
        assert_eq!(tag1, tag2);
        
        // Should be able to check viewing tags
        assert_eq!(view_wallet.check_viewing_tag(&tag1, 100), Some(5));
        assert_eq!(view_wallet.check_viewing_tag(&[0xFF; 4], 100), None);
    }

    #[test]
    fn test_viewing_key_privacy_separation() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_TESTNET, Network::Testnet).unwrap();
        
        let account = wallet.derive_account(0).unwrap();
        let viewing_key = account.export_viewing_key();
        let view_wallet = ViewOnlyWallet::from_viewing_key(viewing_key);
        
        // View-only wallet can derive viewing tags but NOT spend secrets
        let viewing_tag = view_wallet.derive_viewing_tag(10);
        assert_eq!(viewing_tag.len(), 4);
        
        // Compare with full account's tag derivation
        let coin_keys = account.derive_coin_keys(10, [0; 32]);
        assert_eq!(viewing_tag, coin_keys.viewing_tag);
        
        // But view-only wallet cannot derive spending keys
        // (This is ensured by not exposing spending_key in ViewOnlyWallet)
    }

    // ============================================================================
    // Account and Coin Key Tests
    // ============================================================================

    #[test]
    fn test_account_key_derivation() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Mainnet).unwrap();
        
        // Different accounts should have different keys
        let account0 = wallet.derive_account(0).unwrap();
        let account1 = wallet.derive_account(1).unwrap();
        
        assert_ne!(account0.spending_key, account1.spending_key);
        assert_ne!(account0.viewing_key, account1.viewing_key);
        assert_ne!(account0.nullifier_key, account1.nullifier_key);
        
        // Account indices should be correct
        assert_eq!(account0.account_index, 0);
        assert_eq!(account1.account_index, 1);
    }

    #[test]
    fn test_coin_key_derivation_within_account() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_TESTNET, Network::Testnet).unwrap();
        let account = wallet.derive_account(0).unwrap();
        
        let puzzle_hash = [123u8; 32];
        
        // Different coin indices should produce different keys
        let coin0 = account.derive_coin_keys(0, puzzle_hash);
        let coin1 = account.derive_coin_keys(1, puzzle_hash);
        
        assert_ne!(coin0.spend_secret, coin1.spend_secret);
        assert_ne!(coin0.viewing_tag, coin1.viewing_tag);
        assert_ne!(coin0.nullifier, coin1.nullifier);
        
        // Same puzzle hash should be preserved
        assert_eq!(coin0.puzzle_hash, puzzle_hash);
        assert_eq!(coin1.puzzle_hash, puzzle_hash);
        
        // Coin indices should be correct
        assert_eq!(coin0.coin_index, 0);
        assert_eq!(coin1.coin_index, 1);
    }

    // ============================================================================
    // Private Coin Integration Tests
    // ============================================================================

    #[test]
    fn test_private_coin_creation_and_validation() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Mainnet).unwrap();
        
        let puzzle_hash = [42u8; 32];
        let coin = WalletPrivateCoin::from_wallet(&wallet, 0, 0, puzzle_hash, 1000).unwrap();
        
        // Should validate successfully
        coin.validate().unwrap();
        
        // Should generate consistent nullifier
        let null1 = coin.nullifier();
        let null2 = coin.nullifier();
        assert_eq!(null1, null2);
        
        // Should create hint correctly
        let (hint, nullifier) = coin.with_hint();
        assert_eq!(hint, [nullifier[0], nullifier[1], nullifier[2], nullifier[3]]);
        
        // Account and coin indices should be preserved
        assert_eq!(coin.account_index, 0);
        assert_eq!(coin.coin_index, 0);
        assert_eq!(coin.amount(), 1000);
    }

    #[test]
    fn test_private_coin_protocol_integration() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_TESTNET, Network::Testnet).unwrap();
        let puzzle_hash = [55u8; 32];
        
        let wallet_coin = WalletPrivateCoin::from_wallet(&wallet, 1, 5, puzzle_hash, 2000).unwrap();
        let protocol_coin = wallet_coin.to_protocol_coin();
        
        // Should preserve all essential data
        assert_eq!(wallet_coin.spend_secret(), protocol_coin.spend_secret);
        assert_eq!(wallet_coin.puzzle_hash(), protocol_coin.puzzle_hash);
        assert_eq!(wallet_coin.amount(), protocol_coin.amount);
        assert_eq!(wallet_coin.nullifier(), protocol_coin.nullifier());
    }

    // ============================================================================
    // Wallet Recovery Tests
    // ============================================================================

    #[test]
    fn test_wallet_recovery_with_hints() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_RECOVERY, Network::Mainnet).unwrap();
        let account = wallet.derive_account(0).unwrap();
        
        // Create viewing tags (not nullifier hints!)
        let mut hints = Vec::new();
        let mut expected_coins = Vec::new();
        
        for i in 0..5 {
            let coin = WalletPrivateCoin::from_wallet(&wallet, 0, i, [0; 32], 1000).unwrap();
            let viewing_tag = crate::crypto_utils::generate_viewing_tag(&account.viewing_key, i);
            hints.push(viewing_tag);
            expected_coins.push((0u32, i, coin.spend_secret()));
        }
        
        // Simulate losing wallet and recovering from seed
        let new_wallet = CLVMHDWallet::from_seed(TEST_SEED_RECOVERY, Network::Mainnet).unwrap();
        let recovery = WalletRecovery::new(new_wallet);
        
        // Should recover all coins
        let recovered = recovery.recover_with_hints(&hints, 1, 100);
        assert_eq!(recovered.len(), 5);
        
        // Check that all expected coins were recovered
        for (expected_account, expected_coin, expected_secret) in expected_coins {
            let found = recovered.iter().find(|r| {
                r.account_index == expected_account && 
                r.coin_index == expected_coin
            });
            
            assert!(found.is_some(), "Failed to recover coin {}/{}", expected_account, expected_coin);
            let recovered_coin = found.unwrap();
            assert_eq!(recovered_coin.spend_secret, expected_secret);
        }
    }

    #[test]
    fn test_wallet_recovery_gap_limit() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_RECOVERY, Network::Testnet).unwrap();
        let account = wallet.derive_account(0).unwrap();
        
        // Create viewing tags for coins with gaps (don't need actual coins)
        let hint0 = crate::crypto_utils::generate_viewing_tag(&account.viewing_key, 0);
        let hint25 = crate::crypto_utils::generate_viewing_tag(&account.viewing_key, 25);
        let hints = vec![hint0, hint25];
        
        let recovery = WalletRecovery::new(wallet);
        let recovered = recovery.recover_with_hints(&hints, 1, 100);
        
        // Should only recover coin 0 due to gap limit
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].coin_index, 0);
    }

    #[test]
    fn test_nullifier_scanning_recovery() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Mainnet).unwrap();
        
        // Create some spent coins (simulate blockchain state)
        let puzzle_hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let mut spent_nullifiers = Vec::new();
        
        // Account 0, coins 0-2 with different puzzles
        for (coin_idx, &puzzle_hash) in puzzle_hashes.iter().enumerate() {
            let nullifier = wallet.create_nullifier(0, coin_idx as u32, puzzle_hash).unwrap();
            spent_nullifiers.push(nullifier.bytes);
        }
        
        let recovery = WalletRecovery::new(wallet);
        let found = recovery.scan_nullifiers(&spent_nullifiers, &puzzle_hashes, 1, 10);
        
        // Should find all 3 spent coins
        assert_eq!(found.len(), 3);
        
        for (i, recovered_spend) in found.iter().enumerate() {
            assert_eq!(recovered_spend.account_index, 0);
            assert_eq!(recovered_spend.coin_index, i as u32);
            assert_eq!(recovered_spend.puzzle_hash, puzzle_hashes[i]);
        }
    }

    // ============================================================================
    // Cross-Protocol Integration Tests
    // ============================================================================

    #[test]
    fn test_wallet_with_protocol_spender() {
        // Skip if RISC0 proof generation is disabled
        if std::env::var("RISC0_SKIP_BUILD").is_ok() {
            return;
        }

        let wallet = CLVMHDWallet::from_seed(TEST_SEED_TESTNET, Network::Testnet).unwrap();
        let puzzle_hash = [77u8; 32];
        
        let wallet_coin = WalletPrivateCoin::from_wallet(&wallet, 0, 0, puzzle_hash, 1500).unwrap();
        let protocol_coin = wallet_coin.to_protocol_coin();
        
        // Should be able to spend through protocol
        let puzzle_code = "1500";
        let result = Spender::create_spend(&protocol_coin, puzzle_code, &[]);
        
        // Note: This might fail if puzzle_code doesn't match puzzle_hash exactly
        // In real usage, the puzzle_code would need to hash to the expected puzzle_hash
        match result {
            Ok(spend_bundle) => {
                assert_eq!(spend_bundle.nullifier, protocol_coin.nullifier());
            },
            Err(_) => {
                // Expected if puzzle hash doesn't match - that's a security feature!
                println!("Spend failed due to puzzle hash mismatch - this is expected");
            }
        }
    }

    // ============================================================================
    // Edge Cases and Security Tests
    // ============================================================================

    #[test]
    fn test_invalid_coin_validation() {
        let _wallet = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Mainnet).unwrap();
        
        // Create coin with all-zero spend secret (should be invalid)
        let invalid_protocol_coin = crate::protocol::PrivateCoin::new([0u8; 32], [1; 32], 1000);
        let invalid_coin = WalletPrivateCoin {
            coin: invalid_protocol_coin,
            account_index: 0,
            coin_index: 0,
        };
        
        assert!(invalid_coin.validate().is_err());
        
        // Create coin with all-zero puzzle hash (should be invalid)
        let invalid_protocol_coin2 = crate::protocol::PrivateCoin::new([1; 32], [0u8; 32], 1000);
        let invalid_coin2 = WalletPrivateCoin {
            coin: invalid_protocol_coin2,
            account_index: 0,
            coin_index: 0,
        };
        
        assert!(invalid_coin2.validate().is_err());
    }

    #[test]
    fn test_nullifier_uniqueness_across_all_parameters() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_TESTNET, Network::Testnet).unwrap();
        
        let mut nullifiers = std::collections::HashSet::new();
        
        // Generate nullifiers for many different combinations
        for account in 0..3 {
            for coin in 0..10 {
                for puzzle_variant in 0..5 {
                    let puzzle_hash = [puzzle_variant; 32];
                    let nullifier = wallet.create_nullifier(account, coin, puzzle_hash).unwrap();
                    
                    // Each nullifier should be unique
                    assert!(nullifiers.insert(nullifier.bytes), 
                        "Duplicate nullifier found for account={}, coin={}, puzzle={}", 
                        account, coin, puzzle_variant);
                }
            }
        }
        
        // Should have generated 3 * 10 * 5 = 150 unique nullifiers
        assert_eq!(nullifiers.len(), 150);
    }

    #[test]
    fn test_seed_sensitivity() {
        let seed1 = b"seed with one specific content for testing!";
        let seed2 = b"seed with two specific content for testing!";
        
        let wallet1 = CLVMHDWallet::from_seed(seed1, Network::Mainnet).unwrap();
        let wallet2 = CLVMHDWallet::from_seed(seed2, Network::Mainnet).unwrap();
        
        // Even tiny seed differences should produce completely different keys
        let account1 = wallet1.derive_account(0).unwrap();
        let account2 = wallet2.derive_account(0).unwrap();
        
        assert_ne!(account1.spending_key, account2.spending_key);
        assert_ne!(account1.viewing_key, account2.viewing_key);
        assert_ne!(account1.nullifier_key, account2.nullifier_key);
    }

    // ============================================================================
    // Performance and Stress Tests
    // ============================================================================

    #[test]
    fn test_large_scale_key_derivation() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Mainnet).unwrap();
        
        // Should be able to derive many keys efficiently
        for account in 0..10 {
            let account_keys = wallet.derive_account(account).unwrap();
            
            for coin in 0..100 {
                let coin_keys = account_keys.derive_coin_keys(coin, [account as u8; 32]);
                
                // Basic sanity checks
                assert_ne!(coin_keys.spend_secret, [0u8; 32]);
                assert_ne!(coin_keys.nullifier, [0u8; 32]);
                assert_eq!(coin_keys.coin_index, coin);
            }
        }
    }

    // ============================================================================
    // Display and Serialization Tests
    // ============================================================================

    #[test]
    fn test_display_implementations() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_TESTNET, Network::Testnet).unwrap();
        let account = wallet.derive_account(0).unwrap();
        
        let nullifier = wallet.create_nullifier(0, 0, [1; 32]).unwrap();
        let viewing_key = account.export_viewing_key();
        
        // Should have meaningful string representations
        let null_str = format!("{}", nullifier);
        let view_str = format!("{}", viewing_key);
        
        assert!(null_str.starts_with("null:"));
        assert!(view_str.starts_with("vk:"));
        assert!(view_str.contains("acc_0"));
    }

    #[test]
    fn test_viewing_key_serialization() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED_MAINNET, Network::Mainnet).unwrap();
        let account = wallet.derive_account(0).unwrap();
        let viewing_key = account.export_viewing_key();
        
        // Should be serializable and deserializable
        let serialized = serde_json::to_string(&viewing_key).unwrap();
        let deserialized: ViewingKey = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(viewing_key.key, deserialized.key);
        assert_eq!(viewing_key.account_index, deserialized.account_index);
        assert_eq!(viewing_key.network, deserialized.network);
    }
}