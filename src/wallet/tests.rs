#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::wallet::hd_wallet::*;

    const TEST_SEED: &[u8] = b"test seed must be at least 16 bytes long!!!";

    #[test]
    fn test_wallet_creation_from_seed() {
        // Test different seed lengths
        let short_seed = b"short";
        let result = CLVMHDWallet::from_seed(short_seed, Network::Testnet);
        assert!(result.is_err());

        let good_seed = TEST_SEED;
        let wallet = CLVMHDWallet::from_seed(good_seed, Network::Mainnet).unwrap();
        let account = wallet.derive_account(0).unwrap();
        assert_eq!(account.account_index, 0);
        assert_eq!(account.network, Network::Mainnet);
    }

    #[test]
    fn test_deterministic_key_derivation() {
        let wallet1 = CLVMHDWallet::from_seed(TEST_SEED, Network::Mainnet).unwrap();
        let wallet2 = CLVMHDWallet::from_seed(TEST_SEED, Network::Mainnet).unwrap();

        let account1 = wallet1.derive_account(0).unwrap();
        let account2 = wallet2.derive_account(0).unwrap();

        assert_eq!(account1.spending_key, account2.spending_key);
        assert_eq!(account1.viewing_key, account2.viewing_key);
        assert_eq!(account1.nullifier_key, account2.nullifier_key);
    }

    #[test]
    fn test_different_networks_produce_different_keys() {
        let wallet_mainnet = CLVMHDWallet::from_seed(TEST_SEED, Network::Mainnet).unwrap();
        let wallet_testnet = CLVMHDWallet::from_seed(TEST_SEED, Network::Testnet).unwrap();

        let account_main = wallet_mainnet.derive_account(0).unwrap();
        let account_test = wallet_testnet.derive_account(0).unwrap();

        assert_ne!(account_main.spending_key, account_test.spending_key);
        assert_ne!(account_main.viewing_key, account_test.viewing_key);
    }

    #[test]
    fn test_viewing_key_export() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED, Network::Mainnet).unwrap();
        let account = wallet.derive_account(0).unwrap();
        let viewing_key = account.export_viewing_key();

        let view_wallet = ViewOnlyWallet::from_viewing_key(viewing_key.clone());

        let tag1 = view_wallet.derive_viewing_tag(5);
        let tag2 = view_wallet.derive_viewing_tag(5);
        assert_eq!(tag1, tag2);

        assert_eq!(view_wallet.check_viewing_tag(&tag1, 100), Some(5));
        assert_eq!(view_wallet.check_viewing_tag(&[0xFF; 4], 100), None);
    }

    #[test]
    fn test_private_coin_creation_with_random_serials() {
        let puzzle_hash = [42u8; 32];
        let coin1 = WalletPrivateCoin::new(puzzle_hash, 1000, 0, 0);
        let coin2 = WalletPrivateCoin::new(puzzle_hash, 1000, 0, 0);

        // should validate successfully
        coin1.validate().unwrap();
        coin2.validate().unwrap();

        assert_ne!(coin1.serial_number(), coin2.serial_number());

        assert_eq!(coin1.account_index, 0);
        assert_eq!(coin1.coin_index, 0);
        assert_eq!(coin1.amount(), 1000);
    }

    #[test]
    fn test_private_coin_protocol_integration() {
        let puzzle_hash = [55u8; 32];
        let wallet_coin = WalletPrivateCoin::new(puzzle_hash, 2000, 1, 5);
        let protocol_coin = wallet_coin.to_protocol_coin();

        assert_eq!(wallet_coin.puzzle_hash(), protocol_coin.puzzle_hash);
        assert_eq!(wallet_coin.amount(), protocol_coin.amount);
        assert_eq!(wallet_coin.serial_number(), wallet_coin.secrets.serial_number());
    }

    #[test]
    fn test_viewing_key_serialization() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED, Network::Mainnet).unwrap();
        let account = wallet.derive_account(0).unwrap();
        let viewing_key = account.export_viewing_key();

        // should be serializable
        let serialized = serde_json::to_string(&viewing_key).unwrap();
        let deserialized: ViewingKey = serde_json::from_str(&serialized).unwrap();

        assert_eq!(viewing_key.key, deserialized.key);
        assert_eq!(viewing_key.account_index, deserialized.account_index);
        assert_eq!(viewing_key.network, deserialized.network);
    }

    #[test]
    fn test_wallet_coin_serialization() {
        let puzzle_hash = [77u8; 32];
        let coin = WalletPrivateCoin::new(puzzle_hash, 5000, 2, 10);

        // should be serializable
        let serialized = serde_json::to_string(&coin).unwrap();
        let deserialized: WalletPrivateCoin = serde_json::from_str(&serialized).unwrap();

        assert_eq!(coin.serial_number(), deserialized.serial_number());
        assert_eq!(coin.amount(), deserialized.amount());
        assert_eq!(coin.account_index, deserialized.account_index);
        assert_eq!(coin.coin_index, deserialized.coin_index);
    }

    #[test]
    fn test_viewing_key_display() {
        let wallet = CLVMHDWallet::from_seed(TEST_SEED, Network::Testnet).unwrap();
        let account = wallet.derive_account(0).unwrap();
        let viewing_key = account.export_viewing_key();

        let view_str = format!("{}", viewing_key);
        assert!(view_str.starts_with("vk:"));
        assert!(view_str.contains("acc_0"));
    }
}
