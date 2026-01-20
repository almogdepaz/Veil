/// test payment scanning for ecdh-based coin discovery
#[cfg(feature = "mock")]
mod tests {
    use clvm_zk::payment_keys::{derive_ecdh_puzzle_hash_from_sender, PaymentKey};
    use clvm_zk::protocol::PrivateCoin;
    use clvm_zk_core::coin_commitment::SerialCommitment;

    #[test]
    fn test_scan_finds_ecdh_payment() {
        // maker has a payment key
        let maker_key = PaymentKey::generate();

        // taker creates payment to maker via ecdh (real ECDH with private key)
        let taker_key = PaymentKey::generate();
        let payment_puzzle_hash = derive_ecdh_puzzle_hash_from_sender(
            &maker_key.to_pubkey(),
            &taker_key.privkey.unwrap(),
        )
        .unwrap();

        // create payment coin with ecdh puzzle_hash
        let payment_coin = PrivateCoin {
            puzzle_hash: payment_puzzle_hash,
            amount: 1000,
            tail_hash: [0u8; 32], // XCH
            serial_commitment: SerialCommitment::compute(
                &[0x11; 32],
                &[0x22; 32],
                clvm_zk::crypto_utils::hash_data_default,
            ),
        };

        // create some other coins with different puzzle hashes
        let other_coin1 = PrivateCoin {
            puzzle_hash: [0x33; 32],
            amount: 500,
            tail_hash: [0u8; 32], // XCH
            serial_commitment: SerialCommitment::compute(
                &[0x44; 32],
                &[0x55; 32],
                clvm_zk::crypto_utils::hash_data_default,
            ),
        };

        let other_coin2 = PrivateCoin {
            puzzle_hash: [0x66; 32],
            amount: 250,
            tail_hash: [0u8; 32], // XCH
            serial_commitment: SerialCommitment::compute(
                &[0x77; 32],
                &[0x88; 32],
                clvm_zk::crypto_utils::hash_data_default,
            ),
        };

        // maker scans for payments
        let coins = vec![
            (other_coin1, [0x02; 32]),             // not ours
            (payment_coin, taker_key.to_pubkey()), // THIS ONE - ecdh match
            (other_coin2, [0x03; 32]),             // not ours
        ];

        let spendable = maker_key.scan_for_payments(&coins);

        // should find exactly coin at index 1
        assert_eq!(spendable.len(), 1, "should find exactly 1 spendable coin");
        assert_eq!(spendable[0], 1, "should find coin at index 1");
    }

    #[test]
    fn test_scan_multiple_payments() {
        let receiver = PaymentKey::generate();

        // multiple senders create payments
        let sender1 = PaymentKey::generate();
        let sender2 = PaymentKey::generate();
        let sender3 = PaymentKey::generate();

        // create ecdh coins from sender1 and sender3 (real ECDH with private keys)
        let payment1_puzzle =
            derive_ecdh_puzzle_hash_from_sender(&receiver.to_pubkey(), &sender1.privkey.unwrap())
                .unwrap();
        let payment2_puzzle =
            derive_ecdh_puzzle_hash_from_sender(&receiver.to_pubkey(), &sender3.privkey.unwrap())
                .unwrap();

        let payment1 = PrivateCoin::new_with_secrets(payment1_puzzle, 500).0;
        let random_coin = PrivateCoin::new_with_secrets([0x99; 32], 300).0;
        let payment2 = PrivateCoin::new_with_secrets(payment2_puzzle, 700).0;

        let coins = vec![
            (payment1, sender1.to_pubkey()),    // match
            (random_coin, sender2.to_pubkey()), // no match
            (payment2, sender3.to_pubkey()),    // match
        ];

        let spendable = receiver.scan_for_payments(&coins);

        assert_eq!(spendable.len(), 2, "should find 2 spendable coins");
        assert_eq!(spendable[0], 0, "first payment at index 0");
        assert_eq!(spendable[1], 2, "second payment at index 2");
    }

    #[test]
    fn test_scan_with_pubkey_only_returns_empty() {
        // observer wallet (pubkey only, no privkey)
        let pubkey_only = PaymentKey::from_pubkey([0x02; 32]);

        let coin = PrivateCoin::new_with_secrets([0x11; 32], 1000).0;
        let coins = vec![(coin, [0x03; 32])];

        let spendable = pubkey_only.scan_for_payments(&coins);

        assert_eq!(spendable.len(), 0, "pubkey-only wallet can't spend");
    }

    #[test]
    fn test_can_spend_ecdh_coin_verification() {
        let receiver = PaymentKey::generate();
        let sender = PaymentKey::generate();

        // correct ecdh derivation (real ECDH with sender's private key)
        let correct_puzzle =
            derive_ecdh_puzzle_hash_from_sender(&receiver.to_pubkey(), &sender.privkey.unwrap())
                .unwrap();
        assert!(
            receiver.can_spend_ecdh_coin(&sender.to_pubkey(), &correct_puzzle),
            "should be able to spend correct ecdh coin"
        );

        // wrong puzzle_hash
        let wrong_puzzle = [0x99; 32];
        assert!(
            !receiver.can_spend_ecdh_coin(&sender.to_pubkey(), &wrong_puzzle),
            "should not be able to spend wrong puzzle"
        );

        // wrong sender pubkey
        let other_sender = PaymentKey::generate();
        assert!(
            !receiver.can_spend_ecdh_coin(&other_sender.to_pubkey(), &correct_puzzle),
            "should not match with wrong sender pubkey"
        );
    }
}
