/// test hash-based stealth payment scanning
#[cfg(feature = "mock")]
mod tests {
    use clvm_zk::payment_keys::{derive_stealth_puzzle_hash, generate_stealth_nonce, PaymentKey};

    #[test]
    fn test_stealth_puzzle_derivation() {
        // receiver has a payment key
        let receiver = PaymentKey::generate();

        // sender creates payment with random nonce
        let nonce = generate_stealth_nonce();
        let payment_puzzle = derive_stealth_puzzle_hash(&receiver.to_pubkey(), &nonce);

        // receiver can verify with same nonce
        assert!(
            receiver.can_spend_stealth_coin(&nonce, &payment_puzzle),
            "receiver should be able to spend with correct nonce"
        );

        // wrong nonce doesn't work
        let wrong_nonce = generate_stealth_nonce();
        assert!(
            !receiver.can_spend_stealth_coin(&wrong_nonce, &payment_puzzle),
            "wrong nonce should not work"
        );

        // wrong receiver can't spend
        let other_receiver = PaymentKey::generate();
        assert!(
            !other_receiver.can_spend_stealth_coin(&nonce, &payment_puzzle),
            "other receiver should not be able to spend"
        );
    }

    #[test]
    fn test_multiple_payments_different_nonces() {
        let receiver = PaymentKey::generate();

        // multiple payments with different nonces
        let nonce1 = generate_stealth_nonce();
        let nonce2 = generate_stealth_nonce();

        let puzzle1 = derive_stealth_puzzle_hash(&receiver.to_pubkey(), &nonce1);
        let puzzle2 = derive_stealth_puzzle_hash(&receiver.to_pubkey(), &nonce2);

        // different nonces produce different puzzles
        assert_ne!(
            puzzle1, puzzle2,
            "different nonces should produce different puzzles"
        );

        // receiver can spend both with correct nonces
        assert!(receiver.can_spend_stealth_coin(&nonce1, &puzzle1));
        assert!(receiver.can_spend_stealth_coin(&nonce2, &puzzle2));

        // but not with swapped nonces
        assert!(!receiver.can_spend_stealth_coin(&nonce1, &puzzle2));
        assert!(!receiver.can_spend_stealth_coin(&nonce2, &puzzle1));
    }

    #[test]
    fn test_pubkey_only_can_verify() {
        // pubkey-only receiver (for verification, not spending)
        let full_key = PaymentKey::generate();
        let pubkey_only = PaymentKey::from_pubkey(full_key.to_pubkey());

        let nonce = generate_stealth_nonce();
        let puzzle = derive_stealth_puzzle_hash(&full_key.to_pubkey(), &nonce);

        // pubkey-only can still verify (stealth is hash-based)
        assert!(
            pubkey_only.can_spend_stealth_coin(&nonce, &puzzle),
            "pubkey-only should be able to verify stealth puzzle"
        );
    }

    #[test]
    fn test_deterministic_puzzle_derivation() {
        let receiver = PaymentKey::generate();
        let nonce = [42u8; 32];

        // same inputs should produce same puzzle
        let puzzle1 = derive_stealth_puzzle_hash(&receiver.to_pubkey(), &nonce);
        let puzzle2 = derive_stealth_puzzle_hash(&receiver.to_pubkey(), &nonce);

        assert_eq!(puzzle1, puzzle2, "same inputs should produce same puzzle");
    }

    #[test]
    fn test_offer_key_derivation() {
        let master = PaymentKey::generate();

        // derive keys for different offers
        let offer0 = master.derive_offer_key(0).unwrap();
        let offer1 = master.derive_offer_key(1).unwrap();

        // different indices produce different keys
        assert_ne!(offer0.to_pubkey(), offer1.to_pubkey());

        // same index produces same key
        let offer0_again = master.derive_offer_key(0).unwrap();
        assert_eq!(offer0.to_pubkey(), offer0_again.to_pubkey());
    }
}
