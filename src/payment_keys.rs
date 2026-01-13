/// ECDH payment keys for unlinkable offers
///
/// Payment keys enable receiver-derived addresses:
/// - maker publishes ephemeral payment pubkey
/// - taker derives shared secret via ECDH
/// - payment address unlinkable to maker's identity
///
/// Uses x25519 (Curve25519) for ECDH, consistent with encrypted note infrastructure

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// payment key for ECDH address derivation
#[derive(Debug, Clone)]
pub struct PaymentKey {
    /// x25519 public key (32 bytes)
    pub pubkey: [u8; 32],

    /// private scalar (only holder knows, None for receive-only keys)
    pub privkey: Option<[u8; 32]>,
}

impl PaymentKey {
    /// create payment key from private scalar
    pub fn from_privkey(privkey: [u8; 32]) -> Self {
        // derive public key using x25519
        let secret = StaticSecret::from(privkey);
        let pubkey = PublicKey::from(&secret).to_bytes();

        Self {
            pubkey,
            privkey: Some(privkey),
        }
    }

    /// create receive-only key from public key
    pub fn from_pubkey(pubkey: [u8; 32]) -> Self {
        Self {
            pubkey,
            privkey: None,
        }
    }

    /// generate random payment key
    pub fn generate() -> Self {
        let mut privkey = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut privkey);
        Self::from_privkey(privkey)
    }

    /// derive child key for specific offer index (hd wallet style)
    ///
    /// derivation: child_privkey = hash("offer_derivation" || parent_privkey || index)
    /// ensures unlinkable keys across different offers
    pub fn derive_offer_key(&self, offer_index: u32) -> Result<PaymentKey, &'static str> {
        let parent_privkey = self.privkey.ok_or("cannot derive from pubkey-only key")?;

        let domain = b"offer_derivation";
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(parent_privkey);
        hasher.update(offer_index.to_be_bytes());

        let child_privkey: [u8; 32] = hasher.finalize().into();
        Ok(Self::from_privkey(child_privkey))
    }

    /// derive key using custom derivation path
    pub fn derive_path(&self, path: &[u32]) -> Result<PaymentKey, &'static str> {
        let mut current = self.clone();
        for index in path {
            current = current.derive_offer_key(*index)?;
        }
        Ok(current)
    }

    /// check if this key can spend a coin derived via ecdh
    pub fn can_spend_ecdh_coin(
        &self,
        sender_pubkey: &[u8; 32],
        puzzle_hash: &[u8; 32],
    ) -> bool {
        if self.privkey.is_none() {
            return false; // can't spend without privkey
        }

        // derive what puzzle_hash should be for this ecdh pair
        let derived_result = derive_ecdh_puzzle_hash_from_receiver(
            sender_pubkey,
            &self.privkey.unwrap(),
        );

        match derived_result {
            Ok(derived) => derived == *puzzle_hash,
            Err(_) => false,
        }
    }

    /// scan for payments made via ecdh
    ///
    /// given a list of (coin, sender_ephemeral_pubkey) pairs, returns indices of coins
    /// that can be spent by this payment key
    ///
    /// usage:
    /// ```ignore
    /// let payment_key = PaymentKey::generate();
    /// let coins_with_pubkeys = vec![
    ///     (coin1, taker_pubkey1),
    ///     (coin2, taker_pubkey2),
    /// ];
    /// let spendable = payment_key.scan_for_payments(&coins_with_pubkeys);
    /// // spendable contains indices of coins this key can spend
    /// ```
    pub fn scan_for_payments(
        &self,
        coins: &[(crate::protocol::PrivateCoin, [u8; 32])],
    ) -> Vec<usize> {
        if self.privkey.is_none() {
            return vec![]; // can't spend without privkey
        }

        let mut spendable_indices = Vec::new();
        for (i, (coin, sender_pubkey)) in coins.iter().enumerate() {
            if self.can_spend_ecdh_coin(sender_pubkey, &coin.puzzle_hash) {
                spendable_indices.push(i);
            }
        }
        spendable_indices
    }

    /// get public key bytes
    pub fn to_pubkey(&self) -> [u8; 32] {
        self.pubkey
    }
}

/// derive ecdh puzzle hash using sender's private key (real ecdh)
///
/// sender side: has receiver_pubkey and sender_privkey
/// computes shared_secret = receiver_pubkey * sender_privkey
///
/// uses x25519 for ECDH (compatible with encrypted notes)
pub fn derive_ecdh_puzzle_hash_from_sender(
    receiver_pubkey: &[u8; 32],
    sender_privkey: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    // parse receiver's public key
    let receiver_pk = PublicKey::from(*receiver_pubkey);

    // parse sender's private key
    let sender_sk = StaticSecret::from(*sender_privkey);

    // ecdh: x25519 diffie-hellman
    let shared_secret = sender_sk.diffie_hellman(&receiver_pk);

    // derive puzzle_hash from shared secret
    let domain = b"ecdh_payment_v1";
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(shared_secret.as_bytes());

    Ok(hasher.finalize().into())
}

/// derive ecdh puzzle hash using receiver's private key (real ecdh)
///
/// receiver side: has sender_pubkey and receiver_privkey
/// computes shared_secret = sender_pubkey * receiver_privkey
///
/// produces SAME result as derive_ecdh_puzzle_hash_from_sender (ecdh property)
pub fn derive_ecdh_puzzle_hash_from_receiver(
    sender_pubkey: &[u8; 32],
    receiver_privkey: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    // parse sender's public key
    let sender_pk = PublicKey::from(*sender_pubkey);

    // parse receiver's private key
    let receiver_sk = StaticSecret::from(*receiver_privkey);

    // ecdh: x25519 diffie-hellman
    // CRITICAL: same result as sender side due to ecdh property
    let shared_secret = receiver_sk.diffie_hellman(&sender_pk);

    // derive puzzle_hash from shared secret
    let domain = b"ecdh_payment_v1";
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(shared_secret.as_bytes());

    Ok(hasher.finalize().into())
}

/// simplified public-key-only derivation (fallback for testing/compatibility)
///
/// in production, use derive_ecdh_puzzle_hash_from_sender or derive_ecdh_puzzle_hash_from_receiver
pub fn derive_ecdh_puzzle_hash(
    receiver_pubkey: &[u8; 32],
    sender_pubkey: &[u8; 32],
) -> [u8; 32] {
    // simplified hash-based derivation when only pubkeys available
    // NOTE: this is NOT real ECDH, just for compatibility
    let domain = b"ecdh_payment_v1_pubkey_only";
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(receiver_pubkey);
    hasher.update(sender_pubkey);

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_key_generation() {
        let key = PaymentKey::generate();
        assert!(key.privkey.is_some());
        assert_eq!(key.pubkey.len(), 32);
    }

    #[test]
    fn test_ecdh_commutative_property() {
        // generate two keypairs
        let alice = PaymentKey::generate();
        let bob = PaymentKey::generate();

        // alice computes: shared = bob_pub * alice_priv
        let shared_alice = derive_ecdh_puzzle_hash_from_sender(
            &bob.pubkey,
            &alice.privkey.unwrap(),
        )
        .unwrap();

        // bob computes: shared = alice_pub * bob_priv
        let shared_bob = derive_ecdh_puzzle_hash_from_receiver(
            &alice.pubkey,
            &bob.privkey.unwrap(),
        )
        .unwrap();

        // both should get same result!
        assert_eq!(shared_alice, shared_bob);
    }

    #[test]
    fn test_offer_key_derivation() {
        let master = PaymentKey::generate();

        let offer0 = master.derive_offer_key(0).unwrap();
        let offer1 = master.derive_offer_key(1).unwrap();

        // different indices = different keys
        assert_ne!(offer0.pubkey, offer1.pubkey);

        // same index = same key
        let offer0_again = master.derive_offer_key(0).unwrap();
        assert_eq!(offer0.pubkey, offer0_again.pubkey);
    }

    #[test]
    fn test_can_spend_ecdh_coin() {
        let maker = PaymentKey::generate();
        let taker = PaymentKey::generate();

        // taker creates payment to maker
        let payment_puzzle = derive_ecdh_puzzle_hash_from_sender(
            &maker.pubkey,
            &taker.privkey.unwrap(),
        )
        .unwrap();

        // maker should be able to identify the coin
        assert!(maker.can_spend_ecdh_coin(&taker.pubkey, &payment_puzzle));

        // random key should not be able to spend
        let random = PaymentKey::generate();
        assert!(!random.can_spend_ecdh_coin(&taker.pubkey, &payment_puzzle));
    }
}
