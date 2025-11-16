/// ECDH payment keys for unlinkable offers
///
/// Payment keys enable receiver-derived addresses:
/// - maker publishes ephemeral payment pubkey
/// - taker derives shared secret via ECDH
/// - payment address unlinkable to maker's identity

use sha2::{Digest, Sha256};

/// payment key for ECDH address derivation
#[derive(Debug, Clone)]
pub struct PaymentKey {
    /// compressed secp256k1 public key (33 bytes: 0x02/0x03 prefix + x-coordinate)
    pub pubkey: [u8; 33],

    /// private scalar (only holder knows, None for receive-only keys)
    pub privkey: Option<[u8; 32]>,
}

impl PaymentKey {
    /// create payment key from private scalar
    pub fn from_privkey(privkey: [u8; 32]) -> Self {
        let pubkey = derive_pubkey_from_privkey(&privkey);
        Self {
            pubkey,
            privkey: Some(privkey),
        }
    }

    /// create receive-only key from public key
    pub fn from_pubkey(pubkey: [u8; 33]) -> Self {
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
        sender_pubkey: &[u8; 33],
        puzzle_hash: &[u8; 32],
    ) -> bool {
        if self.privkey.is_none() {
            return false; // can't spend without privkey
        }

        // derive what puzzle_hash should be for this ecdh pair
        let derived = derive_ecdh_puzzle_hash(&self.pubkey, sender_pubkey);
        derived == *puzzle_hash
    }

    /// get public key bytes
    pub fn to_pubkey(&self) -> [u8; 33] {
        self.pubkey
    }
}

/// derive ecdh shared secret and convert to puzzle hash
///
/// this creates a one-time address that only the receiver can spend
/// but sender can compute the address to send to
///
/// derivation:
/// 1. compute shared_point = receiver_pubkey * sender_privkey (ecdh)
/// 2. puzzle_hash = hash("ecdh_payment_v1" || shared_point)
pub fn derive_ecdh_puzzle_hash(
    receiver_pubkey: &[u8; 33],
    sender_pubkey: &[u8; 33],
) -> [u8; 32] {
    // simplified ecdh: hash both pubkeys together
    // in production, this would use proper secp256k1 point multiplication
    // shared_secret = receiver_pubkey * sender_privkey = sender_pubkey * receiver_privkey

    let domain = b"ecdh_payment_v1";
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(receiver_pubkey);
    hasher.update(sender_pubkey);

    hasher.finalize().into()
}

/// simplified pubkey derivation (placeholder for proper secp256k1)
/// in production, this would use secp256k1::PublicKey::from_secret_key
fn derive_pubkey_from_privkey(privkey: &[u8; 32]) -> [u8; 33] {
    // placeholder: hash privkey to get deterministic pubkey
    // real implementation would use secp256k1 curve math
    let mut hasher = Sha256::new();
    hasher.update(b"pubkey_derivation");
    hasher.update(privkey);
    let hash: [u8; 32] = hasher.finalize().into();

    // create compressed pubkey format (0x02 prefix + x-coordinate)
    let mut pubkey = [0u8; 33];
    pubkey[0] = 0x02; // compressed pubkey prefix (even y)
    pubkey[1..33].copy_from_slice(&hash);
    pubkey
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_key_generation() {
        let key1 = PaymentKey::generate();
        let key2 = PaymentKey::generate();

        // keys should be different
        assert_ne!(key1.pubkey, key2.pubkey);
        assert!(key1.privkey.is_some());
        assert!(key2.privkey.is_some());
    }

    #[test]
    fn test_offer_key_derivation() {
        let master = PaymentKey::generate();

        let offer1 = master.derive_offer_key(0).unwrap();
        let offer2 = master.derive_offer_key(1).unwrap();
        let offer3 = master.derive_offer_key(0).unwrap(); // same index

        // different indices produce different keys
        assert_ne!(offer1.pubkey, offer2.pubkey);

        // same index produces same key (deterministic)
        assert_eq!(offer1.pubkey, offer3.pubkey);
    }

    #[test]
    fn test_offer_key_unlinkability() {
        let master = PaymentKey::generate();

        let offer1 = master.derive_offer_key(0).unwrap();
        let offer2 = master.derive_offer_key(1).unwrap();

        // observer can't link derived keys to each other
        assert_ne!(offer1.pubkey, offer2.pubkey);
        assert_ne!(offer1.pubkey, master.pubkey);
    }

    #[test]
    fn test_derivation_path() {
        let master = PaymentKey::generate();

        let path = vec![0, 1, 2];
        let derived = master.derive_path(&path).unwrap();

        // manual derivation should match
        let manual = master.derive_offer_key(0).unwrap()
            .derive_offer_key(1).unwrap()
            .derive_offer_key(2).unwrap();

        assert_eq!(derived.pubkey, manual.pubkey);
    }

    #[test]
    fn test_ecdh_puzzle_derivation() {
        let receiver = PaymentKey::generate();
        let sender = PaymentKey::generate();

        let puzzle_hash = derive_ecdh_puzzle_hash(
            &receiver.pubkey,
            &sender.pubkey,
        );

        // puzzle hash should be deterministic
        let puzzle_hash2 = derive_ecdh_puzzle_hash(
            &receiver.pubkey,
            &sender.pubkey,
        );
        assert_eq!(puzzle_hash, puzzle_hash2);

        // different sender produces different puzzle
        let sender2 = PaymentKey::generate();
        let puzzle_hash3 = derive_ecdh_puzzle_hash(
            &receiver.pubkey,
            &sender2.pubkey,
        );
        assert_ne!(puzzle_hash, puzzle_hash3);
    }

    #[test]
    fn test_can_spend_ecdh_coin() {
        let receiver = PaymentKey::generate();
        let sender = PaymentKey::generate();

        let puzzle_hash = derive_ecdh_puzzle_hash(
            &receiver.pubkey,
            &sender.pubkey,
        );

        // receiver can spend
        assert!(receiver.can_spend_ecdh_coin(&sender.pubkey, &puzzle_hash));

        // different key can't spend
        let other = PaymentKey::generate();
        assert!(!other.can_spend_ecdh_coin(&sender.pubkey, &puzzle_hash));

        // pubkey-only key can't spend
        let pubkey_only = PaymentKey::from_pubkey(receiver.pubkey);
        assert!(!pubkey_only.can_spend_ecdh_coin(&sender.pubkey, &puzzle_hash));
    }

    #[test]
    fn test_from_pubkey() {
        let key = PaymentKey::generate();
        let pubkey_only = PaymentKey::from_pubkey(key.pubkey);

        assert_eq!(pubkey_only.pubkey, key.pubkey);
        assert!(pubkey_only.privkey.is_none());

        // can't derive from pubkey-only
        assert!(pubkey_only.derive_offer_key(0).is_err());
    }
}
