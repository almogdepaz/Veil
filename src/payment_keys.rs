//! Hash-based stealth payment keys for unlinkable transfers
//!
//! Payment keys enable receiver-derived addresses:
//! - sender picks random nonce, computes puzzle = hash(receiver_pubkey || nonce)
//! - sender encrypts nonce to receiver's pubkey
//! - receiver decrypts nonce, derives same puzzle
//!
//! Uses hash-based stealth (consistent with settlement proofs) instead of ECDH

use sha2::{Digest, Sha256};

/// payment key for stealth address derivation
#[derive(Debug, Clone)]
pub struct PaymentKey {
    /// public key (32 bytes) - used in puzzle derivation
    pub pubkey: [u8; 32],

    /// private key (only holder knows, None for receive-only keys)
    /// used for decrypting nonces sent by senders
    pub privkey: Option<[u8; 32]>,
}

impl PaymentKey {
    /// create payment key from private key
    pub fn from_privkey(privkey: [u8; 32]) -> Self {
        // derive public key via hash (deterministic, no EC math needed)
        let mut hasher = Sha256::new();
        hasher.update(b"stealth_pubkey_v1");
        hasher.update(privkey);
        let pubkey: [u8; 32] = hasher.finalize().into();

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

        let mut hasher = Sha256::new();
        hasher.update(b"offer_derivation");
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

    /// check if this key can spend a coin created with given nonce
    ///
    /// receiver uses their pubkey + the nonce to derive the expected puzzle
    pub fn can_spend_stealth_coin(&self, nonce: &[u8; 32], puzzle_hash: &[u8; 32]) -> bool {
        let derived = derive_stealth_puzzle_hash(&self.pubkey, nonce);
        derived == *puzzle_hash
    }

    /// derive encryption key for receiving encrypted nonces
    ///
    /// senders encrypt nonces to this key so receiver can decrypt and derive puzzle
    pub fn derive_encryption_key(&self) -> Result<[u8; 32], &'static str> {
        let privkey = self
            .privkey
            .ok_or("cannot derive encryption key from pubkey-only")?;

        let mut hasher = Sha256::new();
        hasher.update(b"stealth_encryption_v1");
        hasher.update(privkey);
        Ok(hasher.finalize().into())
    }

    /// get public key bytes
    pub fn to_pubkey(&self) -> [u8; 32] {
        self.pubkey
    }
}

/// derive stealth puzzle hash from receiver's pubkey and sender's nonce
///
/// sender side: generates random nonce, computes puzzle, encrypts nonce to receiver
/// receiver side: decrypts nonce, computes same puzzle
///
/// consistent with settlement proof stealth address derivation
pub fn derive_stealth_puzzle_hash(receiver_pubkey: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"stealth_v1");
    hasher.update(receiver_pubkey);
    hasher.update(nonce);
    hasher.finalize().into()
}

/// generate a random nonce for stealth payment
pub fn generate_stealth_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    nonce
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
    fn test_stealth_puzzle_derivation() {
        let receiver = PaymentKey::generate();
        let nonce = generate_stealth_nonce();

        // derive puzzle hash
        let puzzle = derive_stealth_puzzle_hash(&receiver.pubkey, &nonce);

        // receiver can verify with same nonce
        assert!(receiver.can_spend_stealth_coin(&nonce, &puzzle));

        // different nonce = different puzzle
        let other_nonce = generate_stealth_nonce();
        assert!(!receiver.can_spend_stealth_coin(&other_nonce, &puzzle));

        // different receiver can't spend
        let other = PaymentKey::generate();
        assert!(!other.can_spend_stealth_coin(&nonce, &puzzle));
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
    fn test_deterministic_pubkey_derivation() {
        let privkey = [42u8; 32];

        let key1 = PaymentKey::from_privkey(privkey);
        let key2 = PaymentKey::from_privkey(privkey);

        // same privkey = same pubkey
        assert_eq!(key1.pubkey, key2.pubkey);
    }
}
