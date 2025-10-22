//! Encrypted payment notes for cross-wallet transfers
//!
//! This module implements the payment note system that allows alice to send coins to bob
//! even when bob is offline. The note contains the serial_number and serial_randomness
//! needed to spend the coin, encrypted to bob's viewing key.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Encrypted payment note that can be decrypted by recipient
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedNote {
    /// Ephemeral public key for ECDH
    pub ephemeral_key: [u8; 32],

    /// Encrypted payload containing PaymentNote
    pub ciphertext: Vec<u8>,

    /// Nonce for ChaCha20-Poly1305
    pub nonce: [u8; 12],
}

/// Decrypted payment note containing coin secrets and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentNote {
    /// Serial number (becomes nullifier when spent)
    pub serial_number: [u8; 32],

    /// Serial randomness (proves knowledge of serial)
    pub serial_randomness: [u8; 32],

    /// Coin amount
    pub amount: u64,

    /// Puzzle hash for the coin
    pub puzzle_hash: [u8; 32],

    /// Optional memo (arbitrary data)
    pub memo: Vec<u8>,
}

impl EncryptedNote {
    /// Encrypt a payment note to a recipient's viewing public key
    ///
    /// Uses ECDH with ephemeral key + ChaCha20-Poly1305 for authenticated encryption
    pub fn encrypt(
        recipient_viewing_public: &[u8; 32],
        note: &PaymentNote,
    ) -> Result<Self, String> {
        // Generate ephemeral keypair for ECDH
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Perform ECDH
        let recipient_public = PublicKey::from(*recipient_viewing_public);
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

        // Derive encryption key from shared secret
        let key = Self::derive_encryption_key(shared_secret.as_bytes());

        // Serialize payment note
        let plaintext =
            serde_json::to_vec(note).map_err(|e| format!("failed to serialize note: {e}"))?;

        // Generate random nonce
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from(nonce_bytes);

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(&key.into());
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| format!("encryption failed: {e}"))?;

        Ok(EncryptedNote {
            ephemeral_key: ephemeral_public.to_bytes(),
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    /// Decrypt a payment note using recipient's viewing private key
    pub fn decrypt(&self, viewing_private: &[u8; 32]) -> Result<PaymentNote, String> {
        // Reconstruct ephemeral public key
        let ephemeral_public = PublicKey::from(self.ephemeral_key);

        // Perform ECDH with our private key
        let static_secret = StaticSecret::from(*viewing_private);
        let shared_secret = static_secret.diffie_hellman(&ephemeral_public);

        // Derive same encryption key
        let key = Self::derive_encryption_key(shared_secret.as_bytes());

        // Decrypt with ChaCha20-Poly1305
        let nonce = Nonce::from(self.nonce);
        let cipher = ChaCha20Poly1305::new(&key.into());
        let plaintext = cipher
            .decrypt(&nonce, self.ciphertext.as_ref())
            .map_err(|_| "decryption failed (wrong key or corrupted data)")?;

        // Deserialize payment note
        serde_json::from_slice(&plaintext).map_err(|e| format!("failed to deserialize note: {e}"))
    }

    /// Derive encryption key from ECDH shared secret using HKDF
    fn derive_encryption_key(shared_secret: &[u8]) -> [u8; 32] {
        // Use SHA256 as simple KDF
        // In production, use proper HKDF
        let mut hasher = Sha256::new();
        hasher.update(b"clvm_zk_note_encryption_v1");
        hasher.update(shared_secret);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate viewing keypair
        let viewing_private = rand::random::<[u8; 32]>();
        let viewing_public = PublicKey::from(&StaticSecret::from(viewing_private)).to_bytes();

        // Create payment note
        let note = PaymentNote {
            serial_number: rand::random(),
            serial_randomness: rand::random(),
            amount: 1000,
            puzzle_hash: rand::random(),
            memo: b"test payment".to_vec(),
        };

        // Encrypt
        let encrypted =
            EncryptedNote::encrypt(&viewing_public, &note).expect("encryption should succeed");

        // Decrypt
        let decrypted = encrypted
            .decrypt(&viewing_private)
            .expect("decryption should succeed");

        // Verify
        assert_eq!(decrypted.serial_number, note.serial_number);
        assert_eq!(decrypted.serial_randomness, note.serial_randomness);
        assert_eq!(decrypted.amount, note.amount);
        assert_eq!(decrypted.puzzle_hash, note.puzzle_hash);
        assert_eq!(decrypted.memo, note.memo);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let viewing_private1 = rand::random::<[u8; 32]>();
        let viewing_public1 = PublicKey::from(&StaticSecret::from(viewing_private1)).to_bytes();

        let viewing_private2 = rand::random::<[u8; 32]>();

        let note = PaymentNote {
            serial_number: rand::random(),
            serial_randomness: rand::random(),
            amount: 1000,
            puzzle_hash: rand::random(),
            memo: vec![],
        };

        let encrypted = EncryptedNote::encrypt(&viewing_public1, &note).unwrap();

        // Try to decrypt with wrong key
        let result = encrypted.decrypt(&viewing_private2);
        assert!(result.is_err());
    }
}
