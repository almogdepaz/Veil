// crypto utilities
// shared stuff to avoid copy-pasting code everywhere

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// sha256 hash function for general use
pub fn hash_data_default(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// make viewing tag for coin discovery
///
/// viewing tags are 4-byte ids that let wallets scan for coins efficiently
/// without revealing spending keys. made from viewing key + coin index.
///
/// returns the first 4 bytes of the hash as the tag
pub fn generate_viewing_tag(viewing_key: &[u8; 32], coin_index: u32) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(b"clvm_zk_viewing_tag_v1"); // domain separator
    hasher.update(viewing_key); // account viewing key
    hasher.update(coin_index.to_le_bytes()); // coin index
    let hash: [u8; 32] = hasher.finalize().into();
    [hash[0], hash[1], hash[2], hash[3]] // first 4 bytes as tag
}

/// make viewing tag from string identifier (for testing)
///
/// simplified version for simulator testing that makes
/// a deterministic viewing tag from a string identifier.
pub fn generate_viewing_tag_from_string(identifier: &str, index: u32) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(b"clvm_zk_viewing_tag_v1");
    hasher.update(identifier.as_bytes());
    hasher.update(index.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    [hash[0], hash[1], hash[2], hash[3]]
}

/// check if a viewing tag matches any coin index within a range
///
/// used for wallet recovery to scan for coins belonging to an account.
/// returns the index if found, otherwise none
pub fn find_coin_index_by_viewing_tag(
    target_tag: &[u8; 4],
    viewing_key: &[u8; 32],
    max_index: u32,
) -> Option<u32> {
    for index in 0..max_index {
        let generated_tag = generate_viewing_tag(viewing_key, index);
        if generated_tag == *target_tag {
            return Some(index);
        }
    }
    None
}

/// encrypt a 32-byte stealth nonce to a recipient's x25519 public key.
/// returns 80 bytes: ephemeral_pubkey (32) || ciphertext (32 + 16 tag).
pub fn encrypt_stealth_nonce(
    nonce: &[u8; 32],
    recipient_pubkey: &[u8; 32],
) -> Vec<u8> {
    // 1. ephemeral x25519 keypair
    let ephemeral_secret = X25519Secret::random_from_rng(rand::thread_rng());
    let ephemeral_public = X25519Public::from(&ephemeral_secret);

    // 2. ECDH shared secret
    let recipient = X25519Public::from(*recipient_pubkey);
    let dh_shared = ephemeral_secret.diffie_hellman(&recipient);

    // 3. derive chacha key (separate domain from nonce)
    let chacha_key: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"veil_note_key_v1");
        h.update(dh_shared.as_bytes());
        h.finalize().into()
    };

    // 4. derive chacha nonce (first 12 bytes of separate hash)
    let chacha_nonce: [u8; 12] = {
        let mut h = Sha256::new();
        h.update(b"veil_note_encrypt_v1");
        h.update(dh_shared.as_bytes());
        let hash: [u8; 32] = h.finalize().into();
        let mut n = [0u8; 12];
        n.copy_from_slice(&hash[..12]);
        n
    };

    // 5. encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&chacha_key).expect("valid key length");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&chacha_nonce), nonce.as_slice())
        .expect("encryption should not fail");

    // 6. ephemeral_pubkey || ciphertext
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&ciphertext);
    out
}

/// decrypt an 80-byte encrypted stealth nonce using our x25519 private key.
/// returns None if auth tag fails (not our coin).
pub fn decrypt_stealth_nonce(
    encrypted_note: &[u8],
    recipient_privkey: &[u8; 32],
) -> Option<[u8; 32]> {
    if encrypted_note.len() != 80 {
        return None;
    }

    // 1. extract ephemeral pubkey
    let mut ephem_bytes = [0u8; 32];
    ephem_bytes.copy_from_slice(&encrypted_note[..32]);
    let ephemeral_public = X25519Public::from(ephem_bytes);

    // 2. ECDH
    let secret = X25519Secret::from(*recipient_privkey);
    let dh_shared = secret.diffie_hellman(&ephemeral_public);

    // 3. derive same key and nonce
    let chacha_key: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"veil_note_key_v1");
        h.update(dh_shared.as_bytes());
        h.finalize().into()
    };
    let chacha_nonce: [u8; 12] = {
        let mut h = Sha256::new();
        h.update(b"veil_note_encrypt_v1");
        h.update(dh_shared.as_bytes());
        let hash: [u8; 32] = h.finalize().into();
        let mut n = [0u8; 12];
        n.copy_from_slice(&hash[..12]);
        n
    };

    // 4. decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&chacha_key).ok()?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&chacha_nonce), &encrypted_note[32..])
        .ok()?;

    if plaintext.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_viewing_tag_deterministic() {
        let viewing_key = [0x42; 32];
        let index = 123;

        let tag1 = generate_viewing_tag(&viewing_key, index);
        let tag2 = generate_viewing_tag(&viewing_key, index);

        assert_eq!(tag1, tag2, "Viewing tags should be deterministic");
    }

    #[test]
    fn test_viewing_tag_uniqueness() {
        let viewing_key = [0x42; 32];

        let tag1 = generate_viewing_tag(&viewing_key, 1);
        let tag2 = generate_viewing_tag(&viewing_key, 2);

        assert_ne!(
            tag1, tag2,
            "Different indices should produce different tags"
        );
    }

    #[test]
    fn test_viewing_tag_from_string() {
        let tag1 = generate_viewing_tag_from_string("alice", 0);
        let tag2 = generate_viewing_tag_from_string("alice", 0);
        let tag3 = generate_viewing_tag_from_string("bob", 0);

        assert_eq!(tag1, tag2, "Same string should produce same tag");
        assert_ne!(
            tag1, tag3,
            "Different strings should produce different tags"
        );
    }

    #[test]
    fn test_find_coin_index_by_viewing_tag() {
        let viewing_key = [0x99; 32];
        let target_index = 42;

        // Generate a tag for index 42
        let target_tag = generate_viewing_tag(&viewing_key, target_index);

        // Should find the correct index
        let found_index = find_coin_index_by_viewing_tag(&target_tag, &viewing_key, 100);
        assert_eq!(found_index, Some(target_index));

        // Should not find if max_index is too small
        let not_found = find_coin_index_by_viewing_tag(&target_tag, &viewing_key, 10);
        assert_eq!(not_found, None);
    }

    #[test]
    fn test_viewing_tag_collision_resistance() {
        let viewing_key = [0x77; 32];
        let mut tags = std::collections::HashSet::new();

        // Generate 1000 tags and ensure no collisions
        for i in 0..1000 {
            let tag = generate_viewing_tag(&viewing_key, i);
            assert!(tags.insert(tag), "Collision detected at index {}", i);
        }
    }

    #[test]
    fn test_stealth_nonce_encrypt_decrypt_roundtrip() {
        let privkey: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"test_recipient_seed");
            h.finalize().into()
        };
        let pubkey = x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(privkey),
        )
        .to_bytes();

        let nonce = [0x42u8; 32];
        let encrypted = encrypt_stealth_nonce(&nonce, &pubkey);
        assert_eq!(encrypted.len(), 80);

        let decrypted = decrypt_stealth_nonce(&encrypted, &privkey).unwrap();
        assert_eq!(decrypted, nonce);
    }

    #[test]
    fn test_stealth_nonce_wrong_key_fails() {
        let privkey: [u8; 32] = [0xAA; 32];
        let pubkey = x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(privkey),
        )
        .to_bytes();

        let nonce = [0x42u8; 32];
        let encrypted = encrypt_stealth_nonce(&nonce, &pubkey);

        // wrong key should fail decryption
        let wrong_key: [u8; 32] = [0xBB; 32];
        assert!(decrypt_stealth_nonce(&encrypted, &wrong_key).is_none());
    }
}
