// crypto utilities
// shared stuff to avoid copy-pasting code everywhere

use sha2::{Digest, Sha256};

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

/// make canonical nullifier with domain separation and puzzle binding
///
/// this implements the hardened nullifier algorithm v1.0 with:
/// - domain separation to prevent cross-protocol attacks
/// - puzzle binding for future features
/// - deterministic output for the same inputs
///
/// design note: the puzzle_hash binding is defensive programming.
/// in the current protocol, each spend_secret should be globally unique,
/// so simple sha256(spend_secret) would work for double-spend prevention.
/// but puzzle_hash binding gives us:
/// - future-proofing for protocol extensions
/// - extra protection against bugs
/// - flexibility for future features
///
/// returns 32-byte nullifier that uniquely identifies this spend
pub fn generate_nullifier(spend_secret: &[u8; 32], puzzle_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"clvm_zk_nullifier_v1.0"); // domain separator for protocol version
    hasher.update(spend_secret); // unique spend secret
    hasher.update(puzzle_hash); // defensive puzzle binding for future features
    hasher.finalize().into()
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
}
