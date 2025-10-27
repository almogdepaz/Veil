//! sparse merkle tree for coin commitment tracking
//!
//! provides authenticated membership proofs for coins in the utxo set.
//! uses a sparse merkle tree where leaves are coin commitments.

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// sparse merkle tree for tracking coin commitments
///
/// maintains a merkle tree where each leaf is a coin commitment.
/// allows efficient generation of membership proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseMerkleTree {
    /// tree leaves (coin commitments)
    leaves: Vec<[u8; 32]>,

    /// cached merkle root
    root: [u8; 32],

    /// tree depth (determines max capacity = 2^depth)
    depth: usize,

    /// empty node hashes at each level (for sparse tree optimization)
    empty_hashes: Vec<[u8; 32]>,
}

impl SparseMerkleTree {
    /// create new sparse merkle tree with given depth
    pub fn new(depth: usize, hasher: fn(&[u8]) -> [u8; 32]) -> Self {
        // precompute empty node hashes for each level
        let mut empty_hashes = Vec::with_capacity(depth + 1);

        // level 0 (leaves): empty leaf = hash("EMPTY_LEAF")
        empty_hashes.push(hasher(b"EMPTY_LEAF"));

        // higher levels: empty_node[i] = hash(empty_node[i-1] || empty_node[i-1])
        for i in 0..depth {
            let prev = empty_hashes[i];
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&prev);
            combined.extend_from_slice(&prev);
            empty_hashes.push(hasher(&combined));
        }

        let root = empty_hashes[depth];

        Self {
            leaves: Vec::new(),
            root,
            depth,
            empty_hashes,
        }
    }

    /// insert a new coin commitment and return its leaf index
    pub fn insert(&mut self, commitment: [u8; 32], hasher: fn(&[u8]) -> [u8; 32]) -> usize {
        let index = self.leaves.len();
        self.leaves.push(commitment);

        // recompute root
        self.root = self.compute_root(hasher);

        index
    }

    /// get current merkle root
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// get number of leaves
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// generate authentication path (merkle proof) for a leaf
    pub fn generate_proof(
        &self,
        leaf_index: usize,
        hasher: fn(&[u8]) -> [u8; 32],
    ) -> Result<MerkleProof, &'static str> {
        if leaf_index >= self.leaves.len() {
            return Err("leaf index out of bounds");
        }

        let mut path = Vec::new();
        let mut current_index = leaf_index;

        // for each level, collect the sibling hash
        for level in 0..self.depth {
            let sibling_index = current_index ^ 1; // flip last bit to get sibling

            let sibling_hash = if sibling_index < self.leaves.len() {
                // sibling exists, compute its hash at this level
                self.compute_node_hash(sibling_index, level, hasher)
            } else {
                // sibling is empty, use precomputed empty hash
                self.empty_hashes[level]
            };

            path.push(sibling_hash);
            current_index >>= 1; // move up one level
        }

        Ok(MerkleProof {
            leaf_index,
            leaf_value: self.leaves[leaf_index],
            path,
        })
    }

    /// verify a merkle proof against the current root
    pub fn verify_proof(&self, proof: &MerkleProof, hasher: fn(&[u8]) -> [u8; 32]) -> bool {
        let computed_root = proof.compute_root(hasher);
        computed_root == self.root
    }

    /// compute hash of a node at given index and level
    fn compute_node_hash(
        &self,
        index: usize,
        level: usize,
        hasher: fn(&[u8]) -> [u8; 32],
    ) -> [u8; 32] {
        if level == 0 {
            // base case: leaf level
            if index < self.leaves.len() {
                self.leaves[index]
            } else {
                self.empty_hashes[0]
            }
        } else {
            // recursive case: internal node
            let left_child = index << 1;
            let right_child = left_child + 1;

            let left_hash = self.compute_node_hash(left_child, level - 1, hasher);
            let right_hash = self.compute_node_hash(right_child, level - 1, hasher);

            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&left_hash);
            combined.extend_from_slice(&right_hash);
            hasher(&combined)
        }
    }

    /// compute current merkle root from leaves
    fn compute_root(&self, hasher: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
        if self.leaves.is_empty() {
            return self.empty_hashes[self.depth];
        }

        // compute root by hashing up from leaves
        self.compute_node_hash(0, self.depth, hasher)
    }
}

/// merkle proof for proving membership of a leaf
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// index of the leaf in the tree
    pub leaf_index: usize,

    /// value of the leaf (coin commitment)
    pub leaf_value: [u8; 32],

    /// authentication path (sibling hashes from leaf to root)
    pub path: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// compute the merkle root from this proof
    pub fn compute_root(&self, hasher: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
        let mut current_hash = self.leaf_value;
        let mut current_index = self.leaf_index;

        // hash up the tree using the authentication path
        for sibling in &self.path {
            let mut combined = Vec::with_capacity(64);

            // order matters: if index is even, we're on the left
            if current_index & 1 == 0 {
                // left child: hash(current || sibling)
                combined.extend_from_slice(&current_hash);
                combined.extend_from_slice(sibling);
            } else {
                // right child: hash(sibling || current)
                combined.extend_from_slice(sibling);
                combined.extend_from_slice(&current_hash);
            }

            current_hash = hasher(&combined);
            current_index >>= 1;
        }

        current_hash
    }

    /// verify this proof against a given root
    pub fn verify(&self, root: &[u8; 32], hasher: fn(&[u8]) -> [u8; 32]) -> bool {
        let computed_root = self.compute_root(hasher);
        &computed_root == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hasher(data: &[u8]) -> [u8; 32] {
        // simple test hasher: xor all bytes
        let mut result = [0u8; 32];
        for (i, byte) in data.iter().enumerate() {
            result[i % 32] ^= byte;
        }
        result
    }

    #[test]
    fn test_empty_tree() {
        let tree = SparseMerkleTree::new(4, test_hasher);
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());

        // root should be deterministic for empty tree
        let empty_root = tree.root();
        let tree2 = SparseMerkleTree::new(4, test_hasher);
        assert_eq!(empty_root, tree2.root());
    }

    #[test]
    fn test_insert_single_leaf() {
        let mut tree = SparseMerkleTree::new(4, test_hasher);
        let commitment = [1u8; 32];

        let index = tree.insert(commitment, test_hasher);

        assert_eq!(index, 0);
        assert_eq!(tree.len(), 1);
        assert!(!tree.is_empty());
    }

    #[test]
    fn test_insert_multiple_leaves() {
        let mut tree = SparseMerkleTree::new(4, test_hasher);

        for i in 0..5 {
            let commitment = [i as u8; 32];
            let index = tree.insert(commitment, test_hasher);
            assert_eq!(index, i as usize);
        }

        assert_eq!(tree.len(), 5);
    }

    #[test]
    fn test_root_changes_on_insert() {
        let mut tree = SparseMerkleTree::new(4, test_hasher);
        let initial_root = tree.root();

        tree.insert([1u8; 32], test_hasher);
        let root_after_insert = tree.root();

        assert_ne!(initial_root, root_after_insert);
    }

    #[test]
    fn test_generate_proof() {
        let mut tree = SparseMerkleTree::new(4, test_hasher);

        // insert some commitments
        tree.insert([1u8; 32], test_hasher);
        tree.insert([2u8; 32], test_hasher);
        tree.insert([3u8; 32], test_hasher);

        // generate proof for leaf 1
        let proof = tree.generate_proof(1, test_hasher).unwrap();

        assert_eq!(proof.leaf_index, 1);
        assert_eq!(proof.leaf_value, [2u8; 32]);
        assert_eq!(proof.path.len(), 4); // depth = 4
    }

    #[test]
    fn test_verify_proof() {
        let mut tree = SparseMerkleTree::new(4, test_hasher);

        tree.insert([1u8; 32], test_hasher);
        tree.insert([2u8; 32], test_hasher);
        tree.insert([3u8; 32], test_hasher);

        let proof = tree.generate_proof(1, test_hasher).unwrap();

        // proof should verify against tree root
        assert!(tree.verify_proof(&proof, test_hasher));
        assert!(proof.verify(&tree.root(), test_hasher));
    }

    #[test]
    fn test_proof_fails_with_wrong_root() {
        let mut tree = SparseMerkleTree::new(4, test_hasher);

        tree.insert([1u8; 32], test_hasher);
        let proof = tree.generate_proof(0, test_hasher).unwrap();

        // modify tree
        tree.insert([2u8; 32], test_hasher);

        // old proof should fail with new root
        assert!(!tree.verify_proof(&proof, test_hasher));
    }

    #[test]
    fn test_proof_compute_root() {
        let mut tree = SparseMerkleTree::new(4, test_hasher);

        tree.insert([1u8; 32], test_hasher);
        tree.insert([2u8; 32], test_hasher);

        let proof = tree.generate_proof(0, test_hasher).unwrap();
        let computed_root = proof.compute_root(test_hasher);

        assert_eq!(computed_root, tree.root());
    }

    #[test]
    fn test_proof_out_of_bounds() {
        let mut tree = SparseMerkleTree::new(4, test_hasher);
        tree.insert([1u8; 32], test_hasher);

        let result = tree.generate_proof(5, test_hasher);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_proofs_same_tree() {
        let mut tree = SparseMerkleTree::new(4, test_hasher);

        for i in 0..4 {
            tree.insert([i as u8; 32], test_hasher);
        }

        // all proofs should verify
        for i in 0..4 {
            let proof = tree.generate_proof(i, test_hasher).unwrap();
            assert!(tree.verify_proof(&proof, test_hasher));
        }
    }
}
