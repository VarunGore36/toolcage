//! Merkle tree for audit log inclusion proofs.
//!
//! This module provides a Merkle tree implementation for generating and
//! verifying inclusion proofs of events in the audit log. The tree is built
//! incrementally as events are appended, allowing efficient generation of
//! inclusion proofs without reading the entire log.
//!
//! The tree uses a binary Merkle tree with SHA-256 hashes. Leaf nodes are
//! event hashes, and internal nodes are hashes of their children. Inclusion
//! proofs consist of the sibling hashes along the path from the leaf to the
//! root.

use anyhow::Result;
use hex;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fmt;

/// A Merkle tree node hash (SHA-256).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleHash(pub String);

impl MerkleHash {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(bytes))
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        hex::decode(&self.0).map_err(|e| anyhow::anyhow!("invalid hex: {}", e))
    }
}

impl fmt::Display for MerkleHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A Merkle tree for audit log events.
///
/// The tree is built incrementally as events are appended. Each event's hash
/// becomes a leaf node, and internal nodes are computed as SHA-256 hashes of
/// their children's concatenated hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// Leaf hashes (event hashes) in order.
    leaves: Vec<MerkleHash>,
    /// Internal nodes, level by level (bottom-up).
    /// levels[0] = leaf hashes, levels[1] = parent hashes, etc.
    levels: Vec<Vec<MerkleHash>>,
    /// Root hash.
    root: Option<MerkleHash>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    /// Create a new empty Merkle tree.
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            levels: Vec::new(),
            root: None,
        }
    }

    /// Get the current root hash, if any.
    pub fn root(&self) -> Option<&MerkleHash> {
        self.root.as_ref()
    }

    /// Get the number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Append an event hash to the tree and update the Merkle root.
    ///
    /// Returns the index of the new leaf (0-based).
    pub fn append(&mut self, event_hash: &str) -> usize {
        let leaf_hash = MerkleHash(event_hash.to_string());
        let index = self.leaves.len();
        self.leaves.push(leaf_hash);

        // Rebuild the tree from the leaves up
        self.rebuild();

        index
    }

    /// Rebuild the entire Merkle tree from the leaves.
    fn rebuild(&mut self) {
        if self.leaves.is_empty() {
            self.levels.clear();
            self.root = None;
            return;
        }

        // Level 0: leaf hashes
        let mut current_level: Vec<MerkleHash> = self.leaves.clone();
        self.levels.clear();
        self.levels.push(current_level.clone());

        // Build upper levels
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    // Hash of both children concatenated
                    let left = &chunk[0];
                    let right = &chunk[1];
                    let combined = format!("{}{}", left.0, right.0);
                    let hash = sha2::Sha256::digest(combined.as_bytes());
                    MerkleHash(hex::encode(hash))
                } else {
                    // Odd number of nodes: promote the last one up
                    chunk[0].clone()
                };
                next_level.push(combined);
            }
            self.levels.push(next_level.clone());
            current_level = next_level;
        }

        // The root is the single hash at the top level
        self.root = current_level.first().cloned();
    }

    /// Get the leaf hash at the given index.
    pub fn get_leaf(&self, index: usize) -> Option<&MerkleHash> {
        self.leaves.get(index)
    }

    /// Generate an inclusion proof for the leaf at the given index.
    ///
    /// Returns the sibling hashes along the path from the leaf to the root.
    /// The proof can be verified by anyone who knows the root hash.
    pub fn inclusion_proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut proof = InclusionProof {
            leaf_index: index,
            leaf_hash: self.leaves[index].clone(),
            siblings: Vec::new(),
            tree_height: self.levels.len(),
            has_sibling: Vec::new(),
        };

        let mut index = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_index = if index.is_multiple_of(2) {
                // Left child, sibling is right
                if index + 1 < level.len() {
                    Some(index + 1)
                } else {
                    // No sibling (odd number of nodes at this level)
                    None
                }
            } else {
                // Right child, sibling is left
                Some(index - 1)
            };

            // Record whether there was a sibling at this level
            proof.has_sibling.push(sibling_index.is_some());

            // Add sibling to proof only if it exists
            if let Some(sibling_index) = sibling_index {
                if sibling_index < level.len() {
                    proof.siblings.push(level[sibling_index].clone());
                }
            }

            // Move up to parent level
            index /= 2;
        }

        Some(proof)
    }

    /// Verify an inclusion proof against this tree's root.
    pub fn verify_proof(&self, proof: &InclusionProof) -> bool {
        self.root.as_ref() == Some(&proof.root())
    }

    /// Get the number of levels in the tree (including leaves).
    pub fn height(&self) -> usize {
        self.levels.len()
    }

    /// Get all leaves.
    pub fn leaves(&self) -> &[MerkleHash] {
        &self.leaves
    }
}

/// An inclusion proof for a Merkle tree leaf.
///
/// Contains the leaf index, its hash, and the sibling hashes along the
/// path to the root. The proof can be verified against a known root hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the leaf in the tree (0-based).
    pub leaf_index: usize,
    /// Hash of the leaf itself.
    pub leaf_hash: MerkleHash,
    /// Sibling hashes from leaf to root (bottom-up).
    pub siblings: Vec<MerkleHash>,
    /// Height of the tree (number of levels from leaf to root).
    pub tree_height: usize,
    /// For each level from leaf to root (excluding root), whether the node had a sibling.
    /// True = had sibling (hash with sibling), False = promoted (no hash).
    pub has_sibling: Vec<bool>,
}

/// Compute the root hash from this inclusion proof.
impl InclusionProof {
    pub fn root(&self) -> MerkleHash {
        let mut current = self.leaf_hash.clone();
        let mut index = self.leaf_index;
        let mut sibling_idx = 0;

        // We need to iterate through all levels from leaf to root (tree_height - 1 steps)
        // At each level, check if there was a sibling or if the node was promoted
        for &has_sibling in &self.has_sibling {
            if has_sibling {
                // There was a sibling at this level, hash with it
                let sibling = &self.siblings[sibling_idx];
                let combined = if index.is_multiple_of(2) {
                    format!("{}{}", current.0, sibling.0)
                } else {
                    format!("{}{}", sibling.0, current.0)
                };
                let hash = sha2::Sha256::digest(combined.as_bytes());
                current = MerkleHash(hex::encode(hash));
                sibling_idx += 1;
            } else {
                // No sibling at this level: node was promoted, hash stays the same
                // (or we could hash with empty, but promotion means the hash is carried up unchanged)
            }
            index /= 2;
        }

        current
    }

    /// Verify this inclusion proof against a known root hash.
    pub fn verify(&self, expected_root: &MerkleHash) -> bool {
        self.root() == *expected_root
    }

    /// Get the leaf index.
    pub fn leaf_index(&self) -> usize {
        self.leaf_index
    }

    /// Get the leaf hash.
    pub fn leaf_hash(&self) -> &MerkleHash {
        &self.leaf_hash
    }

    /// Get the sibling hashes.
    pub fn siblings(&self) -> &[MerkleHash] {
        &self.siblings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert!(tree.root().is_none());
    }

    #[test]
    fn test_single_leaf() {
        let mut tree = MerkleTree::new();
        tree.append("hash1");
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.root(), tree.get_leaf(0));
    }

    #[test]
    fn test_two_leaves() {
        let mut tree = MerkleTree::new();
        tree.append("hash1");
        tree.append("hash2");

        assert_eq!(tree.len(), 2);
        assert!(tree.root().is_some());

        // Root should be hash of "hash1" + "hash2"
        let expected = format!("{}{}", "hash1", "hash2");
        let expected_hash = hex::encode(sha2::Sha256::digest(expected.as_bytes()));
        assert_eq!(tree.root().unwrap().0, expected_hash);
    }

    #[test]
    fn test_four_leaves() {
        let mut tree = MerkleTree::new();
        tree.append("h1");
        tree.append("h2");
        tree.append("h3");
        tree.append("hash4");

        assert_eq!(tree.len(), 4);
        assert!(tree.root().is_some());

        // Verify inclusion proofs for all leaves
        for i in 0..4 {
            let proof = tree.inclusion_proof(i).unwrap();
            assert!(proof.verify(tree.root().unwrap()));
            assert_eq!(proof.leaf_index(), i);
        }
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let mut tree = MerkleTree::new();
        tree.append("h1");
        tree.append("h2");
        tree.append("h3");

        assert_eq!(tree.len(), 3);
        assert!(tree.root().is_some());

        // Verify inclusion proofs
        for i in 0..3 {
            let proof = tree.inclusion_proof(i).unwrap();
            assert!(proof.verify(tree.root().unwrap()));
        }
    }

    #[test]
    fn test_inclusion_proof_verification() {
        let mut tree = MerkleTree::new();
        tree.append("h1");
        tree.append("h2");
        tree.append("h3");
        tree.append("h4");

        let root = tree.root().unwrap().clone();

        // Verify all inclusion proofs
        for i in 0..4 {
            let proof = tree.inclusion_proof(i).unwrap();
            assert!(proof.verify(&root), "Proof {} failed verification", i);
        }

        // Tamper with proof should fail
        let mut proof = tree.inclusion_proof(0).unwrap();
        proof.leaf_hash = MerkleHash("tampered".to_string());
        assert!(!proof.verify(&root));
    }

    #[test]
    fn test_empty_tree_proof() {
        let tree = MerkleTree::new();
        assert!(tree.inclusion_proof(0).is_none());
    }

    #[test]
    fn test_out_of_bounds_proof() {
        let mut tree = MerkleTree::new();
        tree.append("h1");
        assert!(tree.inclusion_proof(1).is_none());
    }
}
