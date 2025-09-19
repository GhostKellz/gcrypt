//! Merkle Tree Implementation
//!
//! This module provides a comprehensive Merkle tree implementation for
//! blockchain state proofs, data integrity verification, and efficient
//! proof-of-inclusion/exclusion systems.
//!
//! Features:
//! - Binary Merkle trees with configurable hash functions
//! - Sparse Merkle trees for efficient state storage
//! - Merkle proofs (inclusion/exclusion)
//! - Batch verification
//! - Incremental updates

#[cfg(feature = "sha2")]
use crate::hash::Sha256Hasher;
#[cfg(feature = "blake3")]
use crate::hash::Blake3HasherWrapper;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String, boxed::Box};

/// Error types for Merkle tree operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    /// Invalid tree structure
    InvalidTree,
    /// Invalid proof
    InvalidProof,
    /// Empty leaf set
    EmptyLeaves,
    /// Mismatched proof length
    InvalidProofLength,
    /// Index out of bounds
    IndexOutOfBounds,
    /// Invalid hash length
    InvalidHashLength,
    /// Tree is full (for fixed-size trees)
    TreeFull,
    /// Serialization error
    SerializationError,
}

/// Hash output type (32 bytes for SHA-256/Blake3)
pub type Hash = [u8; 32];

/// Trait for different hash functions used in Merkle trees
pub trait MerkleHash {
    /// Hash a single value
    fn hash_leaf(data: &[u8]) -> Hash;

    /// Hash two child hashes to create parent hash
    fn hash_nodes(left: &Hash, right: &Hash) -> Hash;

    /// Name of the hash function
    fn name() -> &'static str;
}

/// SHA-256 based Merkle hash
#[cfg(feature = "sha2")]
pub struct Sha256MerkleHash;

#[cfg(feature = "sha2")]
impl MerkleHash for Sha256MerkleHash {
    fn hash_leaf(data: &[u8]) -> Hash {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"\x00"); // Leaf prefix
        hasher.update(data);
        hasher.finalize()
    }

    fn hash_nodes(left: &Hash, right: &Hash) -> Hash {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"\x01"); // Internal node prefix
        hasher.update(left);
        hasher.update(right);
        hasher.finalize()
    }

    fn name() -> &'static str {
        "SHA256"
    }
}

/// Blake3 based Merkle hash
#[cfg(feature = "blake3")]
pub struct Blake3MerkleHash;

#[cfg(feature = "blake3")]
impl MerkleHash for Blake3MerkleHash {
    fn hash_leaf(data: &[u8]) -> Hash {
        let mut hasher = Blake3HasherWrapper::new();
        hasher.update(b"\x00"); // Leaf prefix
        hasher.update(data);
        hasher.finalize()
    }

    fn hash_nodes(left: &Hash, right: &Hash) -> Hash {
        let mut hasher = Blake3HasherWrapper::new();
        hasher.update(b"\x01"); // Internal node prefix
        hasher.update(left);
        hasher.update(right);
        hasher.finalize()
    }

    fn name() -> &'static str {
        "Blake3"
    }
}

/// Binary Merkle tree
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MerkleTree<H: MerkleHash> {
    /// Tree layers (layer 0 = leaves, top layer = root)
    layers: Vec<Vec<Hash>>,
    /// Number of leaves
    leaf_count: usize,
    /// Hash function marker
    _hash: core::marker::PhantomData<H>,
}

impl<H: MerkleHash> MerkleTree<H> {
    /// Create a new Merkle tree from leaf data
    pub fn new(leaves: &[&[u8]]) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyLeaves);
        }

        let mut layers = Vec::new();

        // Hash leaves to create first layer
        let leaf_hashes: Vec<Hash> = leaves.iter()
            .map(|leaf| H::hash_leaf(leaf))
            .collect();

        let leaf_count = leaf_hashes.len();
        layers.push(leaf_hashes);

        // Build tree layers bottom-up
        while layers.last().unwrap().len() > 1 {
            let current_layer = layers.last().unwrap();
            let mut next_layer = Vec::new();

            // Process pairs of nodes
            for chunk in current_layer.chunks(2) {
                let left = &chunk[0];
                let right = if chunk.len() == 2 {
                    &chunk[1]
                } else {
                    // Odd number of nodes - duplicate the last one
                    left
                };
                next_layer.push(H::hash_nodes(left, right));
            }

            layers.push(next_layer);
        }

        Ok(Self {
            layers,
            leaf_count,
            _hash: core::marker::PhantomData,
        })
    }

    /// Get the root hash
    pub fn root(&self) -> &Hash {
        &self.layers.last().unwrap()[0]
    }

    /// Get the number of leaves
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Get the height of the tree
    pub fn height(&self) -> usize {
        self.layers.len()
    }

    /// Generate a Merkle proof for the leaf at given index
    pub fn prove(&self, index: usize) -> Result<MerkleProof, MerkleError> {
        if index >= self.leaf_count {
            return Err(MerkleError::IndexOutOfBounds);
        }

        let mut proof_hashes = Vec::new();
        let mut proof_directions = Vec::new();
        let mut current_index = index;

        // Traverse from leaf to root, collecting sibling hashes
        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            // Record direction (false = left, true = right)
            proof_directions.push(current_index % 2 == 1);

            // Get sibling hash (or duplicate if no sibling)
            if sibling_index < layer.len() {
                proof_hashes.push(layer[sibling_index]);
            } else {
                proof_hashes.push(layer[current_index]);
            }

            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf_index: index,
            leaf_hash: self.layers[0][index],
            proof_hashes,
            proof_directions,
        })
    }

    /// Verify a Merkle proof against this tree's root
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        Self::verify_proof_against_root(proof, self.root())
    }

    /// Verify a Merkle proof against a given root hash
    pub fn verify_proof_against_root(proof: &MerkleProof, expected_root: &Hash) -> bool {
        if proof.proof_hashes.len() != proof.proof_directions.len() {
            return false;
        }

        let mut current_hash = proof.leaf_hash;

        for (sibling_hash, is_right) in proof.proof_hashes.iter().zip(proof.proof_directions.iter()) {
            current_hash = if *is_right {
                // Current node is right child
                H::hash_nodes(sibling_hash, &current_hash)
            } else {
                // Current node is left child
                H::hash_nodes(&current_hash, sibling_hash)
            };
        }

        &current_hash == expected_root
    }

    /// Get leaf hash at index
    pub fn get_leaf(&self, index: usize) -> Result<&Hash, MerkleError> {
        if index >= self.leaf_count {
            return Err(MerkleError::IndexOutOfBounds);
        }
        Ok(&self.layers[0][index])
    }

    /// Update a leaf and recompute affected hashes
    pub fn update_leaf(&mut self, index: usize, new_data: &[u8]) -> Result<(), MerkleError> {
        if index >= self.leaf_count {
            return Err(MerkleError::IndexOutOfBounds);
        }

        // Update leaf hash
        self.layers[0][index] = H::hash_leaf(new_data);

        // Propagate changes up the tree
        let mut current_index = index;
        for layer_idx in 0..self.layers.len() - 1 {
            let parent_index = current_index / 2;
            let left_child_index = parent_index * 2;
            let right_child_index = left_child_index + 1;

            let left_hash = &self.layers[layer_idx][left_child_index];
            let right_hash = if right_child_index < self.layers[layer_idx].len() {
                &self.layers[layer_idx][right_child_index]
            } else {
                left_hash
            };

            self.layers[layer_idx + 1][parent_index] = H::hash_nodes(left_hash, right_hash);
            current_index = parent_index;
        }

        Ok(())
    }
}

/// Merkle proof for inclusion
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MerkleProof {
    /// Index of the leaf being proved
    pub leaf_index: usize,
    /// Hash of the leaf
    pub leaf_hash: Hash,
    /// Sibling hashes along the path to root
    pub proof_hashes: Vec<Hash>,
    /// Directions (false = left, true = right)
    pub proof_directions: Vec<bool>,
}

impl MerkleProof {
    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Leaf index (8 bytes)
        bytes.extend_from_slice(&(self.leaf_index as u64).to_le_bytes());

        // Leaf hash (32 bytes)
        bytes.extend_from_slice(&self.leaf_hash);

        // Number of proof elements (4 bytes)
        bytes.extend_from_slice(&(self.proof_hashes.len() as u32).to_le_bytes());

        // Proof hashes and directions
        for (hash, direction) in self.proof_hashes.iter().zip(self.proof_directions.iter()) {
            bytes.extend_from_slice(hash);
            bytes.push(if *direction { 1 } else { 0 });
        }

        bytes
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MerkleError> {
        if bytes.len() < 44 { // 8 + 32 + 4 minimum
            return Err(MerkleError::SerializationError);
        }

        let mut offset = 0;

        // Leaf index
        let leaf_index = u64::from_le_bytes(
            bytes[offset..offset + 8].try_into()
                .map_err(|_| MerkleError::SerializationError)?
        ) as usize;
        offset += 8;

        // Leaf hash
        let leaf_hash: Hash = bytes[offset..offset + 32].try_into()
            .map_err(|_| MerkleError::SerializationError)?;
        offset += 32;

        // Number of proof elements
        let proof_count = u32::from_le_bytes(
            bytes[offset..offset + 4].try_into()
                .map_err(|_| MerkleError::SerializationError)?
        ) as usize;
        offset += 4;

        // Check remaining length
        if bytes.len() != offset + proof_count * 33 { // 32 bytes hash + 1 byte direction
            return Err(MerkleError::SerializationError);
        }

        let mut proof_hashes = Vec::with_capacity(proof_count);
        let mut proof_directions = Vec::with_capacity(proof_count);

        for _ in 0..proof_count {
            // Hash
            let hash: Hash = bytes[offset..offset + 32].try_into()
                .map_err(|_| MerkleError::SerializationError)?;
            proof_hashes.push(hash);
            offset += 32;

            // Direction
            let direction = bytes[offset] != 0;
            proof_directions.push(direction);
            offset += 1;
        }

        Ok(Self {
            leaf_index,
            leaf_hash,
            proof_hashes,
            proof_directions,
        })
    }
}

/// Sparse Merkle Tree for efficient state storage
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SparseMerkleTree<H: MerkleHash> {
    /// Map from path to hash
    nodes: std::collections::HashMap<Vec<bool>, Hash>,
    /// Tree depth
    depth: usize,
    /// Default value hash
    default_hash: Hash,
    /// Hash function marker
    _hash: core::marker::PhantomData<H>,
}

impl<H: MerkleHash> SparseMerkleTree<H> {
    /// Create a new sparse Merkle tree with given depth
    pub fn new(depth: usize) -> Self {
        let default_hash = [0u8; 32]; // Hash of empty/default value

        Self {
            nodes: std::collections::HashMap::new(),
            depth,
            default_hash,
            _hash: core::marker::PhantomData,
        }
    }

    /// Set a value at the given key
    pub fn set(&mut self, key: &[u8; 32], value: &[u8]) -> Result<(), MerkleError> {
        let leaf_hash = H::hash_leaf(value);
        let path = self.key_to_path(key);

        // Set leaf
        self.nodes.insert(path.clone(), leaf_hash);

        // Update path to root
        for i in (0..self.depth).rev() {
            let parent_path = path[..i].to_vec();
            let child_bit = path[i];

            let left_path = {
                let mut p = parent_path.clone();
                p.push(false);
                p
            };
            let right_path = {
                let mut p = parent_path.clone();
                p.push(true);
                p
            };

            let left_hash = self.nodes.get(&left_path).unwrap_or(&self.default_hash);
            let right_hash = self.nodes.get(&right_path).unwrap_or(&self.default_hash);

            let parent_hash = H::hash_nodes(left_hash, right_hash);
            self.nodes.insert(parent_path, parent_hash);
        }

        Ok(())
    }

    /// Get the root hash
    pub fn root(&self) -> Hash {
        self.nodes.get(&Vec::new()).cloned().unwrap_or(self.default_hash)
    }

    /// Generate a proof of inclusion/exclusion for a key
    pub fn prove(&self, key: &[u8; 32]) -> SparseMerkleProof {
        let path = self.key_to_path(key);
        let mut proof_hashes = Vec::new();

        for i in 0..self.depth {
            let sibling_path = {
                let mut p = path[..i].to_vec();
                p.push(!path[i]);
                p
            };

            let sibling_hash = self.nodes.get(&sibling_path).unwrap_or(&self.default_hash);
            proof_hashes.push(*sibling_hash);
        }

        let leaf_hash = self.nodes.get(&path).unwrap_or(&self.default_hash);

        SparseMerkleProof {
            key: *key,
            value_hash: *leaf_hash,
            proof_hashes,
        }
    }

    /// Convert key to binary path
    fn key_to_path(&self, key: &[u8; 32]) -> Vec<bool> {
        let mut path = Vec::with_capacity(self.depth);

        for byte_idx in 0..(self.depth + 7) / 8 {
            if byte_idx >= 32 {
                break;
            }

            let byte = key[byte_idx];
            for bit_idx in 0..8 {
                if path.len() >= self.depth {
                    break;
                }
                path.push((byte >> (7 - bit_idx)) & 1 != 0);
            }
        }

        path
    }
}

/// Sparse Merkle tree proof
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SparseMerkleProof {
    /// The key being proved
    pub key: [u8; 32],
    /// Hash of the value (or default if not present)
    pub value_hash: Hash,
    /// Sibling hashes along the path
    pub proof_hashes: Vec<Hash>,
}

/// Batch verification for multiple Merkle proofs
pub fn batch_verify_proofs<H: MerkleHash>(
    proofs: &[MerkleProof],
    expected_root: &Hash,
) -> bool {
    proofs.iter().all(|proof| {
        MerkleTree::<H>::verify_proof_against_root(proof, expected_root)
    })
}

/// Utility functions for Merkle trees
pub mod utils {
    use super::*;

    /// Create a Merkle tree from a list of byte slices
    #[cfg(feature = "sha2")]
    pub fn create_tree_sha256(leaves: &[&[u8]]) -> Result<MerkleTree<Sha256MerkleHash>, MerkleError> {
        MerkleTree::new(leaves)
    }

    /// Create a Merkle tree from a list of byte slices using Blake3
    #[cfg(feature = "blake3")]
    pub fn create_tree_blake3(leaves: &[&[u8]]) -> Result<MerkleTree<Blake3MerkleHash>, MerkleError> {
        MerkleTree::new(leaves)
    }

    /// Verify multiple proofs efficiently
    #[cfg(feature = "sha2")]
    pub fn batch_verify_sha256(proofs: &[MerkleProof], root: &Hash) -> bool {
        batch_verify_proofs::<Sha256MerkleHash>(proofs, root)
    }

    /// Calculate the minimum tree height for a given number of leaves
    pub fn required_height(leaf_count: usize) -> usize {
        if leaf_count <= 1 {
            1
        } else {
            (leaf_count as f64).log2().ceil() as usize + 1
        }
    }

    /// Calculate the maximum number of leaves for a given height
    pub fn max_leaves(height: usize) -> usize {
        if height == 0 {
            0
        } else {
            1 << (height - 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "sha2")]
    fn test_merkle_tree_basic() {
        let leaves = vec![b"leaf1", b"leaf2", b"leaf3", b"leaf4"];
        let tree = MerkleTree::<Sha256MerkleHash>::new(&leaves).unwrap();

        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.height(), 3); // 4 leaves -> height 3

        // Test proofs
        for i in 0..4 {
            let proof = tree.prove(i).unwrap();
            assert!(tree.verify_proof(&proof));
        }
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_merkle_proof_serialization() {
        let leaves = vec![b"data1", b"data2", b"data3"];
        let tree = MerkleTree::<Sha256MerkleHash>::new(&leaves).unwrap();
        let proof = tree.prove(1).unwrap();

        let serialized = proof.to_bytes();
        let deserialized = MerkleProof::from_bytes(&serialized).unwrap();

        assert_eq!(proof, deserialized);
        assert!(tree.verify_proof(&deserialized));
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_tree_update() {
        let leaves = vec![b"original1", b"original2", b"original3"];
        let mut tree = MerkleTree::<Sha256MerkleHash>::new(&leaves).unwrap();
        let original_root = *tree.root();

        // Update middle leaf
        tree.update_leaf(1, b"updated2").unwrap();
        let new_root = *tree.root();

        // Root should change
        assert_ne!(original_root, new_root);

        // Proofs should still work
        let proof = tree.prove(1).unwrap();
        assert!(tree.verify_proof(&proof));
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_sparse_merkle_tree() {
        let mut smt = SparseMerkleTree::<Sha256MerkleHash>::new(256);

        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let value1 = b"value1";
        let value2 = b"value2";

        // Set values
        smt.set(&key1, value1).unwrap();
        smt.set(&key2, value2).unwrap();

        // Generate proofs
        let proof1 = smt.prove(&key1);
        let proof2 = smt.prove(&key2);

        // Verify proof structure
        assert_eq!(proof1.key, key1);
        assert_eq!(proof2.key, key2);
        assert_eq!(proof1.proof_hashes.len(), 256);
        assert_eq!(proof2.proof_hashes.len(), 256);
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_batch_verification() {
        let leaves = vec![b"a", b"b", b"c", b"d", b"e"];
        let tree = MerkleTree::<Sha256MerkleHash>::new(&leaves).unwrap();

        let proofs: Vec<_> = (0..5).map(|i| tree.prove(i).unwrap()).collect();

        assert!(utils::batch_verify_sha256(&proofs, tree.root()));

        // Test with wrong root
        let wrong_root = [0u8; 32];
        assert!(!utils::batch_verify_sha256(&proofs, &wrong_root));
    }

    #[test]
    fn test_utils() {
        assert_eq!(utils::required_height(1), 1);
        assert_eq!(utils::required_height(2), 2);
        assert_eq!(utils::required_height(4), 3);
        assert_eq!(utils::required_height(8), 4);

        assert_eq!(utils::max_leaves(1), 1);
        assert_eq!(utils::max_leaves(2), 2);
        assert_eq!(utils::max_leaves(3), 4);
        assert_eq!(utils::max_leaves(4), 8);
    }
}