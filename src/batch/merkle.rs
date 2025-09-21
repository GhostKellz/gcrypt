//! Batch Merkle Tree Operations
//!
//! High-performance batch operations for Merkle tree construction,
//! verification, and updates optimized for blockchain applications.

use crate::{field::FieldElement, hash::blake3_hash};
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "rayon")]
use rayon::prelude::*;

/// Batch Merkle operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchMerkleError {
    /// Invalid tree height
    InvalidHeight,
    /// Input arrays have mismatched lengths
    MismatchedLengths,
    /// Batch is empty
    EmptyBatch,
    /// Invalid proof format
    InvalidProof,
    /// Tree construction failed
    ConstructionFailed,
}

impl fmt::Display for BatchMerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BatchMerkleError::InvalidHeight => write!(f, "Invalid Merkle tree height"),
            BatchMerkleError::MismatchedLengths => write!(f, "Input arrays have mismatched lengths"),
            BatchMerkleError::EmptyBatch => write!(f, "Batch is empty"),
            BatchMerkleError::InvalidProof => write!(f, "Invalid Merkle proof format"),
            BatchMerkleError::ConstructionFailed => write!(f, "Merkle tree construction failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BatchMerkleError {}

/// Merkle tree proof structure
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Path from leaf to root (sibling hashes)
    pub path: Vec<[u8; 32]>,
    /// Leaf index
    pub index: usize,
    /// Root hash
    pub root: [u8; 32],
}

impl MerkleProof {
    /// Create a new Merkle proof
    pub fn new(path: Vec<[u8; 32]>, index: usize, root: [u8; 32]) -> Self {
        Self { path, index, root }
    }

    /// Verify this proof against a leaf value
    pub fn verify(&self, leaf: &[u8]) -> bool {
        let mut current_hash = blake3_hash(leaf);
        let mut index = self.index;

        for &sibling_hash in &self.path {
            let mut combined = [0u8; 64];

            if index % 2 == 0 {
                // Current hash is left child
                combined[..32].copy_from_slice(&current_hash);
                combined[32..].copy_from_slice(&sibling_hash);
            } else {
                // Current hash is right child
                combined[..32].copy_from_slice(&sibling_hash);
                combined[32..].copy_from_slice(&current_hash);
            }

            current_hash = blake3_hash(&combined);
            index /= 2;
        }

        current_hash == self.root
    }

    /// Get the depth of this proof
    pub fn depth(&self) -> usize {
        self.path.len()
    }
}

/// High-performance batch Merkle tree builder
pub struct BatchMerkleTreeBuilder {
    /// Whether to use parallel processing
    use_parallel: bool,
    /// Minimum batch size for parallel processing
    parallel_threshold: usize,
}

impl BatchMerkleTreeBuilder {
    /// Create a new batch Merkle tree builder
    pub fn new() -> Self {
        Self {
            use_parallel: cfg!(feature = "rayon"),
            parallel_threshold: 64,
        }
    }

    /// Enable or disable parallel processing
    pub fn with_parallel(mut self, use_parallel: bool) -> Self {
        self.use_parallel = use_parallel && cfg!(feature = "rayon");
        self
    }

    /// Set the parallel processing threshold
    pub fn with_parallel_threshold(mut self, threshold: usize) -> Self {
        self.parallel_threshold = threshold;
        self
    }

    /// Build a Merkle tree from a batch of leaves
    #[cfg(feature = "alloc")]
    pub fn build_tree(&self, leaves: &[&[u8]]) -> Result<([u8; 32], Vec<Vec<[u8; 32]>>), BatchMerkleError> {
        if leaves.is_empty() {
            return Err(BatchMerkleError::EmptyBatch);
        }

        // Hash all leaves first
        let leaf_hashes = if self.use_parallel && leaves.len() >= self.parallel_threshold {
            self.hash_leaves_parallel(leaves)
        } else {
            self.hash_leaves_sequential(leaves)
        };

        // Build tree levels
        let (root, levels) = self.build_tree_levels(leaf_hashes)?;

        Ok((root, levels))
    }

    /// Hash leaves sequentially
    #[cfg(feature = "alloc")]
    fn hash_leaves_sequential(&self, leaves: &[&[u8]]) -> Vec<[u8; 32]> {
        leaves.iter().map(|leaf| blake3_hash(leaf)).collect()
    }

    /// Hash leaves in parallel
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn hash_leaves_parallel(&self, leaves: &[&[u8]]) -> Vec<[u8; 32]> {
        leaves.par_iter().map(|leaf| blake3_hash(leaf)).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn hash_leaves_parallel(&self, leaves: &[&[u8]]) -> Vec<[u8; 32]> {
        self.hash_leaves_sequential(leaves)
    }

    /// Build tree levels from leaf hashes
    #[cfg(feature = "alloc")]
    fn build_tree_levels(&self, mut current_level: Vec<[u8; 32]>) -> Result<([u8; 32], Vec<Vec<[u8; 32]>>), BatchMerkleError> {
        let mut levels = Vec::new();
        levels.push(current_level.clone());

        while current_level.len() > 1 {
            current_level = if self.use_parallel && current_level.len() >= self.parallel_threshold {
                self.build_next_level_parallel(&current_level)
            } else {
                self.build_next_level_sequential(&current_level)
            };

            levels.push(current_level.clone());
        }

        if current_level.is_empty() {
            return Err(BatchMerkleError::ConstructionFailed);
        }

        Ok((current_level[0], levels))
    }

    /// Build next tree level sequentially
    #[cfg(feature = "alloc")]
    fn build_next_level_sequential(&self, level: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let mut next_level = Vec::with_capacity((level.len() + 1) / 2);

        for chunk in level.chunks(2) {
            let combined_hash = if chunk.len() == 2 {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&chunk[0]);
                combined[32..].copy_from_slice(&chunk[1]);
                blake3_hash(&combined)
            } else {
                // Odd number of nodes, hash with itself
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&chunk[0]);
                combined[32..].copy_from_slice(&chunk[0]);
                blake3_hash(&combined)
            };

            next_level.push(combined_hash);
        }

        next_level
    }

    /// Build next tree level in parallel
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn build_next_level_parallel(&self, level: &[[u8; 32]]) -> Vec<[u8; 32]> {
        level.par_chunks(2).map(|chunk| {
            let combined_hash = if chunk.len() == 2 {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&chunk[0]);
                combined[32..].copy_from_slice(&chunk[1]);
                blake3_hash(&combined)
            } else {
                // Odd number of nodes, hash with itself
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&chunk[0]);
                combined[32..].copy_from_slice(&chunk[0]);
                blake3_hash(&combined)
            };
            combined_hash
        }).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn build_next_level_parallel(&self, level: &[[u8; 32]]) -> Vec<[u8; 32]> {
        self.build_next_level_sequential(level)
    }

    /// Generate Merkle proofs for multiple leaves
    #[cfg(feature = "alloc")]
    pub fn generate_proofs(
        &self,
        levels: &[Vec<[u8; 32]>],
        indices: &[usize],
    ) -> Result<Vec<MerkleProof>, BatchMerkleError> {
        if levels.is_empty() {
            return Err(BatchMerkleError::EmptyBatch);
        }

        let root = levels.last().unwrap()[0];
        let proofs = if self.use_parallel && indices.len() >= 8 {
            self.generate_proofs_parallel(levels, indices, root)
        } else {
            self.generate_proofs_sequential(levels, indices, root)
        };

        Ok(proofs)
    }

    /// Generate proofs sequentially
    #[cfg(feature = "alloc")]
    fn generate_proofs_sequential(
        &self,
        levels: &[Vec<[u8; 32]>],
        indices: &[usize],
        root: [u8; 32],
    ) -> Vec<MerkleProof> {
        indices.iter().map(|&index| self.generate_single_proof(levels, index, root)).collect()
    }

    /// Generate proofs in parallel
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn generate_proofs_parallel(
        &self,
        levels: &[Vec<[u8; 32]>],
        indices: &[usize],
        root: [u8; 32],
    ) -> Vec<MerkleProof> {
        indices.par_iter().map(|&index| self.generate_single_proof(levels, index, root)).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn generate_proofs_parallel(
        &self,
        levels: &[Vec<[u8; 32]>],
        indices: &[usize],
        root: [u8; 32],
    ) -> Vec<MerkleProof> {
        self.generate_proofs_sequential(levels, indices, root)
    }

    /// Generate a single Merkle proof
    #[cfg(feature = "alloc")]
    fn generate_single_proof(&self, levels: &[Vec<[u8; 32]>], mut index: usize, root: [u8; 32]) -> MerkleProof {
        let mut path = Vec::new();

        // Skip the last level (root)
        for level in levels.iter().take(levels.len() - 1) {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };

            if sibling_index < level.len() {
                path.push(level[sibling_index]);
            } else {
                // If sibling doesn't exist, use the node itself (for odd number of nodes)
                path.push(level[index]);
            }

            index /= 2;
        }

        MerkleProof::new(path, index, root)
    }
}

impl Default for BatchMerkleTreeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch Merkle proof verifier
pub struct BatchMerkleProofVerifier {
    /// Whether to use parallel processing
    use_parallel: bool,
}

impl BatchMerkleProofVerifier {
    /// Create a new batch proof verifier
    pub fn new() -> Self {
        Self {
            use_parallel: cfg!(feature = "rayon"),
        }
    }

    /// Enable or disable parallel processing
    pub fn with_parallel(mut self, use_parallel: bool) -> Self {
        self.use_parallel = use_parallel && cfg!(feature = "rayon");
        self
    }

    /// Verify a batch of Merkle proofs
    #[cfg(feature = "alloc")]
    pub fn verify_batch(
        &self,
        proofs: &[MerkleProof],
        leaves: &[&[u8]],
    ) -> Result<Vec<bool>, BatchMerkleError> {
        if proofs.len() != leaves.len() {
            return Err(BatchMerkleError::MismatchedLengths);
        }

        if proofs.is_empty() {
            return Err(BatchMerkleError::EmptyBatch);
        }

        let results = if self.use_parallel && proofs.len() >= 8 {
            self.verify_batch_parallel(proofs, leaves)
        } else {
            self.verify_batch_sequential(proofs, leaves)
        };

        Ok(results)
    }

    /// Verify proofs sequentially
    #[cfg(feature = "alloc")]
    fn verify_batch_sequential(&self, proofs: &[MerkleProof], leaves: &[&[u8]]) -> Vec<bool> {
        proofs.iter().zip(leaves.iter()).map(|(proof, leaf)| proof.verify(leaf)).collect()
    }

    /// Verify proofs in parallel
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn verify_batch_parallel(&self, proofs: &[MerkleProof], leaves: &[&[u8]]) -> Vec<bool> {
        proofs.par_iter().zip(leaves.par_iter()).map(|(proof, leaf)| proof.verify(leaf)).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn verify_batch_parallel(&self, proofs: &[MerkleProof], leaves: &[&[u8]]) -> Vec<bool> {
        self.verify_batch_sequential(proofs, leaves)
    }

    /// Verify that all proofs in a batch are valid
    #[cfg(feature = "alloc")]
    pub fn verify_all(&self, proofs: &[MerkleProof], leaves: &[&[u8]]) -> Result<bool, BatchMerkleError> {
        let results = self.verify_batch(proofs, leaves)?;
        Ok(results.iter().all(|&valid| valid))
    }
}

impl Default for BatchMerkleProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience functions for batch Merkle operations
#[cfg(feature = "alloc")]
pub mod batch_merkle {
    use super::*;

    /// Build a Merkle tree from leaves and return the root
    pub fn build_tree_root(leaves: &[&[u8]]) -> Result<[u8; 32], BatchMerkleError> {
        let builder = BatchMerkleTreeBuilder::new();
        let (root, _) = builder.build_tree(leaves)?;
        Ok(root)
    }

    /// Build a Merkle tree and generate proofs for all leaves
    pub fn build_tree_with_proofs(leaves: &[&[u8]]) -> Result<([u8; 32], Vec<MerkleProof>), BatchMerkleError> {
        let builder = BatchMerkleTreeBuilder::new();
        let (root, levels) = builder.build_tree(leaves)?;

        let indices: Vec<usize> = (0..leaves.len()).collect();
        let proofs = builder.generate_proofs(&levels, &indices)?;

        Ok((root, proofs))
    }

    /// Verify a batch of Merkle proofs
    pub fn verify_proofs(proofs: &[MerkleProof], leaves: &[&[u8]]) -> Result<bool, BatchMerkleError> {
        let verifier = BatchMerkleProofVerifier::new();
        verifier.verify_all(proofs, leaves)
    }

    /// Build tree and verify consistency
    pub fn build_and_verify(leaves: &[&[u8]]) -> Result<bool, BatchMerkleError> {
        let (root, proofs) = build_tree_with_proofs(leaves)?;

        // Verify all proofs against the computed root
        let all_valid = proofs.iter().zip(leaves.iter()).all(|(proof, leaf)| {
            proof.root == root && proof.verify(leaf)
        });

        Ok(all_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_leaves(count: usize) -> Vec<Vec<u8>> {
        (0..count).map(|i| format!("leaf_{}", i).into_bytes()).collect()
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_merkle_tree_construction() {
        let leaves_data = create_test_leaves(8);
        let leaves: Vec<&[u8]> = leaves_data.iter().map(|l| l.as_slice()).collect();

        let builder = BatchMerkleTreeBuilder::new();
        let result = builder.build_tree(&leaves);

        assert!(result.is_ok());

        let (root, levels) = result.unwrap();
        assert_ne!(root, [0u8; 32]);
        assert_eq!(levels.len(), 4); // 8 -> 4 -> 2 -> 1 levels
        assert_eq!(levels[0].len(), 8); // Leaf level
        assert_eq!(levels[3].len(), 1); // Root level
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_single_merkle_proof() {
        let leaf_data = b"test_leaf";
        let proof_data = MerkleProof::new(
            vec![[1u8; 32], [2u8; 32]],
            0,
            [3u8; 32],
        );

        // This will likely fail with our simplified test data, but should not panic
        let _result = proof_data.verify(leaf_data);
        assert_eq!(proof_data.depth(), 2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_proof_generation() {
        let leaves_data = create_test_leaves(4);
        let leaves: Vec<&[u8]> = leaves_data.iter().map(|l| l.as_slice()).collect();

        let builder = BatchMerkleTreeBuilder::new();
        let (root, levels) = builder.build_tree(&leaves).unwrap();

        let indices = vec![0, 1, 2, 3];
        let proofs = builder.generate_proofs(&levels, &indices).unwrap();

        assert_eq!(proofs.len(), 4);
        for proof in &proofs {
            assert_eq!(proof.root, root);
            assert_eq!(proof.depth(), 2); // log2(4) = 2 levels
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_proof_verification() {
        let leaves_data = create_test_leaves(4);
        let leaves: Vec<&[u8]> = leaves_data.iter().map(|l| l.as_slice()).collect();

        let builder = BatchMerkleTreeBuilder::new();
        let (root, levels) = builder.build_tree(&leaves).unwrap();

        let indices = vec![0, 1, 2, 3];
        let proofs = builder.generate_proofs(&levels, &indices).unwrap();

        let verifier = BatchMerkleProofVerifier::new();
        let results = verifier.verify_batch(&proofs, &leaves).unwrap();

        assert_eq!(results.len(), 4);
        // All proofs should be valid since we generated them correctly
        assert!(results.iter().all(|&valid| valid));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_empty_batch_error() {
        let builder = BatchMerkleTreeBuilder::new();
        let result = builder.build_tree(&[]);

        assert!(matches!(result, Err(BatchMerkleError::EmptyBatch)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_mismatched_lengths() {
        let leaves_data = create_test_leaves(3);
        let leaves: Vec<&[u8]> = leaves_data.iter().map(|l| l.as_slice()).collect();

        let verifier = BatchMerkleProofVerifier::new();
        let proofs = vec![MerkleProof::new(vec![], 0, [0u8; 32]); 2]; // Different length

        let result = verifier.verify_batch(&proofs, &leaves);
        assert!(matches!(result, Err(BatchMerkleError::MismatchedLengths)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_convenience_functions() {
        let leaves_data = create_test_leaves(6);
        let leaves: Vec<&[u8]> = leaves_data.iter().map(|l| l.as_slice()).collect();

        let root = batch_merkle::build_tree_root(&leaves).unwrap();
        assert_ne!(root, [0u8; 32]);

        let (root2, proofs) = batch_merkle::build_tree_with_proofs(&leaves).unwrap();
        assert_eq!(root, root2);
        assert_eq!(proofs.len(), 6);

        let all_valid = batch_merkle::verify_proofs(&proofs, &leaves).unwrap();
        assert!(all_valid);

        let consistency_check = batch_merkle::build_and_verify(&leaves).unwrap();
        assert!(consistency_check);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_parallel_vs_sequential() {
        let leaves_data = create_test_leaves(100);
        let leaves: Vec<&[u8]> = leaves_data.iter().map(|l| l.as_slice()).collect();

        let sequential_builder = BatchMerkleTreeBuilder::new().with_parallel(false);
        let parallel_builder = BatchMerkleTreeBuilder::new().with_parallel(true);

        let (seq_root, _) = sequential_builder.build_tree(&leaves).unwrap();
        let (par_root, _) = parallel_builder.build_tree(&leaves).unwrap();

        // Both should produce the same result
        assert_eq!(seq_root, par_root);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_odd_number_of_leaves() {
        let leaves_data = create_test_leaves(7); // Odd number
        let leaves: Vec<&[u8]> = leaves_data.iter().map(|l| l.as_slice()).collect();

        let builder = BatchMerkleTreeBuilder::new();
        let result = builder.build_tree(&leaves);

        assert!(result.is_ok());

        let (root, levels) = result.unwrap();
        assert_ne!(root, [0u8; 32]);
        assert_eq!(levels[0].len(), 7); // Leaf level
        assert_eq!(levels.last().unwrap().len(), 1); // Root level
    }
}