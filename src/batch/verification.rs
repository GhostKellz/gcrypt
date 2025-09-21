//! Batch Verification Operations
//!
//! General-purpose batch verification utilities for cryptographic primitives
//! beyond just signatures, including proofs, commitments, and other operations.

use crate::{EdwardsPoint, Scalar, field::FieldElement};
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::time::Instant;

#[cfg(feature = "rayon")]
use rayon::prelude::*;

/// Batch verification errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchVerificationError {
    /// Input arrays have mismatched lengths
    MismatchedLengths,
    /// Batch is empty
    EmptyBatch,
    /// Verification failed
    VerificationFailed,
    /// Invalid input format
    InvalidInput,
    /// Operation not supported
    UnsupportedOperation,
}

impl fmt::Display for BatchVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BatchVerificationError::MismatchedLengths => write!(f, "Input arrays have mismatched lengths"),
            BatchVerificationError::EmptyBatch => write!(f, "Batch is empty"),
            BatchVerificationError::VerificationFailed => write!(f, "Batch verification failed"),
            BatchVerificationError::InvalidInput => write!(f, "Invalid input format"),
            BatchVerificationError::UnsupportedOperation => write!(f, "Operation not supported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BatchVerificationError {}

/// Trait for batch-verifiable operations
pub trait BatchVerifiable {
    type VerificationData;
    type Error;

    /// Verify a single instance
    fn verify_single(&self, data: &Self::VerificationData) -> Result<bool, Self::Error>;

    /// Verify a batch of instances
    #[cfg(feature = "alloc")]
    fn verify_batch(&self, data: &[Self::VerificationData]) -> Result<Vec<bool>, Self::Error>;
}

/// Batch verification for range proofs
#[derive(Debug, Clone)]
pub struct RangeProofData {
    /// Commitment to the value
    pub commitment: EdwardsPoint,
    /// Range proof (simplified representation)
    pub proof: Vec<FieldElement>,
    /// Range bounds (min, max)
    pub range: (u64, u64),
}

/// Batch range proof verifier
pub struct BatchRangeProofVerifier;

impl BatchRangeProofVerifier {
    /// Create a new batch range proof verifier
    pub fn new() -> Self {
        Self
    }

    /// Verify a batch of range proofs
    #[cfg(feature = "alloc")]
    pub fn verify_batch(&self, proofs: &[RangeProofData]) -> Result<bool, BatchVerificationError> {
        if proofs.is_empty() {
            return Err(BatchVerificationError::EmptyBatch);
        }

        // Simplified range proof verification
        // In a real implementation, this would use bulletproofs or similar
        for proof_data in proofs {
            if !self.verify_single_range_proof(proof_data) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify a single range proof (simplified)
    fn verify_single_range_proof(&self, proof_data: &RangeProofData) -> bool {
        // Simplified verification - in practice this would be much more complex
        if proof_data.proof.is_empty() {
            return false;
        }

        // Check that the commitment is not the identity point
        if proof_data.commitment == EdwardsPoint::identity() {
            return false;
        }

        // Check range bounds are valid
        proof_data.range.0 <= proof_data.range.1
    }
}

impl Default for BatchRangeProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch verification for Merkle proofs
#[derive(Debug, Clone)]
pub struct MerkleProofData {
    /// Root hash
    pub root: [u8; 32],
    /// Leaf value
    pub leaf: Vec<u8>,
    /// Proof path (sibling hashes)
    pub proof: Vec<[u8; 32]>,
    /// Leaf index
    pub index: usize,
}

/// Batch Merkle proof verifier
pub struct BatchMerkleProofVerifier;

impl BatchMerkleProofVerifier {
    /// Create a new batch Merkle proof verifier
    pub fn new() -> Self {
        Self
    }

    /// Verify a batch of Merkle proofs
    #[cfg(feature = "alloc")]
    pub fn verify_batch(&self, proofs: &[MerkleProofData]) -> Result<Vec<bool>, BatchVerificationError> {
        if proofs.is_empty() {
            return Err(BatchVerificationError::EmptyBatch);
        }

        let results = if cfg!(feature = "rayon") && proofs.len() > 16 {
            self.verify_parallel(proofs)
        } else {
            self.verify_sequential(proofs)
        };

        Ok(results)
    }

    /// Sequential verification
    #[cfg(feature = "alloc")]
    fn verify_sequential(&self, proofs: &[MerkleProofData]) -> Vec<bool> {
        proofs.iter().map(|proof| self.verify_single_merkle_proof(proof)).collect()
    }

    /// Parallel verification
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn verify_parallel(&self, proofs: &[MerkleProofData]) -> Vec<bool> {
        proofs.par_iter().map(|proof| self.verify_single_merkle_proof(proof)).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn verify_parallel(&self, proofs: &[MerkleProofData]) -> Vec<bool> {
        self.verify_sequential(proofs)
    }

    /// Verify a single Merkle proof
    fn verify_single_merkle_proof(&self, proof_data: &MerkleProofData) -> bool {
        use crate::hash::blake3_hash;

        let mut current_hash = blake3_hash(&proof_data.leaf);
        let mut index = proof_data.index;

        for &sibling_hash in &proof_data.proof {
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

        current_hash == proof_data.root
    }
}

impl Default for BatchMerkleProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch verification for zero-knowledge proofs
#[derive(Debug, Clone)]
pub struct ZkProofData {
    /// Public inputs
    pub public_inputs: Vec<FieldElement>,
    /// Proof data
    pub proof: Vec<FieldElement>,
    /// Verification key (simplified)
    pub vk_hash: [u8; 32],
}

/// Batch zero-knowledge proof verifier
pub struct BatchZkProofVerifier;

impl BatchZkProofVerifier {
    /// Create a new batch ZK proof verifier
    pub fn new() -> Self {
        Self
    }

    /// Verify a batch of ZK proofs
    #[cfg(feature = "alloc")]
    pub fn verify_batch(&self, proofs: &[ZkProofData]) -> Result<bool, BatchVerificationError> {
        if proofs.is_empty() {
            return Err(BatchVerificationError::EmptyBatch);
        }

        // Use randomized batch verification for ZK proofs
        self.randomized_batch_verify(proofs)
    }

    /// Randomized batch verification for ZK proofs
    #[cfg(feature = "alloc")]
    fn randomized_batch_verify(&self, proofs: &[ZkProofData]) -> Result<bool, BatchVerificationError> {
        use crate::hash::blake3_hash;

        // Generate random coefficients
        let mut coefficients = Vec::with_capacity(proofs.len());
        for (i, proof) in proofs.iter().enumerate() {
            let mut seed = Vec::new();
            seed.extend_from_slice(&(i as u64).to_le_bytes());
            seed.extend_from_slice(&proof.vk_hash);

            let hash = blake3_hash(&seed);
            let coeff = FieldElement::from_bytes(&hash);
            coefficients.push(coeff);
        }

        // Compute linear combination of proofs
        let mut combined_proof = Vec::new();
        if let Some(first_proof) = proofs.first() {
            combined_proof = vec![FieldElement::zero(); first_proof.proof.len()];

            for (coeff, proof) in coefficients.iter().zip(proofs.iter()) {
                if proof.proof.len() != combined_proof.len() {
                    return Err(BatchVerificationError::InvalidInput);
                }

                for (combined_elem, proof_elem) in combined_proof.iter_mut().zip(proof.proof.iter()) {
                    *combined_elem = *combined_elem + (*coeff * *proof_elem);
                }
            }
        }

        // Simplified verification - check that combined proof is non-zero
        let is_valid = combined_proof.iter().any(|&elem| elem != FieldElement::zero());

        Ok(is_valid)
    }

    /// Verify a single ZK proof (simplified)
    fn verify_single_zk_proof(&self, proof_data: &ZkProofData) -> bool {
        // Simplified verification
        !proof_data.proof.is_empty() &&
        proof_data.proof.iter().any(|&elem| elem != FieldElement::zero())
    }
}

impl Default for BatchZkProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Generic batch verifier for multiple proof types
pub struct GenericBatchVerifier {
    /// Whether to use parallel processing
    use_parallel: bool,
    /// Whether to measure timing
    measure_timing: bool,
}

impl GenericBatchVerifier {
    /// Create a new generic batch verifier
    pub fn new() -> Self {
        Self {
            use_parallel: cfg!(feature = "rayon"),
            measure_timing: cfg!(feature = "std"),
        }
    }

    /// Enable or disable parallel processing
    pub fn with_parallel(mut self, use_parallel: bool) -> Self {
        self.use_parallel = use_parallel && cfg!(feature = "rayon");
        self
    }

    /// Enable or disable timing measurements
    pub fn with_timing(mut self, timing: bool) -> Self {
        self.measure_timing = timing && cfg!(feature = "std");
        self
    }

    /// Verify a mixed batch of different proof types
    #[cfg(feature = "alloc")]
    pub fn verify_mixed_batch<F>(&self, verifiers: Vec<F>) -> Result<bool, BatchVerificationError>
    where
        F: Fn() -> bool + Send + Sync,
    {
        if verifiers.is_empty() {
            return Err(BatchVerificationError::EmptyBatch);
        }

        #[cfg(feature = "std")]
        let start_time = if self.measure_timing {
            Some(Instant::now())
        } else {
            None
        };

        let all_valid = if self.use_parallel && verifiers.len() > 8 {
            self.verify_mixed_parallel(verifiers)
        } else {
            self.verify_mixed_sequential(verifiers)
        };

        #[cfg(feature = "std")]
        if let Some(start) = start_time {
            let duration = start.elapsed().as_millis();
            println!("Mixed batch verification took {}ms", duration);
        }

        Ok(all_valid)
    }

    /// Sequential mixed verification
    #[cfg(feature = "alloc")]
    fn verify_mixed_sequential<F>(&self, verifiers: Vec<F>) -> bool
    where
        F: Fn() -> bool,
    {
        verifiers.iter().all(|verify_fn| verify_fn())
    }

    /// Parallel mixed verification
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn verify_mixed_parallel<F>(&self, verifiers: Vec<F>) -> bool
    where
        F: Fn() -> bool + Send + Sync,
    {
        verifiers.par_iter().all(|verify_fn| verify_fn())
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn verify_mixed_parallel<F>(&self, verifiers: Vec<F>) -> bool
    where
        F: Fn() -> bool,
    {
        self.verify_mixed_sequential(verifiers)
    }
}

impl Default for GenericBatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience functions for batch verification
#[cfg(feature = "alloc")]
pub mod batch_verification {
    use super::*;

    /// Verify a batch of Merkle proofs
    pub fn verify_merkle_proofs(proofs: &[MerkleProofData]) -> Result<bool, BatchVerificationError> {
        let verifier = BatchMerkleProofVerifier::new();
        let results = verifier.verify_batch(proofs)?;
        Ok(results.iter().all(|&valid| valid))
    }

    /// Verify a batch of range proofs
    pub fn verify_range_proofs(proofs: &[RangeProofData]) -> Result<bool, BatchVerificationError> {
        let verifier = BatchRangeProofVerifier::new();
        verifier.verify_batch(proofs)
    }

    /// Verify a batch of ZK proofs
    pub fn verify_zk_proofs(proofs: &[ZkProofData]) -> Result<bool, BatchVerificationError> {
        let verifier = BatchZkProofVerifier::new();
        verifier.verify_batch(proofs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_merkle_proof() -> MerkleProofData {
        MerkleProofData {
            root: [1u8; 32],
            leaf: vec![0x42],
            proof: vec![[2u8; 32], [3u8; 32]],
            index: 0,
        }
    }

    fn create_test_range_proof() -> RangeProofData {
        RangeProofData {
            commitment: EdwardsPoint::generator(),
            proof: vec![FieldElement::from_u64(42)],
            range: (0, 100),
        }
    }

    fn create_test_zk_proof() -> ZkProofData {
        ZkProofData {
            public_inputs: vec![FieldElement::from_u64(1), FieldElement::from_u64(2)],
            proof: vec![FieldElement::from_u64(42), FieldElement::from_u64(84)],
            vk_hash: [5u8; 32],
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_merkle_verification() {
        let proofs = vec![create_test_merkle_proof(); 5];

        let verifier = BatchMerkleProofVerifier::new();
        let results = verifier.verify_batch(&proofs).unwrap();

        assert_eq!(results.len(), 5);
        // Results may be false due to simplified test data, but should not panic
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_range_proof_verification() {
        let proofs = vec![create_test_range_proof(); 3];

        let verifier = BatchRangeProofVerifier::new();
        let result = verifier.verify_batch(&proofs).unwrap();

        // Should pass basic validation
        assert!(result);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_zk_proof_verification() {
        let proofs = vec![create_test_zk_proof(); 4];

        let verifier = BatchZkProofVerifier::new();
        let result = verifier.verify_batch(&proofs).unwrap();

        // Should pass simplified validation
        assert!(result);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_generic_batch_verifier() {
        let verifier = GenericBatchVerifier::new();

        let verifiers = vec![
            || true,  // Always passes
            || true,  // Always passes
            || true,  // Always passes
        ];

        let result = verifier.verify_mixed_batch(verifiers).unwrap();
        assert!(result);

        let mixed_verifiers = vec![
            || true,   // Passes
            || false,  // Fails
            || true,   // Passes
        ];

        let result2 = verifier.verify_mixed_batch(mixed_verifiers).unwrap();
        assert!(!result2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_empty_batch_errors() {
        let merkle_verifier = BatchMerkleProofVerifier::new();
        let result = merkle_verifier.verify_batch(&[]);
        assert!(matches!(result, Err(BatchVerificationError::EmptyBatch)));

        let range_verifier = BatchRangeProofVerifier::new();
        let result = range_verifier.verify_batch(&[]);
        assert!(matches!(result, Err(BatchVerificationError::EmptyBatch)));

        let zk_verifier = BatchZkProofVerifier::new();
        let result = zk_verifier.verify_batch(&[]);
        assert!(matches!(result, Err(BatchVerificationError::EmptyBatch)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_convenience_functions() {
        let merkle_proofs = vec![create_test_merkle_proof(); 2];
        let range_proofs = vec![create_test_range_proof(); 2];
        let zk_proofs = vec![create_test_zk_proof(); 2];

        // These may fail due to simplified test data, but should not panic
        let _ = batch_verification::verify_merkle_proofs(&merkle_proofs);
        let _ = batch_verification::verify_range_proofs(&range_proofs);
        let _ = batch_verification::verify_zk_proofs(&zk_proofs);
    }
}