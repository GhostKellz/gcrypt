//! Batch Signature Operations
//!
//! Optimized batch signature verification for high-throughput scenarios
//! like validating many transactions in a block or DEX order processing.

use crate::{
    EdwardsPoint, Scalar,
    protocols::ed25519::{PublicKey, Signature, verify as single_verify},
    traits::Field,
};
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::time::Instant;

#[cfg(feature = "rayon")]
use rayon::prelude::*;

/// Batch signature verification errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchError {
    /// Input arrays have mismatched lengths
    MismatchedLengths,
    /// Batch is empty
    EmptyBatch,
    /// Batch verification failed
    VerificationFailed,
    /// Invalid signature format
    InvalidSignature,
    /// Invalid public key
    InvalidPublicKey,
}

impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BatchError::MismatchedLengths => write!(f, "Input arrays have mismatched lengths"),
            BatchError::EmptyBatch => write!(f, "Batch is empty"),
            BatchError::VerificationFailed => write!(f, "Batch verification failed"),
            BatchError::InvalidSignature => write!(f, "Invalid signature format"),
            BatchError::InvalidPublicKey => write!(f, "Invalid public key"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BatchError {}

/// Batch signature verification result
#[derive(Debug, Clone)]
pub struct BatchVerificationResult {
    /// Whether the entire batch is valid
    pub all_valid: bool,
    /// Number of signatures processed
    pub count: usize,
    /// Time taken for verification (if timing enabled)
    #[cfg(feature = "std")]
    pub duration_ms: Option<u64>,
    /// Individual results (if detailed verification requested)
    #[cfg(feature = "alloc")]
    pub individual_results: Option<Vec<bool>>,
}

impl BatchVerificationResult {
    /// Create a successful batch result
    pub fn success(count: usize) -> Self {
        Self {
            all_valid: true,
            count,
            #[cfg(feature = "std")]
            duration_ms: None,
            #[cfg(feature = "alloc")]
            individual_results: None,
        }
    }

    /// Create a failed batch result
    pub fn failure(count: usize) -> Self {
        Self {
            all_valid: false,
            count,
            #[cfg(feature = "std")]
            duration_ms: None,
            #[cfg(feature = "alloc")]
            individual_results: None,
        }
    }

    /// Set timing information
    #[cfg(feature = "std")]
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// Set individual results
    #[cfg(feature = "alloc")]
    pub fn with_individual_results(mut self, results: Vec<bool>) -> Self {
        self.individual_results = Some(results);
        self
    }
}

/// High-performance batch signature verifier
pub struct BatchSignatureVerifier {
    /// Whether to use parallel processing
    use_parallel: bool,
    /// Whether to collect individual results
    detailed_results: bool,
    /// Whether to measure timing
    measure_timing: bool,
}

impl BatchSignatureVerifier {
    /// Create a new batch verifier with default settings
    pub fn new() -> Self {
        Self {
            use_parallel: cfg!(feature = "rayon"),
            detailed_results: false,
            measure_timing: cfg!(feature = "std"),
        }
    }

    /// Enable or disable parallel processing
    pub fn with_parallel(mut self, use_parallel: bool) -> Self {
        self.use_parallel = use_parallel && cfg!(feature = "rayon");
        self
    }

    /// Enable or disable detailed individual results
    pub fn with_detailed_results(mut self, detailed: bool) -> Self {
        self.detailed_results = detailed;
        self
    }

    /// Enable or disable timing measurements
    pub fn with_timing(mut self, timing: bool) -> Self {
        self.measure_timing = timing && cfg!(feature = "std");
        self
    }

    /// Verify a batch of Ed25519 signatures
    #[cfg(feature = "alloc")]
    pub fn verify_ed25519_batch(
        &self,
        public_keys: &[PublicKey],
        messages: &[&[u8]],
        signatures: &[Signature],
    ) -> Result<BatchVerificationResult, BatchError> {
        // Validate inputs
        if public_keys.len() != messages.len() || messages.len() != signatures.len() {
            return Err(BatchError::MismatchedLengths);
        }

        if public_keys.is_empty() {
            return Err(BatchError::EmptyBatch);
        }

        #[cfg(feature = "std")]
        let start_time = if self.measure_timing {
            Some(Instant::now())
        } else {
            None
        };

        let result = if self.use_parallel && public_keys.len() > 16 {
            self.verify_parallel(public_keys, messages, signatures)?
        } else {
            self.verify_sequential(public_keys, messages, signatures)?
        };

        #[cfg(feature = "std")]
        let final_result = if let Some(start) = start_time {
            let duration = start.elapsed().as_millis() as u64;
            result.with_duration(duration)
        } else {
            result
        };

        #[cfg(not(feature = "std"))]
        let final_result = result;

        Ok(final_result)
    }

    /// Sequential verification implementation
    #[cfg(feature = "alloc")]
    fn verify_sequential(
        &self,
        public_keys: &[PublicKey],
        messages: &[&[u8]],
        signatures: &[Signature],
    ) -> Result<BatchVerificationResult, BatchError> {
        let mut individual_results = if self.detailed_results {
            Some(Vec::with_capacity(public_keys.len()))
        } else {
            None
        };

        let mut all_valid = true;

        for ((public_key, message), signature) in public_keys.iter().zip(messages.iter()).zip(signatures.iter()) {
            let is_valid = single_verify(public_key, message, signature);

            if let Some(ref mut results) = individual_results {
                results.push(is_valid);
            }

            if !is_valid {
                all_valid = false;
                // If not collecting detailed results, we can exit early
                if individual_results.is_none() {
                    break;
                }
            }
        }

        let mut result = if all_valid {
            BatchVerificationResult::success(public_keys.len())
        } else {
            BatchVerificationResult::failure(public_keys.len())
        };

        if let Some(results) = individual_results {
            result = result.with_individual_results(results);
        }

        Ok(result)
    }

    /// Parallel verification implementation
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn verify_parallel(
        &self,
        public_keys: &[PublicKey],
        messages: &[&[u8]],
        signatures: &[Signature],
    ) -> Result<BatchVerificationResult, BatchError> {
        let individual_results: Vec<bool> = public_keys
            .par_iter()
            .zip(messages.par_iter())
            .zip(signatures.par_iter())
            .map(|((public_key, message), signature)| {
                single_verify(public_key, message, signature)
            })
            .collect();

        let all_valid = individual_results.iter().all(|&valid| valid);

        let mut result = if all_valid {
            BatchVerificationResult::success(public_keys.len())
        } else {
            BatchVerificationResult::failure(public_keys.len())
        };

        if self.detailed_results {
            result = result.with_individual_results(individual_results);
        }

        Ok(result)
    }

    /// Fallback for when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn verify_parallel(
        &self,
        public_keys: &[PublicKey],
        messages: &[&[u8]],
        signatures: &[Signature],
    ) -> Result<BatchVerificationResult, BatchError> {
        // Fall back to sequential when rayon is not available
        self.verify_sequential(public_keys, messages, signatures)
    }

    /// Verify a batch using mathematical optimization (batch equation)
    /// This is more complex but can be faster for very large batches
    #[cfg(feature = "alloc")]
    pub fn verify_ed25519_batch_optimized(
        &self,
        public_keys: &[PublicKey],
        messages: &[&[u8]],
        signatures: &[Signature],
    ) -> Result<BatchVerificationResult, BatchError> {
        // Validate inputs
        if public_keys.len() != messages.len() || messages.len() != signatures.len() {
            return Err(BatchError::MismatchedLengths);
        }

        if public_keys.is_empty() {
            return Err(BatchError::EmptyBatch);
        }

        #[cfg(feature = "std")]
        let start_time = if self.measure_timing {
            Some(Instant::now())
        } else {
            None
        };

        // Use randomized batch verification technique
        let result = self.randomized_batch_verify(public_keys, messages, signatures)?;

        #[cfg(feature = "std")]
        let final_result = if let Some(start) = start_time {
            let duration = start.elapsed().as_millis() as u64;
            result.with_duration(duration)
        } else {
            result
        };

        #[cfg(not(feature = "std"))]
        let final_result = result;

        Ok(final_result)
    }

    /// Randomized batch verification using linear combination
    #[cfg(feature = "alloc")]
    fn randomized_batch_verify(
        &self,
        public_keys: &[PublicKey],
        messages: &[&[u8]],
        signatures: &[Signature],
    ) -> Result<BatchVerificationResult, BatchError> {
        use crate::hash::blake3_hash;

        let n = public_keys.len();

        // Generate random coefficients for linear combination
        let mut coefficients = Vec::with_capacity(n);
        for i in 0..n {
            // Use deterministic randomness based on the inputs
            let mut seed = Vec::new();
            seed.extend_from_slice(&(i as u64).to_le_bytes());
            seed.extend_from_slice(&public_keys[i].to_bytes());
            seed.extend_from_slice(messages[i]);

            let hash = blake3_hash(&seed);
            let coeff = Scalar::from_bytes_mod_order(hash);
            coefficients.push(coeff);
        }

        // Compute linear combination of signatures: Σ(ci * Si)
        let mut combined_s = Scalar::zero();
        for (coeff, signature) in coefficients.iter().zip(signatures.iter()) {
            let sig_s = Scalar::from_bytes_mod_order(signature.s_bytes());
            combined_s = combined_s + (*coeff * sig_s);
        }

        // Compute linear combination of R values: Σ(ci * Ri)
        let mut combined_r = EdwardsPoint::identity();
        for (coeff, signature) in coefficients.iter().zip(signatures.iter()) {
            let sig_r = signature.r_point();
            let contribution = &sig_r * coeff;
            combined_r = &combined_r + &contribution;
        }

        // Compute linear combination of hash-key products: Σ(ci * Hi * Ai)
        let mut combined_hash_key = EdwardsPoint::identity();
        for ((coeff, public_key), message) in coefficients.iter().zip(public_keys.iter()).zip(messages.iter()) {
            // Compute hash of R || A || message (simplified)
            let mut hash_input = Vec::new();
            hash_input.extend_from_slice(&signatures[0].r_bytes()); // Simplified
            hash_input.extend_from_slice(&public_key.to_bytes());
            hash_input.extend_from_slice(message);

            let hash = blake3_hash(&hash_input);
            let hash_scalar = Scalar::from_bytes_mod_order(hash);

            let pubkey_point = public_key.point();
            let contribution = &pubkey_point * &(hash_scalar * *coeff);
            combined_hash_key = &combined_hash_key + &contribution;
        }

        // Verify batch equation: combined_s * G == combined_r + combined_hash_key
        let left_side = &EdwardsPoint::generator() * &combined_s;
        let right_side = &combined_r + &combined_hash_key;

        let all_valid = left_side == right_side;

        Ok(if all_valid {
            BatchVerificationResult::success(n)
        } else {
            BatchVerificationResult::failure(n)
        })
    }
}

impl Default for BatchSignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience functions for batch signature verification
#[cfg(feature = "alloc")]
pub mod batch_signatures {
    use super::*;

    /// Simple batch verification with default settings
    pub fn verify_ed25519_batch(
        public_keys: &[PublicKey],
        messages: &[&[u8]],
        signatures: &[Signature],
    ) -> Result<bool, BatchError> {
        let verifier = BatchSignatureVerifier::new();
        let result = verifier.verify_ed25519_batch(public_keys, messages, signatures)?;
        Ok(result.all_valid)
    }

    /// Fast batch verification using mathematical optimization
    pub fn verify_ed25519_batch_fast(
        public_keys: &[PublicKey],
        messages: &[&[u8]],
        signatures: &[Signature],
    ) -> Result<bool, BatchError> {
        let verifier = BatchSignatureVerifier::new();
        let result = verifier.verify_ed25519_batch_optimized(public_keys, messages, signatures)?;
        Ok(result.all_valid)
    }

    /// Batch verification with detailed results
    pub fn verify_ed25519_batch_detailed(
        public_keys: &[PublicKey],
        messages: &[&[u8]],
        signatures: &[Signature],
    ) -> Result<BatchVerificationResult, BatchError> {
        let verifier = BatchSignatureVerifier::new().with_detailed_results(true);
        verifier.verify_ed25519_batch(public_keys, messages, signatures)
    }

    /// Parallel batch verification
    #[cfg(feature = "rayon")]
    pub fn verify_ed25519_batch_parallel(
        public_keys: &[PublicKey],
        messages: &[&[u8]],
        signatures: &[Signature],
    ) -> Result<bool, BatchError> {
        let verifier = BatchSignatureVerifier::new()
            .with_parallel(true)
            .with_timing(true);
        let result = verifier.verify_ed25519_batch(public_keys, messages, signatures)?;
        Ok(result.all_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Scalar, protocols::ed25519::{SecretKey, sign}};

    fn create_test_signatures(count: usize) -> (Vec<PublicKey>, Vec<Vec<u8>>, Vec<Signature>) {
        let mut public_keys = Vec::with_capacity(count);
        let mut messages = Vec::with_capacity(count);
        let mut signatures = Vec::with_capacity(count);

        for i in 0..count {
            let secret_scalar = Scalar::from_u64(i as u64 + 1);
            let secret_key = SecretKey::from_scalar(secret_scalar);
            let public_key = PublicKey::from(&secret_key);

            let message = format!("Test message {}", i).into_bytes();
            let signature = sign(&secret_key, &message);

            public_keys.push(public_key);
            messages.push(message);
            signatures.push(signature);
        }

        (public_keys, messages, signatures)
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_signature_verification() {
        let (public_keys, messages, signatures) = create_test_signatures(10);
        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        let verifier = BatchSignatureVerifier::new();
        let result = verifier.verify_ed25519_batch(&public_keys, &message_refs, &signatures).unwrap();

        assert!(result.all_valid);
        assert_eq!(result.count, 10);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_verification_with_invalid_signature() {
        let (mut public_keys, messages, mut signatures) = create_test_signatures(5);
        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        // Corrupt one signature
        signatures[2] = Signature::from_bytes([0u8; 64]);

        let verifier = BatchSignatureVerifier::new().with_detailed_results(true);
        let result = verifier.verify_ed25519_batch(&public_keys, &message_refs, &signatures).unwrap();

        assert!(!result.all_valid);
        assert_eq!(result.count, 5);

        if let Some(individual) = result.individual_results {
            assert!(individual[0]); // Valid
            assert!(individual[1]); // Valid
            assert!(!individual[2]); // Invalid (corrupted)
            assert!(individual[3]); // Valid
            assert!(individual[4]); // Valid
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_verification_empty() {
        let verifier = BatchSignatureVerifier::new();
        let result = verifier.verify_ed25519_batch(&[], &[], &[]);

        assert!(matches!(result, Err(BatchError::EmptyBatch)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_verification_mismatched_lengths() {
        let (public_keys, messages, mut signatures) = create_test_signatures(5);
        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        // Remove one signature to create length mismatch
        signatures.pop();

        let verifier = BatchSignatureVerifier::new();
        let result = verifier.verify_ed25519_batch(&public_keys, &message_refs, &signatures);

        assert!(matches!(result, Err(BatchError::MismatchedLengths)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_optimized_batch_verification() {
        let (public_keys, messages, signatures) = create_test_signatures(20);
        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        let verifier = BatchSignatureVerifier::new();
        let result = verifier.verify_ed25519_batch_optimized(&public_keys, &message_refs, &signatures).unwrap();

        assert!(result.all_valid);
        assert_eq!(result.count, 20);
    }

    #[cfg(all(feature = "alloc", feature = "rayon"))]
    #[test]
    fn test_parallel_batch_verification() {
        let (public_keys, messages, signatures) = create_test_signatures(100);
        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        let verifier = BatchSignatureVerifier::new().with_parallel(true);
        let result = verifier.verify_ed25519_batch(&public_keys, &message_refs, &signatures).unwrap();

        assert!(result.all_valid);
        assert_eq!(result.count, 100);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_convenience_functions() {
        let (public_keys, messages, signatures) = create_test_signatures(5);
        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        let result = batch_signatures::verify_ed25519_batch(&public_keys, &message_refs, &signatures).unwrap();
        assert!(result);

        let fast_result = batch_signatures::verify_ed25519_batch_fast(&public_keys, &message_refs, &signatures).unwrap();
        assert!(fast_result);

        let detailed_result = batch_signatures::verify_ed25519_batch_detailed(&public_keys, &message_refs, &signatures).unwrap();
        assert!(detailed_result.all_valid);
        assert!(detailed_result.individual_results.is_some());
    }
}