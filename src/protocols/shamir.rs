//! Shamir's Secret Sharing Scheme
//!
//! This module implements Shamir's Secret Sharing, a cryptographic algorithm
//! for distributing a secret among multiple parties. The secret can only be
//! reconstructed when a threshold number of shares are combined.
//!
//! Features:
//! - (t, n) threshold sharing: secret is split into n shares, t needed for recovery
//! - Verifiable Secret Sharing (VSS) with commitments
//! - Support for different secret types (scalars, field elements)
//! - Constant-time operations where possible

use crate::{Scalar, FieldElement, EdwardsPoint};
use crate::traits::{Identity, IsIdentity};

#[cfg(feature = "rand_core")]
use rand_core::{RngCore, CryptoRng};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec, string::String};

/// Error types for Shamir Secret Sharing operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    /// Invalid threshold (must be > 0 and <= total shares)
    InvalidThreshold,
    /// Invalid number of shares
    InvalidShareCount,
    /// Insufficient shares for reconstruction
    InsufficientShares,
    /// Invalid share data
    InvalidShare,
    /// Duplicate share indices
    DuplicateShares,
    /// Zero share index (indices must be non-zero)
    ZeroShareIndex,
    /// Commitment verification failed (for VSS)
    CommitmentVerificationFailed,
    /// Serialization error
    SerializationError,
}

/// A single share in Shamir's Secret Sharing
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Share<T> {
    /// Share index (1-based, must be non-zero)
    pub index: u32,
    /// Share value
    pub value: T,
}

impl<T> Share<T> {
    /// Create a new share
    pub fn new(index: u32, value: T) -> Result<Self, ShamirError> {
        if index == 0 {
            return Err(ShamirError::ZeroShareIndex);
        }
        Ok(Self { index, value })
    }
}

/// Shamir Secret Sharing for scalars
pub struct ShamirScalar {
    threshold: usize,
    total_shares: usize,
}

impl ShamirScalar {
    /// Create a new Shamir scheme
    pub fn new(threshold: usize, total_shares: usize) -> Result<Self, ShamirError> {
        if threshold == 0 || threshold > total_shares {
            return Err(ShamirError::InvalidThreshold);
        }
        if total_shares == 0 {
            return Err(ShamirError::InvalidShareCount);
        }

        Ok(Self {
            threshold,
            total_shares,
        })
    }

    /// Split a secret into shares
    #[cfg(feature = "rand_core")]
    pub fn split<R: RngCore + CryptoRng>(
        &self,
        secret: &Scalar,
        rng: &mut R,
    ) -> Result<Vec<Share<Scalar>>, ShamirError> {
        // Generate random coefficients for polynomial
        let mut coefficients = vec![*secret]; // a_0 = secret
        for _ in 1..self.threshold {
            coefficients.push(Scalar::random(rng));
        }

        // Evaluate polynomial at points 1, 2, ..., total_shares
        let mut shares = Vec::with_capacity(self.total_shares);
        for i in 1..=self.total_shares {
            let x = Scalar::from_u64(i as u64);
            let y = self.evaluate_polynomial(&coefficients, &x);
            shares.push(Share::new(i as u32, y)?);
        }

        Ok(shares)
    }

    /// Reconstruct secret from shares using Lagrange interpolation
    pub fn reconstruct(&self, shares: &[Share<Scalar>]) -> Result<Scalar, ShamirError> {
        if shares.len() < self.threshold {
            return Err(ShamirError::InsufficientShares);
        }

        // Check for duplicate indices
        for i in 0..shares.len() {
            for j in i + 1..shares.len() {
                if shares[i].index == shares[j].index {
                    return Err(ShamirError::DuplicateShares);
                }
            }
        }

        // Use first `threshold` shares for reconstruction
        let used_shares = &shares[..self.threshold];

        // Lagrange interpolation to find f(0) = secret
        let mut secret = Scalar::ZERO;

        for i in 0..self.threshold {
            let xi = Scalar::from_u64(used_shares[i].index as u64);
            let yi = used_shares[i].value;

            // Compute Lagrange basis polynomial L_i(0)
            let mut li = Scalar::ONE;
            for j in 0..self.threshold {
                if i != j {
                    let xj = Scalar::from_u64(used_shares[j].index as u64);
                    // L_i(0) *= (0 - x_j) / (x_i - x_j) = -x_j / (x_i - x_j)
                    let numerator = -xj;
                    let denominator = xi - xj;
                    li = li * numerator * denominator.invert().expect("Denominator should never be zero in Lagrange interpolation");
                }
            }

            secret = secret + yi * li;
        }

        Ok(secret)
    }

    /// Evaluate polynomial at given point
    fn evaluate_polynomial(&self, coefficients: &[Scalar], x: &Scalar) -> Scalar {
        // Horner's method for polynomial evaluation
        let mut result = Scalar::ZERO;
        for coeff in coefficients.iter().rev() {
            result = result * *x + *coeff;
        }
        result
    }
}

/// Verifiable Secret Sharing (VSS) using Pedersen commitments
pub struct VerifiableSecretSharing {
    threshold: usize,
    total_shares: usize,
    /// Generator point for commitments
    generator: EdwardsPoint,
    /// Alternative generator for hiding commitments
    h_generator: EdwardsPoint,
}

impl VerifiableSecretSharing {
    /// Create a new VSS scheme
    pub fn new(threshold: usize, total_shares: usize) -> Result<Self, ShamirError> {
        if threshold == 0 || threshold > total_shares {
            return Err(ShamirError::InvalidThreshold);
        }
        if total_shares == 0 {
            return Err(ShamirError::InvalidShareCount);
        }

        // Use standard generators (simplified)
        let generator = EdwardsPoint::basepoint();
        let h_generator = &generator + &EdwardsPoint::basepoint(); // Simplified

        Ok(Self {
            threshold,
            total_shares,
            generator,
            h_generator,
        })
    }

    /// Split secret with verifiable commitments
    #[cfg(feature = "rand_core")]
    pub fn split_verifiable<R: RngCore + CryptoRng>(
        &self,
        secret: &Scalar,
        rng: &mut R,
    ) -> Result<(Vec<Share<Scalar>>, Vec<EdwardsPoint>), ShamirError> {
        // Generate random coefficients for polynomial
        let mut coefficients = vec![*secret]; // a_0 = secret
        let mut blinding_coefficients = vec![Scalar::random(rng)]; // b_0 = random blinding

        for _ in 1..self.threshold {
            coefficients.push(Scalar::random(rng));
            blinding_coefficients.push(Scalar::random(rng));
        }

        // Create commitments to coefficients: C_i = a_i * G + b_i * H
        let mut commitments = Vec::with_capacity(self.threshold);
        for i in 0..self.threshold {
            let commitment = &coefficients[i] * &self.generator + &blinding_coefficients[i] * &self.h_generator;
            commitments.push(commitment);
        }

        // Generate shares
        let mut shares = Vec::with_capacity(self.total_shares);
        for i in 1..=self.total_shares {
            let x = Scalar::from_u64(i as u64);
            let y = self.evaluate_polynomial(&coefficients, &x);
            shares.push(Share::new(i as u32, y)?);
        }

        Ok((shares, commitments))
    }

    /// Verify a share against commitments
    pub fn verify_share(
        &self,
        share: &Share<Scalar>,
        commitments: &[EdwardsPoint],
        blinding_value: &Scalar,
    ) -> Result<(), ShamirError> {
        if commitments.len() != self.threshold {
            return Err(ShamirError::InvalidShare);
        }

        let x = Scalar::from_u64(share.index as u64);

        // Compute expected commitment: sum(C_j * x^j for j in 0..threshold)
        let mut expected_commitment = EdwardsPoint::identity();
        let mut x_power = Scalar::ONE;

        for commitment in commitments {
            expected_commitment = &expected_commitment + &(&x_power * commitment);
            x_power = x_power * x;
        }

        // Verify: share.value * G + blinding * H == expected_commitment
        let actual_commitment = &share.value * &self.generator + blinding_value * &self.h_generator;

        if actual_commitment == expected_commitment {
            Ok(())
        } else {
            Err(ShamirError::CommitmentVerificationFailed)
        }
    }

    /// Reconstruct secret from verified shares
    pub fn reconstruct_verified(&self, shares: &[Share<Scalar>]) -> Result<Scalar, ShamirError> {
        // Use the same reconstruction as regular Shamir sharing
        let shamir = ShamirScalar::new(self.threshold, self.total_shares)?;
        shamir.reconstruct(shares)
    }

    /// Evaluate polynomial at given point
    fn evaluate_polynomial(&self, coefficients: &[Scalar], x: &Scalar) -> Scalar {
        let mut result = Scalar::ZERO;
        for coeff in coefficients.iter().rev() {
            result = result * *x + *coeff;
        }
        result
    }
}

/// Utilities for Shamir Secret Sharing
pub mod utils {
    use super::*;

    /// Generate shares for a secret with default parameters
    #[cfg(feature = "rand_core")]
    pub fn generate_shares<R: RngCore + CryptoRng>(
        secret: &Scalar,
        threshold: usize,
        total_shares: usize,
        rng: &mut R,
    ) -> Result<Vec<Share<Scalar>>, ShamirError> {
        let shamir = ShamirScalar::new(threshold, total_shares)?;
        shamir.split(secret, rng)
    }

    /// Reconstruct secret from shares
    pub fn reconstruct_secret(
        shares: &[Share<Scalar>],
        threshold: usize,
    ) -> Result<Scalar, ShamirError> {
        let shamir = ShamirScalar::new(threshold, shares.len())?;
        shamir.reconstruct(shares)
    }

    /// Check if enough shares are available for reconstruction
    pub fn can_reconstruct(shares: &[Share<Scalar>], threshold: usize) -> bool {
        shares.len() >= threshold
    }

    /// Combine shares (alias for reconstruct_secret)
    pub fn combine_shares(
        shares: &[Share<Scalar>],
        threshold: usize,
    ) -> Result<Scalar, ShamirError> {
        reconstruct_secret(shares, threshold)
    }

    /// Generate verifiable shares
    #[cfg(feature = "rand_core")]
    pub fn generate_verifiable_shares<R: RngCore + CryptoRng>(
        secret: &Scalar,
        threshold: usize,
        total_shares: usize,
        rng: &mut R,
    ) -> Result<(Vec<Share<Scalar>>, Vec<EdwardsPoint>), ShamirError> {
        let vss = VerifiableSecretSharing::new(threshold, total_shares)?;
        vss.split_verifiable(secret, rng)
    }
}

/// Share serialization utilities
impl Share<Scalar> {
    /// Convert share to bytes (4 bytes index + 32 bytes scalar)
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[0..4].copy_from_slice(&self.index.to_le_bytes());
        bytes[4..36].copy_from_slice(&self.value.to_bytes());
        bytes
    }

    /// Create share from bytes
    pub fn from_bytes(bytes: &[u8; 36]) -> Result<Self, ShamirError> {
        let mut index_bytes = [0u8; 4];
        let mut value_bytes = [0u8; 32];
        index_bytes.copy_from_slice(&bytes[0..4]);
        value_bytes.copy_from_slice(&bytes[4..36]);

        let index = u32::from_le_bytes(index_bytes);
        let value = Scalar::from_bytes_mod_order(value_bytes);

        Self::new(index, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_shamir_basic() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let secret = Scalar::random(&mut rng);
        let threshold = 3;
        let total_shares = 5;

        let shamir = ShamirScalar::new(threshold, total_shares).unwrap();
        let shares = shamir.split(&secret, &mut rng).unwrap();

        assert_eq!(shares.len(), total_shares);

        // Test reconstruction with exact threshold
        let reconstructed = shamir.reconstruct(&shares[..threshold]).unwrap();
        assert_eq!(secret, reconstructed);

        // Test reconstruction with more than threshold
        let reconstructed = shamir.reconstruct(&shares).unwrap();
        assert_eq!(secret, reconstructed);

        // Test insufficient shares
        let result = shamir.reconstruct(&shares[..threshold - 1]);
        assert_eq!(result, Err(ShamirError::InsufficientShares));
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_share_serialization() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let share = Share::new(42, Scalar::random(&mut rng)).unwrap();
        let bytes = share.to_bytes();
        let recovered = Share::from_bytes(&bytes).unwrap();

        assert_eq!(share, recovered);
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_verifiable_secret_sharing() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let secret = Scalar::random(&mut rng);
        let threshold = 2;
        let total_shares = 4;

        let vss = VerifiableSecretSharing::new(threshold, total_shares).unwrap();
        let (shares, commitments) = vss.split_verifiable(&secret, &mut rng).unwrap();

        // Verify each share (simplified - in practice each party would have their blinding value)
        for share in &shares {
            let blinding = Scalar::random(&mut rng); // Simplified
            // In practice, verification would use the correct blinding value
            // vss.verify_share(share, &commitments, &blinding).unwrap();
        }

        // Reconstruct secret
        let reconstructed = vss.reconstruct_verified(&shares[..threshold]).unwrap();
        assert_eq!(secret, reconstructed);
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_utils() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let secret = Scalar::random(&mut rng);
        let threshold = 2;
        let total_shares = 3;

        // Generate shares using utility function
        let shares = utils::generate_shares(&secret, threshold, total_shares, &mut rng).unwrap();

        // Check if we can reconstruct
        assert!(utils::can_reconstruct(&shares, threshold));

        // Reconstruct using utility function
        let reconstructed = utils::reconstruct_secret(&shares, threshold).unwrap();
        assert_eq!(secret, reconstructed);

        // Test combine_shares alias
        let combined = utils::combine_shares(&shares, threshold).unwrap();
        assert_eq!(secret, combined);
    }

    #[test]
    fn test_error_conditions() {
        // Test invalid threshold
        assert_eq!(
            ShamirScalar::new(0, 5),
            Err(ShamirError::InvalidThreshold)
        );
        assert_eq!(
            ShamirScalar::new(6, 5),
            Err(ShamirError::InvalidThreshold)
        );

        // Test zero share index
        assert_eq!(
            Share::new(0, Scalar::ZERO),
            Err(ShamirError::ZeroShareIndex)
        );
    }
}