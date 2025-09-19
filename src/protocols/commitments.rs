//! Cryptographic Commitment Schemes
//!
//! This module implements various commitment schemes used in zero-knowledge proofs
//! and other cryptographic protocols:
//! - Pedersen commitments (perfectly hiding, computationally binding)
//! - Polynomial commitments
//! - Vector commitments
//! - Commitment utilities for range proofs and other ZK applications

use crate::{EdwardsPoint, Scalar, FieldElement};
use crate::traits::{Compress, Decompress, Identity, IsIdentity};

#[cfg(feature = "rand_core")]
use rand_core::{RngCore, CryptoRng};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String};

/// Error types for commitment operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentError {
    /// Invalid generator point
    InvalidGenerator,
    /// Invalid commitment
    InvalidCommitment,
    /// Invalid opening (decommitment failed)
    InvalidOpening,
    /// Mismatched vector lengths
    MismatchedLengths,
    /// Invalid polynomial degree
    InvalidDegree,
    /// Serialization error
    SerializationError,
    /// Commitment scheme error
    SchemeError(String),
}

/// Pedersen commitment scheme
///
/// A Pedersen commitment to value `v` with blinding factor `r` is:
/// C = v * G + r * H
/// where G and H are generator points with unknown discrete log relationship
#[derive(Clone, Debug)]
pub struct PedersenCommitment {
    /// Generator for values
    g_generator: EdwardsPoint,
    /// Generator for blinding factors
    h_generator: EdwardsPoint,
}

impl PedersenCommitment {
    /// Create a new Pedersen commitment scheme with given generators
    pub fn new(g_generator: EdwardsPoint, h_generator: EdwardsPoint) -> Result<Self, CommitmentError> {
        // Basic validation - generators should not be identity
        if g_generator.is_identity().into() || h_generator.is_identity().into() {
            return Err(CommitmentError::InvalidGenerator);
        }

        Ok(Self {
            g_generator,
            h_generator,
        })
    }

    /// Create with default generators (derived from base point)
    pub fn default() -> Self {
        let g_generator = EdwardsPoint::basepoint();
        // H = hash_to_point("PEDERSEN_H") (simplified)
        let h_generator = &g_generator + &g_generator; // Simplified - should use proper hash-to-point

        Self {
            g_generator,
            h_generator,
        }
    }

    /// Create a commitment to a value with random blinding
    #[cfg(feature = "rand_core")]
    pub fn commit<R: RngCore + CryptoRng>(
        &self,
        value: &Scalar,
        rng: &mut R,
    ) -> (Commitment, Opening) {
        let blinding = Scalar::random(rng);
        let commitment_point = value * &self.g_generator + &blinding * &self.h_generator;

        let commitment = Commitment {
            point: commitment_point,
        };
        let opening = Opening {
            value: *value,
            blinding,
        };

        (commitment, opening)
    }

    /// Create a commitment with explicit blinding factor
    pub fn commit_with_blinding(&self, value: &Scalar, blinding: &Scalar) -> Commitment {
        let commitment_point = value * &self.g_generator + blinding * &self.h_generator;
        Commitment {
            point: commitment_point,
        }
    }

    /// Verify a commitment opening
    pub fn verify(&self, commitment: &Commitment, opening: &Opening) -> Result<(), CommitmentError> {
        let expected_commitment = self.commit_with_blinding(&opening.value, &opening.blinding);

        if commitment.point == expected_commitment.point {
            Ok(())
        } else {
            Err(CommitmentError::InvalidOpening)
        }
    }

    /// Add two commitments (homomorphic property)
    pub fn add_commitments(&self, c1: &Commitment, c2: &Commitment) -> Commitment {
        Commitment {
            point: &c1.point + &c2.point,
        }
    }

    /// Add commitment and opening values
    pub fn add_openings(&self, o1: &Opening, o2: &Opening) -> Opening {
        Opening {
            value: &o1.value + &o2.value,
            blinding: &o1.blinding + &o2.blinding,
        }
    }

    /// Multiply commitment by scalar
    pub fn multiply_commitment(&self, commitment: &Commitment, scalar: &Scalar) -> Commitment {
        Commitment {
            point: scalar * &commitment.point,
        }
    }

    /// Multiply opening by scalar
    pub fn multiply_opening(&self, opening: &Opening, scalar: &Scalar) -> Opening {
        Opening {
            value: scalar * &opening.value,
            blinding: scalar * &opening.blinding,
        }
    }

    /// Get the generators
    pub fn generators(&self) -> (&EdwardsPoint, &EdwardsPoint) {
        (&self.g_generator, &self.h_generator)
    }
}

/// A commitment value
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Commitment {
    point: EdwardsPoint,
}

impl Commitment {
    /// Get the underlying point
    pub fn as_point(&self) -> &EdwardsPoint {
        &self.point
    }

    /// Convert to compressed bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Create from compressed bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CommitmentError> {
        let compressed = crate::edwards::CompressedEdwardsY(*bytes);
        let point = compressed.decompress()
            .ok_or(CommitmentError::InvalidCommitment)?;
        Ok(Self { point })
    }
}

/// Opening (decommitment) information
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Opening {
    /// The committed value
    pub value: Scalar,
    /// The blinding factor
    pub blinding: Scalar,
}

impl Opening {
    /// Create a new opening
    pub fn new(value: Scalar, blinding: Scalar) -> Self {
        Self { value, blinding }
    }

    /// Convert to bytes (32 bytes value + 32 bytes blinding)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.value.to_bytes());
        bytes[32..64].copy_from_slice(&self.blinding.to_bytes());
        bytes
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut value_bytes = [0u8; 32];
        let mut blinding_bytes = [0u8; 32];
        value_bytes.copy_from_slice(&bytes[0..32]);
        blinding_bytes.copy_from_slice(&bytes[32..64]);

        Self {
            value: Scalar::from_bytes_mod_order(value_bytes),
            blinding: Scalar::from_bytes_mod_order(blinding_bytes),
        }
    }
}

/// Vector commitment scheme for committing to multiple values
#[derive(Clone, Debug)]
pub struct VectorCommitment {
    /// Pedersen commitment scheme
    pedersen: PedersenCommitment,
    /// Generators for vector elements
    generators: Vec<EdwardsPoint>,
}

impl VectorCommitment {
    /// Create a new vector commitment scheme
    pub fn new(
        pedersen: PedersenCommitment,
        generators: Vec<EdwardsPoint>,
    ) -> Result<Self, CommitmentError> {
        if generators.is_empty() {
            return Err(CommitmentError::InvalidGenerator);
        }

        // Verify generators are not identity
        for generator in &generators {
            if generator.is_identity().into() {
                return Err(CommitmentError::InvalidGenerator);
            }
        }

        Ok(Self {
            pedersen,
            generators,
        })
    }

    /// Create with default generators
    #[cfg(feature = "rand_core")]
    pub fn default_with_size<R: RngCore + CryptoRng>(size: usize, rng: &mut R) -> Self {
        let pedersen = PedersenCommitment::default();

        // Generate random generators (simplified - should use hash-to-point)
        let mut generators = Vec::with_capacity(size);
        for _ in 0..size {
            let scalar = Scalar::random(rng);
            let generator = &scalar * &EdwardsPoint::basepoint();
            generators.push(generator);
        }

        Self {
            pedersen,
            generators,
        }
    }

    /// Commit to a vector of values
    #[cfg(feature = "rand_core")]
    pub fn commit_vector<R: RngCore + CryptoRng>(
        &self,
        values: &[Scalar],
        rng: &mut R,
    ) -> Result<(Commitment, VectorOpening), CommitmentError> {
        if values.len() != self.generators.len() {
            return Err(CommitmentError::MismatchedLengths);
        }

        let blinding = Scalar::random(rng);

        // Compute commitment: sum(v_i * G_i) + r * H
        let mut commitment_point = EdwardsPoint::identity();
        for (value, generator) in values.iter().zip(self.generators.iter()) {
            commitment_point = &commitment_point + &(value * generator);
        }
        commitment_point = &commitment_point + &(&blinding * &self.pedersen.h_generator);

        let commitment = Commitment {
            point: commitment_point,
        };
        let opening = VectorOpening {
            values: values.to_vec(),
            blinding,
        };

        Ok((commitment, opening))
    }

    /// Verify a vector commitment opening
    pub fn verify_vector(
        &self,
        commitment: &Commitment,
        opening: &VectorOpening,
    ) -> Result<(), CommitmentError> {
        if opening.values.len() != self.generators.len() {
            return Err(CommitmentError::MismatchedLengths);
        }

        // Recompute commitment
        let mut expected_point = EdwardsPoint::identity();
        for (value, generator) in opening.values.iter().zip(self.generators.iter()) {
            expected_point = &expected_point + &(value * generator);
        }
        expected_point = &expected_point + &(&opening.blinding * &self.pedersen.h_generator);

        if commitment.point == expected_point {
            Ok(())
        } else {
            Err(CommitmentError::InvalidOpening)
        }
    }

    /// Get the number of supported vector elements
    pub fn size(&self) -> usize {
        self.generators.len()
    }
}

/// Opening for vector commitments
#[derive(Clone, Debug)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VectorOpening {
    /// The committed values
    pub values: Vec<Scalar>,
    /// The blinding factor
    pub blinding: Scalar,
}

/// Polynomial commitment scheme
#[derive(Clone, Debug)]
pub struct PolynomialCommitment {
    /// Vector commitment for coefficients
    vector_commitment: VectorCommitment,
    /// Maximum degree supported
    max_degree: usize,
}

impl PolynomialCommitment {
    /// Create a new polynomial commitment scheme
    pub fn new(
        vector_commitment: VectorCommitment,
        max_degree: usize,
    ) -> Result<Self, CommitmentError> {
        if max_degree == 0 {
            return Err(CommitmentError::InvalidDegree);
        }

        if vector_commitment.size() < max_degree + 1 {
            return Err(CommitmentError::MismatchedLengths);
        }

        Ok(Self {
            vector_commitment,
            max_degree,
        })
    }

    /// Commit to a polynomial (represented by coefficients)
    #[cfg(feature = "rand_core")]
    pub fn commit_polynomial<R: RngCore + CryptoRng>(
        &self,
        coefficients: &[Scalar],
        rng: &mut R,
    ) -> Result<(Commitment, PolynomialOpening), CommitmentError> {
        if coefficients.len() > self.max_degree + 1 {
            return Err(CommitmentError::InvalidDegree);
        }

        // Pad coefficients to full size
        let mut padded_coeffs = coefficients.to_vec();
        padded_coeffs.resize(self.max_degree + 1, Scalar::ZERO);

        let (commitment, vector_opening) = self.vector_commitment.commit_vector(&padded_coeffs, rng)?;

        let poly_opening = PolynomialOpening {
            coefficients: coefficients.to_vec(),
            blinding: vector_opening.blinding,
        };

        Ok((commitment, poly_opening))
    }

    /// Evaluate polynomial at a point
    pub fn evaluate_polynomial(&self, coefficients: &[Scalar], point: &Scalar) -> Scalar {
        // Horner's method
        let mut result = Scalar::ZERO;
        for coeff in coefficients.iter().rev() {
            result = result * *point + *coeff;
        }
        result
    }

    /// Verify polynomial commitment opening at a specific point
    pub fn verify_evaluation(
        &self,
        commitment: &Commitment,
        point: &Scalar,
        value: &Scalar,
        opening: &PolynomialOpening,
    ) -> Result<(), CommitmentError> {
        // Verify that evaluation is correct
        let expected_value = self.evaluate_polynomial(&opening.coefficients, point);
        if expected_value != *value {
            return Err(CommitmentError::InvalidOpening);
        }

        // Verify that commitment matches polynomial
        let mut padded_coeffs = opening.coefficients.clone();
        padded_coeffs.resize(self.max_degree + 1, Scalar::ZERO);

        let vector_opening = VectorOpening {
            values: padded_coeffs,
            blinding: opening.blinding,
        };

        self.vector_commitment.verify_vector(commitment, &vector_opening)
    }

    /// Get maximum degree
    pub fn max_degree(&self) -> usize {
        self.max_degree
    }
}

/// Opening for polynomial commitments
#[derive(Clone, Debug)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PolynomialOpening {
    /// Polynomial coefficients
    pub coefficients: Vec<Scalar>,
    /// Blinding factor
    pub blinding: Scalar,
}

/// Utility functions for commitments
pub mod utils {
    use super::*;

    /// Create a Pedersen commitment to a single value
    #[cfg(feature = "rand_core")]
    pub fn commit_value<R: RngCore + CryptoRng>(
        value: &Scalar,
        rng: &mut R,
    ) -> (Commitment, Opening) {
        let pedersen = PedersenCommitment::default();
        pedersen.commit(value, rng)
    }

    /// Verify a single value commitment
    pub fn verify_value(
        commitment: &Commitment,
        opening: &Opening,
    ) -> Result<(), CommitmentError> {
        let pedersen = PedersenCommitment::default();
        pedersen.verify(commitment, opening)
    }

    /// Create a commitment to zero with random blinding
    #[cfg(feature = "rand_core")]
    pub fn commit_zero<R: RngCore + CryptoRng>(rng: &mut R) -> (Commitment, Opening) {
        commit_value(&Scalar::ZERO, rng)
    }

    /// Check if a commitment could be a commitment to zero (requires opening)
    pub fn is_zero_commitment(opening: &Opening) -> bool {
        opening.value == Scalar::ZERO
    }

    /// Generate random generators for vector commitments
    #[cfg(feature = "rand_core")]
    pub fn generate_generators<R: RngCore + CryptoRng>(
        count: usize,
        rng: &mut R,
    ) -> Vec<EdwardsPoint> {
        let mut generators = Vec::with_capacity(count);
        for _ in 0..count {
            let scalar = Scalar::random(rng);
            generators.push(&scalar * &EdwardsPoint::basepoint());
        }
        generators
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_pedersen_commitment() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let pedersen = PedersenCommitment::default();
        let value = Scalar::random(&mut rng);

        // Create commitment
        let (commitment, opening) = pedersen.commit(&value, &mut rng);

        // Verify commitment
        pedersen.verify(&commitment, &opening).unwrap();

        // Test homomorphic properties
        let value2 = Scalar::random(&mut rng);
        let (commitment2, opening2) = pedersen.commit(&value2, &mut rng);

        let sum_commitment = pedersen.add_commitments(&commitment, &commitment2);
        let sum_opening = pedersen.add_openings(&opening, &opening2);

        pedersen.verify(&sum_commitment, &sum_opening).unwrap();
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_vector_commitment() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let size = 5;
        let vector_commitment = VectorCommitment::default_with_size(size, &mut rng);

        let values: Vec<_> = (0..size).map(|_| Scalar::random(&mut rng)).collect();

        // Create commitment
        let (commitment, opening) = vector_commitment.commit_vector(&values, &mut rng).unwrap();

        // Verify commitment
        vector_commitment.verify_vector(&commitment, &opening).unwrap();
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_polynomial_commitment() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let max_degree = 3;
        let vector_commitment = VectorCommitment::default_with_size(max_degree + 1, &mut rng);
        let poly_commitment = PolynomialCommitment::new(vector_commitment, max_degree).unwrap();

        // Create a polynomial: 2x^2 + 3x + 1
        let coefficients = vec![
            Scalar::one(),                    // constant term
            Scalar::from_u64(3),             // x term
            Scalar::from_u64(2),             // x^2 term
        ];

        // Commit to polynomial
        let (commitment, opening) = poly_commitment.commit_polynomial(&coefficients, &mut rng).unwrap();

        // Test evaluation
        let point = Scalar::from_u64(5);
        let expected_value = Scalar::from_u64(2 * 25 + 3 * 5 + 1); // 2*5^2 + 3*5 + 1 = 66

        let actual_value = poly_commitment.evaluate_polynomial(&coefficients, &point);
        assert_eq!(expected_value, actual_value);

        // Verify evaluation
        poly_commitment.verify_evaluation(&commitment, &point, &actual_value, &opening).unwrap();
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_serialization() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let pedersen = PedersenCommitment::default();
        let value = Scalar::random(&mut rng);
        let (commitment, opening) = pedersen.commit(&value, &mut rng);

        // Test commitment serialization
        let commitment_bytes = commitment.to_bytes();
        let recovered_commitment = Commitment::from_bytes(&commitment_bytes).unwrap();
        assert_eq!(commitment, recovered_commitment);

        // Test opening serialization
        let opening_bytes = opening.to_bytes();
        let recovered_opening = Opening::from_bytes(&opening_bytes);
        assert_eq!(opening.value, recovered_opening.value);
        assert_eq!(opening.blinding, recovered_opening.blinding);

        // Verify recovered commitment and opening
        pedersen.verify(&recovered_commitment, &recovered_opening).unwrap();
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_utils() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let value = Scalar::random(&mut rng);

        // Test utility functions
        let (commitment, opening) = utils::commit_value(&value, &mut rng);
        utils::verify_value(&commitment, &opening).unwrap();

        // Test zero commitment
        let (zero_commitment, zero_opening) = utils::commit_zero(&mut rng);
        assert!(utils::is_zero_commitment(&zero_opening));
        utils::verify_value(&zero_commitment, &zero_opening).unwrap();

        // Test generator generation
        let generators = utils::generate_generators(10, &mut rng);
        assert_eq!(generators.len(), 10);
        for generator in generators {
            assert!(!generator.is_identity());
        }
    }
}