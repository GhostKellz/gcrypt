//! Common traits used throughout the gcrypt library.

use core::borrow::Borrow;
use subtle::Choice;

use crate::scalar::Scalar;

/// Trait for types that have an identity element.
pub trait Identity {
    /// Returns the identity element.
    fn identity() -> Self;
}

/// Trait for testing if an element is the identity.
pub trait IsIdentity {
    /// Returns true if this element is the identity.
    fn is_identity(&self) -> Choice;
}

/// Trait for scalar multiplication.
pub trait ScalarMul<Scalar> {
    /// The resulting point type.
    type Output;
    
    /// Multiply this point by a scalar.
    fn scalar_mul(&self, scalar: &Scalar) -> Self::Output;
}

/// Trait for variable-time multiscalar multiplication.
#[cfg(feature = "alloc")]
pub trait VartimeMultiscalarMul {
    /// The point type.
    type Point;
    
    /// Compute a multiscalar multiplication in variable time.
    ///
    /// Given scalars `a_0, a_1, ..., a_n` and points `A_0, A_1, ..., A_n`,
    /// compute `a_0 * A_0 + a_1 * A_1 + ... + a_n * A_n`.
    fn vartime_multiscalar_mul<I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Self::Point>;
}

/// Trait for precomputed multiscalar multiplication.
#[cfg(feature = "alloc")]
pub trait VartimePrecomputedMultiscalarMul {
    /// The point type.
    type Point;
    
    /// Create a new precomputation table for the given static points.
    fn new<I>(static_points: I) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<Self::Point>;
    
    /// Return the number of precomputed points.
    fn len(&self) -> usize;
    
    /// Return true if the precomputation is empty.
    fn is_empty(&self) -> bool;
    
    /// Compute a multiscalar multiplication using precomputed values.
    ///
    /// Computes `static_scalars[0] * static_points[0] + ... + dynamic_scalars[0] * dynamic_points[0] + ...`
    /// where `static_points` are the precomputed points and `dynamic_points` are provided at runtime.
    fn vartime_mixed_multiscalar_mul<I, J, K>(
        &self,
        static_scalars: I,
        dynamic_scalars: J,
        dynamic_points: K,
    ) -> Self::Point
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Scalar>,
        K: IntoIterator,
        K::Item: Borrow<Self::Point>;
}

/// Trait for basepoint tables used in fixed-base scalar multiplication.
pub trait BasepointTable {
    /// The point type.
    type Point;
    
    /// Multiply the basepoint by a scalar using the precomputed table.
    fn mul_base(&self, scalar: &Scalar) -> Self::Point;
}

/// Trait for validating points on the curve.
pub trait ValidPoint {
    /// Check if this point is valid (on the curve and in the correct subgroup).
    fn is_valid(&self) -> Choice;
    
    /// Check if this point is on the curve.
    fn is_on_curve(&self) -> Choice;
    
    /// Check if this point is in the correct subgroup.
    fn is_in_subgroup(&self) -> Choice;
}

/// Trait for point compression.
pub trait Compress {
    /// The compressed representation type.
    type Compressed;
    
    /// Compress this point to its canonical representation.
    fn compress(&self) -> Self::Compressed;
}

/// Trait for point decompression.
pub trait Decompress<T> {
    /// Decompress a point from its canonical representation.
    ///
    /// Returns `Some(point)` if the compressed point is valid,
    /// or `None` if it's invalid.
    fn decompress(&self) -> Option<T>;
}

/// Trait for clearing the cofactor of a point.
pub trait ClearCofactor {
    /// Clear the cofactor of this point.
    ///
    /// For Ed25519, this multiplies by 8 to ensure the result
    /// is in the prime-order subgroup.
    fn clear_cofactor(&self) -> Self;
}

/// Trait for converting between different point representations.
pub trait ConvertPoint<T> {
    /// Convert this point to another representation.
    fn to_point(&self) -> T;
}

/// Trait for batch operations on points.
#[cfg(feature = "alloc")]
pub trait BatchOps<T> {
    /// Perform a batch operation on multiple points.
    ///
    /// This is often more efficient than performing individual operations.
    fn batch_op<I>(points: I) -> alloc::vec::Vec<T>
    where
        I: IntoIterator,
        I::Item: Borrow<Self>;
}
