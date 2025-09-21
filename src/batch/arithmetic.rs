//! Batch Arithmetic Operations
//!
//! High-performance batch operations for scalar and point arithmetic,
//! optimized for throughput-critical applications like DeFi protocols.

use crate::{EdwardsPoint, MontgomeryPoint, Scalar, field::FieldElement, traits::Field};
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "rayon")]
use rayon::prelude::*;

/// Batch arithmetic operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchArithmeticError {
    /// Input arrays have mismatched lengths
    MismatchedLengths,
    /// Batch is empty
    EmptyBatch,
    /// Arithmetic operation failed
    ArithmeticFailed,
    /// Invalid input
    InvalidInput,
}

impl fmt::Display for BatchArithmeticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BatchArithmeticError::MismatchedLengths => write!(f, "Input arrays have mismatched lengths"),
            BatchArithmeticError::EmptyBatch => write!(f, "Batch is empty"),
            BatchArithmeticError::ArithmeticFailed => write!(f, "Batch arithmetic operation failed"),
            BatchArithmeticError::InvalidInput => write!(f, "Invalid input for batch operation"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BatchArithmeticError {}

/// High-performance batch scalar operations
pub struct BatchScalarOps;

impl BatchScalarOps {
    /// Batch scalar multiplication: [s1*G, s2*G, ..., sn*G]
    #[cfg(feature = "alloc")]
    pub fn batch_mul_base(scalars: &[Scalar]) -> Result<Vec<EdwardsPoint>, BatchArithmeticError> {
        if scalars.is_empty() {
            return Err(BatchArithmeticError::EmptyBatch);
        }

        let results = if cfg!(feature = "rayon") && scalars.len() > 8 {
            Self::batch_mul_base_parallel(scalars)
        } else {
            Self::batch_mul_base_sequential(scalars)
        };

        Ok(results)
    }

    /// Sequential batch base multiplication
    #[cfg(feature = "alloc")]
    fn batch_mul_base_sequential(scalars: &[Scalar]) -> Vec<EdwardsPoint> {
        scalars.iter().map(|scalar| EdwardsPoint::mul_base(scalar)).collect()
    }

    /// Parallel batch base multiplication
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn batch_mul_base_parallel(scalars: &[Scalar]) -> Vec<EdwardsPoint> {
        scalars.par_iter().map(|scalar| EdwardsPoint::mul_base(scalar)).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn batch_mul_base_parallel(scalars: &[Scalar]) -> Vec<EdwardsPoint> {
        Self::batch_mul_base_sequential(scalars)
    }

    /// Batch scalar-point multiplication: [s1*P1, s2*P2, ..., sn*Pn]
    #[cfg(feature = "alloc")]
    pub fn batch_scalar_mul(
        scalars: &[Scalar],
        points: &[EdwardsPoint],
    ) -> Result<Vec<EdwardsPoint>, BatchArithmeticError> {
        if scalars.len() != points.len() {
            return Err(BatchArithmeticError::MismatchedLengths);
        }

        if scalars.is_empty() {
            return Err(BatchArithmeticError::EmptyBatch);
        }

        let results = if cfg!(feature = "rayon") && scalars.len() > 8 {
            Self::batch_scalar_mul_parallel(scalars, points)
        } else {
            Self::batch_scalar_mul_sequential(scalars, points)
        };

        Ok(results)
    }

    /// Sequential batch scalar multiplication
    #[cfg(feature = "alloc")]
    fn batch_scalar_mul_sequential(scalars: &[Scalar], points: &[EdwardsPoint]) -> Vec<EdwardsPoint> {
        scalars.iter().zip(points.iter()).map(|(scalar, point)| point * scalar).collect()
    }

    /// Parallel batch scalar multiplication
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn batch_scalar_mul_parallel(scalars: &[Scalar], points: &[EdwardsPoint]) -> Vec<EdwardsPoint> {
        scalars.par_iter().zip(points.par_iter()).map(|(scalar, point)| point * scalar).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn batch_scalar_mul_parallel(scalars: &[Scalar], points: &[EdwardsPoint]) -> Vec<EdwardsPoint> {
        Self::batch_scalar_mul_sequential(scalars, points)
    }

    /// Batch scalar addition: [s1+t1, s2+t2, ..., sn+tn]
    #[cfg(feature = "alloc")]
    pub fn batch_scalar_add(
        scalars_a: &[Scalar],
        scalars_b: &[Scalar],
    ) -> Result<Vec<Scalar>, BatchArithmeticError> {
        if scalars_a.len() != scalars_b.len() {
            return Err(BatchArithmeticError::MismatchedLengths);
        }

        if scalars_a.is_empty() {
            return Err(BatchArithmeticError::EmptyBatch);
        }

        let results = if cfg!(feature = "rayon") && scalars_a.len() > 16 {
            Self::batch_scalar_add_parallel(scalars_a, scalars_b)
        } else {
            Self::batch_scalar_add_sequential(scalars_a, scalars_b)
        };

        Ok(results)
    }

    /// Sequential batch scalar addition
    #[cfg(feature = "alloc")]
    fn batch_scalar_add_sequential(scalars_a: &[Scalar], scalars_b: &[Scalar]) -> Vec<Scalar> {
        scalars_a.iter().zip(scalars_b.iter()).map(|(a, b)| a + b).collect()
    }

    /// Parallel batch scalar addition
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn batch_scalar_add_parallel(scalars_a: &[Scalar], scalars_b: &[Scalar]) -> Vec<Scalar> {
        scalars_a.par_iter().zip(scalars_b.par_iter()).map(|(a, b)| a + b).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn batch_scalar_add_parallel(scalars_a: &[Scalar], scalars_b: &[Scalar]) -> Vec<Scalar> {
        Self::batch_scalar_add_sequential(scalars_a, scalars_b)
    }

    /// Batch scalar multiplication: [s1*t1, s2*t2, ..., sn*tn]
    #[cfg(feature = "alloc")]
    pub fn batch_scalar_mul_scalar(
        scalars_a: &[Scalar],
        scalars_b: &[Scalar],
    ) -> Result<Vec<Scalar>, BatchArithmeticError> {
        if scalars_a.len() != scalars_b.len() {
            return Err(BatchArithmeticError::MismatchedLengths);
        }

        if scalars_a.is_empty() {
            return Err(BatchArithmeticError::EmptyBatch);
        }

        let results = if cfg!(feature = "rayon") && scalars_a.len() > 16 {
            Self::batch_scalar_mul_scalar_parallel(scalars_a, scalars_b)
        } else {
            Self::batch_scalar_mul_scalar_sequential(scalars_a, scalars_b)
        };

        Ok(results)
    }

    /// Sequential batch scalar multiplication
    #[cfg(feature = "alloc")]
    fn batch_scalar_mul_scalar_sequential(scalars_a: &[Scalar], scalars_b: &[Scalar]) -> Vec<Scalar> {
        scalars_a.iter().zip(scalars_b.iter()).map(|(a, b)| a * b).collect()
    }

    /// Parallel batch scalar multiplication
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn batch_scalar_mul_scalar_parallel(scalars_a: &[Scalar], scalars_b: &[Scalar]) -> Vec<Scalar> {
        scalars_a.par_iter().zip(scalars_b.par_iter()).map(|(a, b)| a * b).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn batch_scalar_mul_scalar_parallel(scalars_a: &[Scalar], scalars_b: &[Scalar]) -> Vec<Scalar> {
        Self::batch_scalar_mul_scalar_sequential(scalars_a, scalars_b)
    }

    /// Batch scalar inversion: [s1^-1, s2^-1, ..., sn^-1]
    /// Uses Montgomery's trick for efficient batch inversion
    #[cfg(feature = "alloc")]
    pub fn batch_scalar_invert(scalars: &[Scalar]) -> Result<Vec<Scalar>, BatchArithmeticError> {
        if scalars.is_empty() {
            return Err(BatchArithmeticError::EmptyBatch);
        }

        // Check for zero scalars
        if scalars.iter().any(|s| *s == Scalar::zero()) {
            return Err(BatchArithmeticError::InvalidInput);
        }

        Ok(Self::montgomery_batch_invert(scalars))
    }

    /// Montgomery's trick for batch inversion
    #[cfg(feature = "alloc")]
    fn montgomery_batch_invert(scalars: &[Scalar]) -> Vec<Scalar> {
        let n = scalars.len();
        if n == 0 {
            return Vec::new();
        }

        if n == 1 {
            return vec![scalars[0].invert()];
        }

        // Compute partial products
        let mut partials = Vec::with_capacity(n);
        partials.push(scalars[0]);

        for i in 1..n {
            partials.push(partials[i - 1] * scalars[i]);
        }

        // Compute the inverse of the product of all elements
        let inv_product = partials[n - 1].invert();

        // Work backwards to compute individual inverses
        let mut results = vec![Scalar::zero(); n];
        let mut accumulator = inv_product;

        for i in (0..n).rev() {
            if i == 0 {
                results[i] = accumulator;
            } else {
                results[i] = accumulator * partials[i - 1];
                accumulator = accumulator * scalars[i];
            }
        }

        results
    }
}

/// High-performance batch point operations
pub struct BatchPointOps;

impl BatchPointOps {
    /// Batch point addition: [P1+Q1, P2+Q2, ..., Pn+Qn]
    #[cfg(feature = "alloc")]
    pub fn batch_point_add(
        points_a: &[EdwardsPoint],
        points_b: &[EdwardsPoint],
    ) -> Result<Vec<EdwardsPoint>, BatchArithmeticError> {
        if points_a.len() != points_b.len() {
            return Err(BatchArithmeticError::MismatchedLengths);
        }

        if points_a.is_empty() {
            return Err(BatchArithmeticError::EmptyBatch);
        }

        let results = if cfg!(feature = "rayon") && points_a.len() > 8 {
            Self::batch_point_add_parallel(points_a, points_b)
        } else {
            Self::batch_point_add_sequential(points_a, points_b)
        };

        Ok(results)
    }

    /// Sequential batch point addition
    #[cfg(feature = "alloc")]
    fn batch_point_add_sequential(points_a: &[EdwardsPoint], points_b: &[EdwardsPoint]) -> Vec<EdwardsPoint> {
        points_a.iter().zip(points_b.iter()).map(|(a, b)| a + b).collect()
    }

    /// Parallel batch point addition
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn batch_point_add_parallel(points_a: &[EdwardsPoint], points_b: &[EdwardsPoint]) -> Vec<EdwardsPoint> {
        points_a.par_iter().zip(points_b.par_iter()).map(|(a, b)| a + b).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn batch_point_add_parallel(points_a: &[EdwardsPoint], points_b: &[EdwardsPoint]) -> Vec<EdwardsPoint> {
        Self::batch_point_add_sequential(points_a, points_b)
    }

    /// Batch point compression: [P1.compress(), P2.compress(), ..., Pn.compress()]
    #[cfg(feature = "alloc")]
    pub fn batch_point_compress(points: &[EdwardsPoint]) -> Result<Vec<[u8; 32]>, BatchArithmeticError> {
        if points.is_empty() {
            return Err(BatchArithmeticError::EmptyBatch);
        }

        let results = if cfg!(feature = "rayon") && points.len() > 16 {
            Self::batch_point_compress_parallel(points)
        } else {
            Self::batch_point_compress_sequential(points)
        };

        Ok(results)
    }

    /// Sequential batch point compression
    #[cfg(feature = "alloc")]
    fn batch_point_compress_sequential(points: &[EdwardsPoint]) -> Vec<[u8; 32]> {
        points.iter().map(|point| point.compress().to_bytes()).collect()
    }

    /// Parallel batch point compression
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn batch_point_compress_parallel(points: &[EdwardsPoint]) -> Vec<[u8; 32]> {
        points.par_iter().map(|point| point.compress().to_bytes()).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn batch_point_compress_parallel(points: &[EdwardsPoint]) -> Vec<[u8; 32]> {
        Self::batch_point_compress_sequential(points)
    }

    /// Batch multi-scalar multiplication: s1*P1 + s2*P2 + ... + sn*Pn
    #[cfg(feature = "alloc")]
    pub fn batch_multiscalar_mul(
        scalars: &[Scalar],
        points: &[EdwardsPoint],
    ) -> Result<EdwardsPoint, BatchArithmeticError> {
        if scalars.len() != points.len() {
            return Err(BatchArithmeticError::MismatchedLengths);
        }

        if scalars.is_empty() {
            return Err(BatchArithmeticError::EmptyBatch);
        }

        // Use sliding window method for efficiency
        Ok(Self::multiscalar_mul_sliding_window(scalars, points))
    }

    /// Multi-scalar multiplication using sliding window method
    #[cfg(feature = "alloc")]
    fn multiscalar_mul_sliding_window(scalars: &[Scalar], points: &[EdwardsPoint]) -> EdwardsPoint {
        // Simple implementation - in practice, use more sophisticated algorithms
        let mut result = EdwardsPoint::identity();

        for (scalar, point) in scalars.iter().zip(points.iter()) {
            result = &result + &(point * scalar);
        }

        result
    }
}

/// High-performance batch field operations
pub struct BatchFieldOps;

impl BatchFieldOps {
    /// Batch field element addition
    #[cfg(feature = "alloc")]
    pub fn batch_field_add(
        elements_a: &[FieldElement],
        elements_b: &[FieldElement],
    ) -> Result<Vec<FieldElement>, BatchArithmeticError> {
        if elements_a.len() != elements_b.len() {
            return Err(BatchArithmeticError::MismatchedLengths);
        }

        if elements_a.is_empty() {
            return Err(BatchArithmeticError::EmptyBatch);
        }

        let results = if cfg!(feature = "rayon") && elements_a.len() > 32 {
            Self::batch_field_add_parallel(elements_a, elements_b)
        } else {
            Self::batch_field_add_sequential(elements_a, elements_b)
        };

        Ok(results)
    }

    /// Sequential batch field addition
    #[cfg(feature = "alloc")]
    fn batch_field_add_sequential(elements_a: &[FieldElement], elements_b: &[FieldElement]) -> Vec<FieldElement> {
        elements_a.iter().zip(elements_b.iter()).map(|(a, b)| *a + *b).collect()
    }

    /// Parallel batch field addition
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn batch_field_add_parallel(elements_a: &[FieldElement], elements_b: &[FieldElement]) -> Vec<FieldElement> {
        elements_a.par_iter().zip(elements_b.par_iter()).map(|(a, b)| *a + *b).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn batch_field_add_parallel(elements_a: &[FieldElement], elements_b: &[FieldElement]) -> Vec<FieldElement> {
        Self::batch_field_add_sequential(elements_a, elements_b)
    }

    /// Batch field element multiplication
    #[cfg(feature = "alloc")]
    pub fn batch_field_mul(
        elements_a: &[FieldElement],
        elements_b: &[FieldElement],
    ) -> Result<Vec<FieldElement>, BatchArithmeticError> {
        if elements_a.len() != elements_b.len() {
            return Err(BatchArithmeticError::MismatchedLengths);
        }

        if elements_a.is_empty() {
            return Err(BatchArithmeticError::EmptyBatch);
        }

        let results = if cfg!(feature = "rayon") && elements_a.len() > 16 {
            Self::batch_field_mul_parallel(elements_a, elements_b)
        } else {
            Self::batch_field_mul_sequential(elements_a, elements_b)
        };

        Ok(results)
    }

    /// Sequential batch field multiplication
    #[cfg(feature = "alloc")]
    fn batch_field_mul_sequential(elements_a: &[FieldElement], elements_b: &[FieldElement]) -> Vec<FieldElement> {
        elements_a.iter().zip(elements_b.iter()).map(|(a, b)| *a * *b).collect()
    }

    /// Parallel batch field multiplication
    #[cfg(all(feature = "alloc", feature = "rayon"))]
    fn batch_field_mul_parallel(elements_a: &[FieldElement], elements_b: &[FieldElement]) -> Vec<FieldElement> {
        elements_a.par_iter().zip(elements_b.par_iter()).map(|(a, b)| *a * *b).collect()
    }

    /// Fallback when rayon is not available
    #[cfg(all(feature = "alloc", not(feature = "rayon")))]
    fn batch_field_mul_parallel(elements_a: &[FieldElement], elements_b: &[FieldElement]) -> Vec<FieldElement> {
        Self::batch_field_mul_sequential(elements_a, elements_b)
    }

    /// Batch field element inversion using Montgomery's trick
    #[cfg(feature = "alloc")]
    pub fn batch_field_invert(elements: &[FieldElement]) -> Result<Vec<FieldElement>, BatchArithmeticError> {
        if elements.is_empty() {
            return Err(BatchArithmeticError::EmptyBatch);
        }

        // Check for zero elements
        if elements.iter().any(|e| *e == FieldElement::zero()) {
            return Err(BatchArithmeticError::InvalidInput);
        }

        Ok(Self::montgomery_batch_invert_field(elements))
    }

    /// Montgomery's trick for batch field inversion
    #[cfg(feature = "alloc")]
    fn montgomery_batch_invert_field(elements: &[FieldElement]) -> Vec<FieldElement> {
        let n = elements.len();
        if n == 0 {
            return Vec::new();
        }

        if n == 1 {
            return vec![elements[0].invert()];
        }

        // Compute partial products
        let mut partials = Vec::with_capacity(n);
        partials.push(elements[0]);

        for i in 1..n {
            partials.push(partials[i - 1] * elements[i]);
        }

        // Compute the inverse of the product of all elements
        let inv_product = partials[n - 1].invert();

        // Work backwards to compute individual inverses
        let mut results = vec![FieldElement::zero(); n];
        let mut accumulator = inv_product;

        for i in (0..n).rev() {
            if i == 0 {
                results[i] = accumulator;
            } else {
                results[i] = accumulator * partials[i - 1];
                accumulator = accumulator * elements[i];
            }
        }

        results
    }
}

/// Convenience functions for batch arithmetic operations
#[cfg(feature = "alloc")]
pub mod batch_arithmetic {
    use super::*;

    /// Batch base scalar multiplication
    pub fn scalar_mul_base(scalars: &[Scalar]) -> Result<Vec<EdwardsPoint>, BatchArithmeticError> {
        BatchScalarOps::batch_mul_base(scalars)
    }

    /// Batch scalar-point multiplication
    pub fn scalar_mul(scalars: &[Scalar], points: &[EdwardsPoint]) -> Result<Vec<EdwardsPoint>, BatchArithmeticError> {
        BatchScalarOps::batch_scalar_mul(scalars, points)
    }

    /// Batch point addition
    pub fn point_add(points_a: &[EdwardsPoint], points_b: &[EdwardsPoint]) -> Result<Vec<EdwardsPoint>, BatchArithmeticError> {
        BatchPointOps::batch_point_add(points_a, points_b)
    }

    /// Multi-scalar multiplication
    pub fn multiscalar_mul(scalars: &[Scalar], points: &[EdwardsPoint]) -> Result<EdwardsPoint, BatchArithmeticError> {
        BatchPointOps::batch_multiscalar_mul(scalars, points)
    }

    /// Batch scalar inversion
    pub fn scalar_invert(scalars: &[Scalar]) -> Result<Vec<Scalar>, BatchArithmeticError> {
        BatchScalarOps::batch_scalar_invert(scalars)
    }

    /// Batch field inversion
    pub fn field_invert(elements: &[FieldElement]) -> Result<Vec<FieldElement>, BatchArithmeticError> {
        BatchFieldOps::batch_field_invert(elements)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_scalars(count: usize) -> Vec<Scalar> {
        (1..=count).map(|i| Scalar::from_u64(i as u64)).collect()
    }

    fn create_test_points(count: usize) -> Vec<EdwardsPoint> {
        (1..=count).map(|i| {
            let scalar = Scalar::from_u64(i as u64);
            EdwardsPoint::mul_base(&scalar)
        }).collect()
    }

    fn create_test_field_elements(count: usize) -> Vec<FieldElement> {
        (1..=count).map(|i| FieldElement::from_u64(i as u64)).collect()
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_scalar_mul_base() {
        let scalars = create_test_scalars(10);
        let results = BatchScalarOps::batch_mul_base(&scalars).unwrap();

        assert_eq!(results.len(), 10);

        // Verify each result individually
        for (i, result) in results.iter().enumerate() {
            let expected = EdwardsPoint::mul_base(&scalars[i]);
            assert_eq!(*result, expected);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_scalar_mul() {
        let scalars = create_test_scalars(5);
        let points = create_test_points(5);
        let results = BatchScalarOps::batch_scalar_mul(&scalars, &points).unwrap();

        assert_eq!(results.len(), 5);

        // Verify each result individually
        for (i, result) in results.iter().enumerate() {
            let expected = &points[i] * &scalars[i];
            assert_eq!(*result, expected);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_scalar_add() {
        let scalars_a = create_test_scalars(8);
        let scalars_b = create_test_scalars(8);
        let results = BatchScalarOps::batch_scalar_add(&scalars_a, &scalars_b).unwrap();

        assert_eq!(results.len(), 8);

        // Verify each result individually
        for (i, result) in results.iter().enumerate() {
            let expected = &scalars_a[i] + &scalars_b[i];
            assert_eq!(*result, expected);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_scalar_invert() {
        let scalars = create_test_scalars(6);
        let results = BatchScalarOps::batch_scalar_invert(&scalars).unwrap();

        assert_eq!(results.len(), 6);

        // Verify each result individually
        for (i, result) in results.iter().enumerate() {
            let expected = scalars[i].invert();
            assert_eq!(*result, expected);

            // Verify that scalar * inverse = 1
            let product = &scalars[i] * result;
            assert_eq!(product, Scalar::one());
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_point_add() {
        let points_a = create_test_points(7);
        let points_b = create_test_points(7);
        let results = BatchPointOps::batch_point_add(&points_a, &points_b).unwrap();

        assert_eq!(results.len(), 7);

        // Verify each result individually
        for (i, result) in results.iter().enumerate() {
            let expected = &points_a[i] + &points_b[i];
            assert_eq!(*result, expected);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_multiscalar_mul() {
        let scalars = create_test_scalars(4);
        let points = create_test_points(4);
        let result = BatchPointOps::batch_multiscalar_mul(&scalars, &points).unwrap();

        // Compute expected result manually
        let mut expected = EdwardsPoint::identity();
        for (scalar, point) in scalars.iter().zip(points.iter()) {
            expected = &expected + &(point * scalar);
        }

        assert_eq!(result, expected);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_field_operations() {
        let elements_a = create_test_field_elements(10);
        let elements_b = create_test_field_elements(10);

        let add_results = BatchFieldOps::batch_field_add(&elements_a, &elements_b).unwrap();
        let mul_results = BatchFieldOps::batch_field_mul(&elements_a, &elements_b).unwrap();

        assert_eq!(add_results.len(), 10);
        assert_eq!(mul_results.len(), 10);

        // Verify results
        for i in 0..10 {
            assert_eq!(add_results[i], elements_a[i] + elements_b[i]);
            assert_eq!(mul_results[i], elements_a[i] * elements_b[i]);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_field_invert() {
        let elements = create_test_field_elements(5);
        let results = BatchFieldOps::batch_field_invert(&elements).unwrap();

        assert_eq!(results.len(), 5);

        // Verify each result
        for (i, result) in results.iter().enumerate() {
            let product = elements[i] * *result;
            assert_eq!(product, FieldElement::one());
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_empty_batch_errors() {
        assert!(matches!(
            BatchScalarOps::batch_mul_base(&[]),
            Err(BatchArithmeticError::EmptyBatch)
        ));

        assert!(matches!(
            BatchPointOps::batch_point_add(&[], &[]),
            Err(BatchArithmeticError::EmptyBatch)
        ));

        assert!(matches!(
            BatchFieldOps::batch_field_add(&[], &[]),
            Err(BatchArithmeticError::EmptyBatch)
        ));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_mismatched_lengths() {
        let scalars = create_test_scalars(5);
        let points = create_test_points(3); // Different length

        assert!(matches!(
            BatchScalarOps::batch_scalar_mul(&scalars, &points),
            Err(BatchArithmeticError::MismatchedLengths)
        ));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_convenience_functions() {
        let scalars = create_test_scalars(3);
        let points = create_test_points(3);

        let base_mul_results = batch_arithmetic::scalar_mul_base(&scalars).unwrap();
        let scalar_mul_results = batch_arithmetic::scalar_mul(&scalars, &points).unwrap();
        let point_add_results = batch_arithmetic::point_add(&points, &points).unwrap();
        let multiscalar_result = batch_arithmetic::multiscalar_mul(&scalars, &points).unwrap();

        assert_eq!(base_mul_results.len(), 3);
        assert_eq!(scalar_mul_results.len(), 3);
        assert_eq!(point_add_results.len(), 3);
        assert_ne!(multiscalar_result, EdwardsPoint::identity());
    }
}