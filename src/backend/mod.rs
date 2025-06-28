//! Backend implementations for different architectures and word sizes.
//!
//! This module contains the actual arithmetic implementations,
//! selecting the best one based on target features and word size.

use crate::scalar::Scalar;
use crate::field::FieldElement;
use crate::traits::Identity;

cfg_if::cfg_if! {
    if #[cfg(target_pointer_width = "64")] {
        mod u64_backend;
        pub(crate) use u64_backend::{ScalarImpl, FieldImpl};
    } else {
        mod u32_backend;
        pub(crate) use u32_backend::{ScalarImpl, FieldImpl};
    }
}

// SIMD backends for vectorized operations
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub mod simd_avx2;

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub use simd_avx2::{FieldElement4x, EdwardsPoint4x, multiscalar_mul_simd};

/// Runtime CPU feature detection for backend selection
pub fn get_optimal_backend() -> BackendType {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        if std::is_x86_feature_detected!("avx2") {
            return BackendType::Avx2;
        }
    }
    
    #[cfg(target_pointer_width = "64")]
    return BackendType::Serial64;
    
    #[cfg(target_pointer_width = "32")]
    return BackendType::Serial32;
}

/// Available backend types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    Serial32,
    Serial64,
    #[cfg(target_arch = "x86_64")]
    Avx2,
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    Avx512,
}

/// Multi-scalar multiplication with automatic backend selection
pub fn multiscalar_mul_auto(scalars: &[Scalar], points: &[crate::EdwardsPoint]) -> crate::EdwardsPoint {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2", feature = "std"))]
    {
        if std::is_x86_feature_detected!("avx2") && scalars.len() >= 4 && scalars.len() % 4 == 0 {
            return multiscalar_mul_simd(scalars, points);
        }
    }
    
    // Fallback to serial implementation
    let mut result = crate::EdwardsPoint::identity();
    for (scalar, point) in scalars.iter().zip(points.iter()) {
        result = &result + &(point * scalar);
    }
    result
}

// Conversion traits
impl From<Scalar> for ScalarImpl {
    fn from(scalar: Scalar) -> Self {
        ScalarImpl::from_bytes(scalar.bytes)
    }
}

impl From<ScalarImpl> for Scalar {
    fn from(impl_scalar: ScalarImpl) -> Self {
        Scalar {
            bytes: impl_scalar.to_bytes(),
        }
    }
}

impl From<FieldElement> for FieldImpl {
    fn from(fe: FieldElement) -> Self {
        fe.0
    }
}

impl From<FieldImpl> for FieldElement {
    fn from(impl_fe: FieldImpl) -> Self {
        FieldElement(impl_fe)
    }
}
