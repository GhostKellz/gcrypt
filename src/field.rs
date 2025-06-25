//! Field arithmetic for the field GF(2^255 - 19).
//!
//! This module provides constant-time arithmetic operations
//! over the field used by Curve25519.

use core::{
    fmt::{self, Debug, Formatter},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::backend::FieldImpl;

/// A field element in GF(2^255 - 19).
///
/// Field elements are represented in Montgomery form for efficient arithmetic.
/// All operations are performed in constant time.
#[derive(Copy, Clone)]
pub struct FieldElement(pub(crate) FieldImpl);

impl FieldElement {
    /// The zero element.
    pub const ZERO: FieldElement = FieldElement(FieldImpl::ZERO);
    
    /// The one element.
    pub const ONE: FieldElement = FieldElement(FieldImpl::ONE);
    
    /// The element -1.
    pub const MINUS_ONE: FieldElement = FieldElement(FieldImpl::MINUS_ONE);

    /// Construct a field element from its canonical 32-byte representation.
    pub fn from_bytes(bytes: &[u8; 32]) -> FieldElement {
        FieldElement(FieldImpl::from_bytes(bytes))
    }

    /// Return the canonical 32-byte encoding of this field element.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Square this field element.
    pub fn square(&self) -> FieldElement {
        FieldElement(self.0.square())
    }

    /// Square this field element `n` times.
    pub fn square_n(&self, n: u32) -> FieldElement {
        let mut result = *self;
        for _ in 0..n {
            result = result.square();
        }
        result
    }

    /// Compute the multiplicative inverse of this field element.
    ///
    /// Returns (1, inverse) if the element is non-zero,
    /// or (0, zero) if the element is zero.
    pub fn invert(&self) -> FieldElement {
        self.0.invert().into()
    }

    /// Compute the square root of this field element.
    ///
    /// Returns (1, sqrt) if the element is a quadratic residue,
    /// or (0, sqrt(-self)) if not.
    pub fn sqrt(&self) -> (Choice, FieldElement) {
        let (is_square, sqrt) = self.0.sqrt();
        (is_square, FieldElement(sqrt))
    }

    /// Compute sqrt(u/v) or sqrt(i*u/v) where i = sqrt(-1).
    ///
    /// This is used in point decompression. Returns:
    /// - (1, sqrt(u/v)) if u/v is a square
    /// - (0, sqrt(i*u/v)) if u/v is not a square
    pub fn sqrt_ratio_i(u: &FieldElement, v: &FieldElement) -> (Choice, FieldElement) {
        let (is_square, result) = FieldImpl::sqrt_ratio_i(&u.0, &v.0);
        (is_square, FieldElement(result))
    }

    /// Conditionally negate this field element.
    pub fn conditional_negate(&mut self, choice: Choice) {
        self.0.conditional_negate(choice);
    }

    /// Return true if this field element is negative (i.e., bit 0 of the encoding is 1).
    pub fn is_negative(&self) -> Choice {
        self.0.is_negative()
    }

    /// Return true if this field element is zero.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&FieldElement::ZERO)
    }

    /// Compute 2 * self.
    pub fn double(&self) -> FieldElement {
        self + self
    }

    /// Compute 2^k * self.
    pub fn mul_by_pow_2(&self, k: u32) -> FieldElement {
        let mut result = *self;
        for _ in 0..k {
            result = result.double();
        }
        result
    }
}

impl Debug for FieldElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldElement")
            .field("bytes", &self.to_bytes())
            .finish()
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        FieldElement(FieldImpl::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for FieldElement {}

// Arithmetic operations
impl Add for FieldElement {
    type Output = FieldElement;

    fn add(self, other: FieldElement) -> FieldElement {
        FieldElement(self.0 + other.0)
    }
}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0 + other.0)
    }
}

impl AddAssign for FieldElement {
    fn add_assign(&mut self, other: FieldElement) {
        self.0 += other.0;
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: FieldElement) -> FieldElement {
        FieldElement(self.0 - other.0)
    }
}

impl Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0 - other.0)
    }
}

impl SubAssign for FieldElement {
    fn sub_assign(&mut self, other: FieldElement) {
        self.0 -= other.0;
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: FieldElement) -> FieldElement {
        FieldElement(self.0 * other.0)
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0 * other.0)
    }
}

impl MulAssign for FieldElement {
    fn mul_assign(&mut self, other: FieldElement) {
        self.0 *= other.0;
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement(-self.0)
    }
}

impl Neg for &FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement(-self.0)
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_constants() {
        assert!(bool::from(FieldElement::ZERO.is_zero()));
        assert!(!bool::from(FieldElement::ONE.is_zero()));
    }

    #[test]
    fn field_arithmetic() {
        let a = FieldElement::from_bytes(&[1u8; 32]);
        let b = FieldElement::from_bytes(&[2u8; 32]);
        
        let sum = &a + &b;
        let diff = &sum - &a;
        assert_eq!(diff, b);
        
        let product = &a * &b;
        let quotient = &product * &a.invert();
        assert_eq!(quotient, b);
    }

    #[test]
    fn field_sqrt() {
        let four = FieldElement::from_bytes(&[4u8; 32]);
        let (is_square, sqrt) = four.sqrt();
        assert!(bool::from(is_square));
        assert_eq!(sqrt.square(), four);
    }
}
