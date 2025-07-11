//! Scalar arithmetic modulo the order of the Curve25519 group.
//!
//! The `Scalar` type represents an integer modulo the order of the Curve25519 group,
//! which is `l = 2^252 + 27742317777372353535851937790883648493`.
//!
//! This module provides:
//! - Constant-time arithmetic operations
//! - Random scalar generation
//! - Serialization and deserialization
//! - Conversion to/from various representations

use core::{
    fmt::{self, Debug, Formatter},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

use crate::backend::ScalarImpl;
use crate::constants::{BASEPOINT_ORDER, BASEPOINT_ORDER_MINUS_ONE};

/// A scalar modulo the order of the Curve25519 group.
///
/// This represents an integer in the range [0, l) where 
/// l = 2^252 + 27742317777372353535851937790883648493.
///
/// All operations are performed in constant time to prevent timing attacks.
#[derive(Copy, Clone)]
pub struct Scalar {
    /// The scalar value as a 32-byte little-endian encoding
    pub(crate) bytes: [u8; 32],
}

impl Scalar {
    /// The zero scalar.
    pub const ZERO: Scalar = Scalar { bytes: [0u8; 32] };
    
    /// The scalar one.
    pub const ONE: Scalar = Scalar {
        bytes: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    };

    /// The order of the Curve25519 group minus one.
    pub const ORDER_MINUS_ONE: Scalar = BASEPOINT_ORDER_MINUS_ONE;

    /// Construct a `Scalar` from the canonical 32-byte representation.
    ///
    /// Returns `None` if the input is not canonical (i.e., if it encodes
    /// a scalar ≥ l).
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Scalar> {
        if Self::is_canonical(&bytes) {
            Some(Scalar { bytes })
        } else {
            None
        }
    }

    /// Construct a `Scalar` from an arbitrary 32-byte array.
    ///
    /// This reduces the input modulo the group order, so the result
    /// is always valid.
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Scalar {
        ScalarImpl::from_bytes_mod_order(bytes).into()
    }

    /// Construct a `Scalar` from an arbitrary 64-byte array.
    ///
    /// This reduces the input modulo the group order using Barrett reduction.
    pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Scalar {
        ScalarImpl::from_bytes_mod_order_wide(bytes).into()
    }

    /// Return the canonical 32-byte encoding of this scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Check if a 32-byte array is the canonical encoding of a scalar.
    pub fn is_canonical(bytes: &[u8; 32]) -> bool {
        // Check if bytes < BASEPOINT_ORDER
        let mut c = 0u8;
        for i in (0..32).rev() {
            c = ((((bytes[i] as u16).wrapping_sub(BASEPOINT_ORDER.bytes[i] as u16)) >> 8) & 1) as u8;
            if c != 0 {
                break;
            }
        }
        c == 1
    }

    /// Generate a random scalar.
    #[cfg(feature = "rand_core")]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes_mod_order_wide(&bytes)
    }

    /// Compute the multiplicative inverse of this scalar.
    ///
    /// Returns `None` if the scalar is zero.
    pub fn invert(&self) -> Option<Scalar> {
        if self.is_zero() {
            None
        } else {
            Some(ScalarImpl::from(*self).invert().into())
        }
    }

    /// Return `true` if this scalar is zero.
    pub fn is_zero(&self) -> bool {
        self.ct_eq(&Scalar::ZERO).into()
    }

    /// Compute the NAF (Non-Adjacent Form) representation of this scalar.
    ///
    /// Returns a signed binary representation where no two adjacent
    /// digits are non-zero.
    pub fn non_adjacent_form(&self, width: usize) -> [i8; 256] {
        assert!(width >= 2);
        assert!(width <= 8);

        let mut naf = [0i8; 256];
        let mut digits = self.to_radix_2w(width);

        for i in 0..256 {
            if digits[i] != 0 {
                let mut d = digits[i];
                if d >= (1 << (width - 1)) {
                    d -= 1 << width;
                    // Propagate carry
                    let mut j = i + 1;
                    while j < 256 && digits[j] == ((1 << width) - 1) {
                        digits[j] = 0;
                        j += 1;
                    }
                    if j < 256 {
                        digits[j] += 1;
                    }
                }
                naf[i] = d;
            }
        }

        naf
    }

    /// Convert this scalar to a radix-2^w representation.
    pub(crate) fn to_radix_2w(&self, w: usize) -> [i8; 256] {
        assert!(w >= 1);
        assert!(w <= 8);

        let mut digits = [0i8; 256];
        let radix = 1i8 << w;
        let window_mask = radix - 1;

        let mut carry = 0i8;
        for i in 0..256 {
            let bit = (self.bytes[i / 8] >> (i % 8)) & 1;
            let digit = carry + (bit as i8);
            
            if digit >= radix {
                digits[i] = digit - radix;
                carry = 1;
            } else {
                digits[i] = digit;
                carry = 0;
            }
        }

        digits
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scalar")
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = u8::conditional_select(&a.bytes[i], &b.bytes[i], choice);
        }
        Scalar { bytes: result }
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Scalar {}

// Arithmetic operations
impl Add for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        &self + &other
    }
}

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        ScalarImpl::add(&(*self).into(), &(*other).into()).into()
    }
}

impl AddAssign for Scalar {
    fn add_assign(&mut self, other: Scalar) {
        *self = *self + other;
    }
}

impl Sub for Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        &self - &other
    }
}

impl Sub<&Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        ScalarImpl::sub(&(*self).into(), &(*other).into()).into()
    }
}

impl SubAssign for Scalar {
    fn sub_assign(&mut self, other: Scalar) {
        *self = *self - other;
    }
}

impl Mul for Scalar {
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Scalar {
        &self * &other
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        ScalarImpl::mul(&(*self).into(), &(*other).into()).into()
    }
}

impl MulAssign for Scalar {
    fn mul_assign(&mut self, other: Scalar) {
        *self = *self * other;
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        ScalarImpl::neg(&self.into()).into()
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        ScalarImpl::neg(&(*self).into()).into()
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

/// Helper function to clamp a scalar for X25519.
///
/// This sets the bits as required by the X25519 specification:
/// - Clear bit 0, 1, 2
/// - Clear bit 255
/// - Set bit 254
pub fn clamp_integer(mut scalar: [u8; 32]) -> [u8; 32] {
    scalar[0] &= 0xf8;  // Clear bits 0, 1, 2
    scalar[31] &= 0x7f; // Clear bit 255
    scalar[31] |= 0x40; // Set bit 254
    scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_constants() {
        assert!(Scalar::ZERO.is_zero());
        assert!(!Scalar::ONE.is_zero());
        assert_eq!(Scalar::ZERO + Scalar::ONE, Scalar::ONE);
    }

    #[test]
    fn scalar_arithmetic() {
        let a = Scalar::from_bytes_mod_order([1u8; 32]);
        let b = Scalar::from_bytes_mod_order([2u8; 32]);
        
        let sum = &a + &b;
        let diff = &sum - &a;
        assert_eq!(diff, b);
        
        let product = &a * &b;
        assert_eq!(&product * &a.invert().unwrap(), b);
    }

    #[test]
    fn scalar_canonical() {
        let canonical = [0u8; 32];
        assert!(Scalar::is_canonical(&canonical));
        
        let non_canonical = [0xff; 32];
        assert!(!Scalar::is_canonical(&non_canonical));
    }

    #[test]
    fn clamp_test() {
        let input = [0xff; 32];
        let clamped = clamp_integer(input);
        
        assert_eq!(clamped[0] & 0x07, 0);  // Bits 0,1,2 cleared
        assert_eq!(clamped[31] & 0x80, 0); // Bit 255 cleared
        assert_eq!(clamped[31] & 0x40, 0x40); // Bit 254 set
    }
}
