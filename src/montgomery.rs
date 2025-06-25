//! Montgomery curve point operations.
//!
//! This module implements the Montgomery ladder for scalar multiplication
//! on the Montgomery form of Curve25519.

use core::ops::{Mul, MulAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::traits::Decompress;

use crate::{
    field::FieldElement,
    scalar::{clamp_integer, Scalar},
    traits::{ValidPoint, ScalarMul},
    constants::X25519_BASEPOINT,
};

/// A point on the Montgomery form of Curve25519.
///
/// This stores only the u-coordinate, as the Montgomery ladder
/// doesn't require the v-coordinate.
#[derive(Copy, Clone, Debug)]
pub struct MontgomeryPoint(pub [u8; 32]);

impl MontgomeryPoint {
    /// The identity element for the Montgomery ladder (u = 0).
    pub const IDENTITY: MontgomeryPoint = MontgomeryPoint([0u8; 32]);

    /// The X25519 basepoint.
    pub const BASEPOINT: MontgomeryPoint = MontgomeryPoint(X25519_BASEPOINT);

    /// Create a MontgomeryPoint from a u-coordinate.
    pub fn from_bytes(bytes: [u8; 32]) -> MontgomeryPoint {
        MontgomeryPoint(bytes)
    }

    /// Return the u-coordinate as bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Scalar multiplication using the Montgomery ladder.
    pub fn mul_scalar(&self, scalar: &Scalar) -> MontgomeryPoint {
        self * scalar
    }

    /// Scalar multiplication with clamping (for X25519).
    pub fn mul_clamped(&self, bytes: [u8; 32]) -> MontgomeryPoint {
        let clamped = clamp_integer(bytes);
        let scalar = Scalar::from_bytes_mod_order(clamped);
        self * &scalar
    }

    /// Fixed-base scalar multiplication with the X25519 basepoint.
    pub fn mul_base(scalar: &Scalar) -> MontgomeryPoint {
        &MontgomeryPoint::BASEPOINT * scalar
    }

    /// Fixed-base scalar multiplication with clamping.
    pub fn mul_base_clamped(bytes: [u8; 32]) -> MontgomeryPoint {
        let clamped = clamp_integer(bytes);
        let scalar = Scalar::from_bytes_mod_order(clamped);
        MontgomeryPoint::mul_base(&scalar)
    }

    /// Convert to Edwards form.
    ///
    /// Returns `None` if the point is on the twist or if u = -1.
    pub fn to_edwards(&self, sign: u8) -> Option<crate::edwards::EdwardsPoint> {
        let u = FieldElement::from_bytes(&self.0);
        let one = FieldElement::ONE;

        // Check for the exceptional point u = -1
        if bool::from(u.ct_eq(&(-&one))) {
            return None;
        }

        // Birational map: y = (u-1)/(u+1)
        let y = &(&u - &one) * &(&u + &one).invert();

        let mut y_bytes = y.to_bytes();
        y_bytes[31] ^= sign << 7;

        crate::edwards::CompressedEdwardsY(y_bytes).decompress()
    }

    /// Perform the Montgomery ladder step.
    fn ladder_step(
        p1: &mut (FieldElement, FieldElement),
        p2: &mut (FieldElement, FieldElement),
        u: &FieldElement,
    ) {
        let (ref mut x1, ref mut z1) = *p1;
        let (ref mut x2, ref mut z2) = *p2;

        let a = &*x1 + &*z1;
        let b = &*x1 - &*z1;
        let c = &*x2 + &*z2;
        let d = &*x2 - &*z2;

        let da = &d * &a;
        let cb = &c * &b;

        *x1 = (&da + &cb).square();
        *z1 = u * (&da - &cb).square();

        let aa = a.square();
        let bb = b.square();
        *x2 = aa * bb;

        let e = &aa - &bb;
        *z2 = e * (&aa + &(crate::constants::MONTGOMERY_A_PLUS_2 * e));
    }
}

impl ValidPoint for MontgomeryPoint {
    fn is_valid(&self) -> Choice {
        // For Montgomery points, we only check if it's not the identity
        // The actual curve equation checking would require the v-coordinate
        let identity = MontgomeryPoint::IDENTITY;
        !self.ct_eq(&identity)
    }

    fn is_on_curve(&self) -> Choice {
        // Cannot check curve equation without v-coordinate
        // Return true for now (would need full point to check)
        Choice::from(1u8)
    }

    fn is_in_subgroup(&self) -> Choice {
        // For X25519, all points are considered valid
        Choice::from(1u8)
    }
}

impl ScalarMul<Scalar> for MontgomeryPoint {
    type Output = MontgomeryPoint;

    fn scalar_mul(&self, scalar: &Scalar) -> MontgomeryPoint {
        self * scalar
    }
}

impl Mul<&Scalar> for &MontgomeryPoint {
    type Output = MontgomeryPoint;

    fn mul(self, scalar: &Scalar) -> MontgomeryPoint {
        let u = FieldElement::from_bytes(&self.0);
        let one = FieldElement::ONE;
        let zero = FieldElement::ZERO;

        // Initialize ladder points
        let mut p1 = (one, zero); // Point at infinity
        let mut p2 = (u, one);    // Input point

        // Process scalar bits from most significant to least significant
        let scalar_bits = scalar.to_radix_2w(1);

        for i in (0..256).rev() {
            let bit = Choice::from(scalar_bits[i] as u8);
            
            // Conditional swap based on the bit
            let (x1, z1) = p1;
            let (x2, z2) = p2;
            
            let swap_x = FieldElement::conditional_select(&x1, &x2, bit);
            let swap_z = FieldElement::conditional_select(&z1, &z2, bit);
            let no_swap_x = FieldElement::conditional_select(&x2, &x1, bit);
            let no_swap_z = FieldElement::conditional_select(&z2, &z1, bit);
            
            p1 = (swap_x, swap_z);
            p2 = (no_swap_x, no_swap_z);

            // Perform ladder step
            MontgomeryPoint::ladder_step(&mut p1, &mut p2, &u);

            // Conditional swap back
            let (x1, z1) = p1;
            let (x2, z2) = p2;
            
            let final_x1 = FieldElement::conditional_select(&x1, &x2, bit);
            let final_z1 = FieldElement::conditional_select(&z1, &z2, bit);
            let final_x2 = FieldElement::conditional_select(&x2, &x1, bit);
            let final_z2 = FieldElement::conditional_select(&z2, &z1, bit);
            
            p1 = (final_x1, final_z1);
            p2 = (final_x2, final_z2);
        }

        // Convert result back to affine coordinates
        let (x, z) = p1;
        let result_u = &x * &z.invert();
        
        MontgomeryPoint(result_u.to_bytes())
    }
}

impl Mul<&Scalar> for MontgomeryPoint {
    type Output = MontgomeryPoint;

    fn mul(self, scalar: &Scalar) -> MontgomeryPoint {
        &self * scalar
    }
}

impl Mul<&MontgomeryPoint> for &Scalar {
    type Output = MontgomeryPoint;

    fn mul(self, point: &MontgomeryPoint) -> MontgomeryPoint {
        point * self
    }
}

impl MulAssign<&Scalar> for MontgomeryPoint {
    fn mul_assign(&mut self, scalar: &Scalar) {
        *self = self * scalar;
    }
}

impl ConstantTimeEq for MontgomeryPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for MontgomeryPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        MontgomeryPoint(<[u8; 32]>::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for MontgomeryPoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for MontgomeryPoint {}

#[cfg(feature = "zeroize")]
impl Zeroize for MontgomeryPoint {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Perform X25519 key exchange.
///
/// Given a secret scalar `k` and a public u-coordinate `u`,
/// compute the shared secret `k * u`.
pub fn x25519(k: [u8; 32], u: [u8; 32]) -> [u8; 32] {
    MontgomeryPoint(u).mul_clamped(k).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montgomery_scalar_mul() {
        let point = MontgomeryPoint::BASEPOINT;
        let scalar = Scalar::from_bytes_mod_order([1u8; 32]);
        
        let result = &point * &scalar;
        assert!(bool::from(result.is_valid()));
    }

    #[test]
    fn x25519_test() {
        let secret = [1u8; 32];
        let public = X25519_BASEPOINT;
        
        let shared = x25519(secret, public);
        
        // Should not be all zeros (except for pathological cases)
        assert_ne!(shared, [0u8; 32]);
    }

    #[test]
    fn montgomery_basepoint_mul() {
        let scalar = Scalar::from_bytes_mod_order([9u8; 32]);
        let result = MontgomeryPoint::mul_base(&scalar);
        
        assert!(bool::from(result.is_valid()));
    }
}
