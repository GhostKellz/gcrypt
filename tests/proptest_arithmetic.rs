//! Property-based tests for arithmetic operations

use proptest::prelude::*;
use gcrypt::{Scalar, EdwardsPoint, MontgomeryPoint, RistrettoPoint};

proptest! {
    #[test]
    fn scalar_addition_is_commutative(a_bytes in any::<[u8; 32]>(), b_bytes in any::<[u8; 32]>()) {
        let a = Scalar::from_bytes_mod_order(a_bytes);
        let b = Scalar::from_bytes_mod_order(b_bytes);

        prop_assert_eq!(&a + &b, &b + &a);
    }

    #[test]
    fn scalar_addition_is_associative(
        a_bytes in any::<[u8; 32]>(),
        b_bytes in any::<[u8; 32]>(),
        c_bytes in any::<[u8; 32]>()
    ) {
        let a = Scalar::from_bytes_mod_order(a_bytes);
        let b = Scalar::from_bytes_mod_order(b_bytes);
        let c = Scalar::from_bytes_mod_order(c_bytes);

        prop_assert_eq!(&(&a + &b) + &c, &a + &(&b + &c));
    }

    #[test]
    fn scalar_multiplication_is_commutative(a_bytes in any::<[u8; 32]>(), b_bytes in any::<[u8; 32]>()) {
        let a = Scalar::from_bytes_mod_order(a_bytes);
        let b = Scalar::from_bytes_mod_order(b_bytes);

        prop_assert_eq!(&a * &b, &b * &a);
    }

    #[test]
    fn scalar_zero_is_additive_identity(a_bytes in any::<[u8; 32]>()) {
        let a = Scalar::from_bytes_mod_order(a_bytes);
        let zero = Scalar::ZERO;

        prop_assert_eq!(&a + &zero, a);
        prop_assert_eq!(&zero + &a, a);
    }

    #[test]
    fn scalar_one_is_multiplicative_identity(a_bytes in any::<[u8; 32]>()) {
        let a = Scalar::from_bytes_mod_order(a_bytes);
        let one = Scalar::ONE;

        prop_assert_eq!(&a * &one, a);
        prop_assert_eq!(&one * &a, a);
    }

    #[test]
    fn edwards_point_addition_is_commutative(
        a_bytes in any::<[u8; 32]>(),
        b_bytes in any::<[u8; 32]>()
    ) {
        let a_scalar = Scalar::from_bytes_mod_order(a_bytes);
        let b_scalar = Scalar::from_bytes_mod_order(b_bytes);

        let a_point = EdwardsPoint::mul_base(&a_scalar);
        let b_point = EdwardsPoint::mul_base(&b_scalar);

        prop_assert_eq!(&a_point + &b_point, &b_point + &a_point);
    }

    #[test]
    fn edwards_point_addition_is_associative(
        a_bytes in any::<[u8; 32]>(),
        b_bytes in any::<[u8; 32]>(),
        c_bytes in any::<[u8; 32]>()
    ) {
        let a_scalar = Scalar::from_bytes_mod_order(a_bytes);
        let b_scalar = Scalar::from_bytes_mod_order(b_bytes);
        let c_scalar = Scalar::from_bytes_mod_order(c_bytes);

        let a_point = EdwardsPoint::mul_base(&a_scalar);
        let b_point = EdwardsPoint::mul_base(&b_scalar);
        let c_point = EdwardsPoint::mul_base(&c_scalar);

        prop_assert_eq!(&(&a_point + &b_point) + &c_point, &a_point + &(&b_point + &c_point));
    }

    #[test]
    fn ristretto_point_compression_roundtrip(a_bytes in any::<[u8; 32]>()) {
        let scalar = Scalar::from_bytes_mod_order(a_bytes);
        let point = RistrettoPoint::mul_base(&scalar);

        let compressed = point.compress();
        if let Some(decompressed) = compressed.decompress() {
            prop_assert_eq!(point, decompressed);
        }
    }

    #[test]
    fn scalar_mult_distributive_over_addition(
        a_bytes in any::<[u8; 32]>(),
        b_bytes in any::<[u8; 32]>(),
        s_bytes in any::<[u8; 32]>()
    ) {
        let a = Scalar::from_bytes_mod_order(a_bytes);
        let b = Scalar::from_bytes_mod_order(b_bytes);
        let s = Scalar::from_bytes_mod_order(s_bytes);

        let a_point = EdwardsPoint::mul_base(&a);
        let b_point = EdwardsPoint::mul_base(&b);

        // s * (A + B) = s * A + s * B
        let lhs = &(&a_point + &b_point) * &s;
        let rhs = &(&a_point * &s) + &(&b_point * &s);

        prop_assert_eq!(lhs, rhs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_properties() {
        // Run some basic property tests to ensure the framework works
        let a = Scalar::from_bytes_mod_order([1; 32]);
        let b = Scalar::from_bytes_mod_order([2; 32]);

        // Commutativity
        assert_eq!(&a + &b, &b + &a);
        assert_eq!(&a * &b, &b * &a);

        // Identity elements
        assert_eq!(&a + &Scalar::ZERO, a);
        assert_eq!(&a * &Scalar::ONE, a);
    }
}