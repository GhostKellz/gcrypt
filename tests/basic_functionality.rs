//! Basic functionality tests for gcrypt
//! 
//! These tests verify that core operations work correctly

use gcrypt::{Scalar, FieldElement};

#[test]
fn test_scalar_arithmetic() {
    let zero = Scalar::ZERO;
    let one = Scalar::ONE;
    
    // Test basic arithmetic
    let sum = &zero + &one;
    assert_eq!(sum.to_bytes()[0], 1);
    
    let diff = &one - &zero;
    assert_eq!(diff.to_bytes()[0], 1);
}

#[test]
fn test_field_arithmetic() {
    let zero = FieldElement::ZERO;
    let one = FieldElement::ONE;
    
    // Test basic arithmetic
    let sum = &zero + &one;
    assert_eq!(sum.to_bytes()[0], 1);
    
    // Test field operations
    let product = &one * &one;
    assert_eq!(product.to_bytes()[0], 1);
}

#[test]
fn test_scalar_constants() {
    assert!(Scalar::ZERO.is_zero());
    assert!(!Scalar::ONE.is_zero());
}

#[test]
fn test_field_constants() {
    let zero = FieldElement::ZERO;
    let one = FieldElement::ONE;
    
    assert!(bool::from(zero.is_zero()));
    assert!(!bool::from(one.is_zero()));
}

#[cfg(feature = "rand_core")]
#[test]
fn test_random_scalar() {
    use rand::thread_rng;
    
    let scalar1 = Scalar::random(&mut thread_rng());
    let scalar2 = Scalar::random(&mut thread_rng());
    
    // They should be different (with overwhelming probability)
    assert_ne!(scalar1.to_bytes(), scalar2.to_bytes());
}