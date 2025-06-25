//! RFC test vectors for Ed25519 and X25519
//!
//! Test vectors from RFC 7748 (X25519) and RFC 8032 (Ed25519)

use gcrypt::{Scalar, EdwardsPoint, MontgomeryPoint};

/// Test vectors from RFC 8032 Section 7.1
#[test]
fn test_ed25519_rfc8032_vectors() {
    // Test case 1
    let secret_key = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let public_key_expected = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    
    let scalar = Scalar::from_bytes_mod_order_wide(&{
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&secret_key);
        bytes
    });
    
    let public_key = EdwardsPoint::mul_base(&scalar);
    let public_key_compressed = public_key.compress();
    
    assert_eq!(public_key_compressed.0, public_key_expected.as_slice());
}

/// Test vectors from RFC 7748 Section 5.2
#[test]  
fn test_x25519_rfc7748_vectors() {
    // Test case 1: Alice's key pair
    let alice_private = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    ];
    
    let alice_public_expected = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    ];
    
    // Generate Alice's public key
    let alice_public = MontgomeryPoint::mul_base_clamped(alice_private);
    assert_eq!(alice_public.to_bytes(), alice_public_expected);
    
    // Test case 2: Bob's key pair
    let bob_private = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
    ];
    
    let bob_public_expected = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    ];
    
    // Generate Bob's public key
    let bob_public = MontgomeryPoint::mul_base_clamped(bob_private);
    assert_eq!(bob_public.to_bytes(), bob_public_expected);
    
    // Test shared secret computation
    let shared_secret_expected = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
    ];
    
    // Compute shared secret from both sides
    let shared_alice = crate::montgomery::x25519(alice_private, bob_public.to_bytes());
    let shared_bob = crate::montgomery::x25519(bob_private, alice_public.to_bytes());
    
    assert_eq!(shared_alice, shared_secret_expected);
    assert_eq!(shared_bob, shared_secret_expected);
    assert_eq!(shared_alice, shared_bob);
}

/// Test vectors for scalar multiplication base point
#[test]
fn test_scalar_mult_basepoint() {
    // Small scalar multiplication tests
    let one = Scalar::ONE;
    let basepoint = EdwardsPoint::basepoint();
    
    // [1]B should equal B
    let result = EdwardsPoint::mul_base(&one);
    assert_eq!(result, basepoint);
    
    // [2]B should equal B + B
    let two_bytes = [2u8; 32];
    let two = Scalar::from_bytes_mod_order(two_bytes);
    let result_2 = EdwardsPoint::mul_base(&two);
    let expected_2 = &basepoint + &basepoint;
    assert_eq!(result_2, expected_2);
}

/// Test field element constants match expected values
#[test]
fn test_field_constants() {
    use gcrypt::FieldElement;
    
    // Test that field zero is actually zero
    let zero = FieldElement::ZERO;
    assert_eq!(zero.to_bytes()[0], 0);
    
    // Test that field one is actually one
    let one = FieldElement::ONE;
    assert_eq!(one.to_bytes()[0], 1);
    
    // Test basic field arithmetic
    let two = &one + &one;
    assert_eq!(two.to_bytes()[0], 2);
}

/// Test curve equation and point validation
#[test]
fn test_curve_equation() {
    let basepoint = EdwardsPoint::basepoint();
    
    // Basepoint should be on the curve
    assert!(bool::from(basepoint.is_on_curve()));
    
    // Identity should be on the curve
    let identity = EdwardsPoint::identity();
    assert!(bool::from(identity.is_on_curve()));
    
    // Random point operations should stay on curve
    let doubled = basepoint.double();
    assert!(bool::from(doubled.is_on_curve()));
    
    let added = &basepoint + &doubled;
    assert!(bool::from(added.is_on_curve()));
}