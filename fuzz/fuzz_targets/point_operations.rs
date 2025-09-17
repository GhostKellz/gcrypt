#![no_main]

use libfuzzer_sys::fuzz_target;
use gcrypt::{Scalar, EdwardsPoint, RistrettoPoint};

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    let mut a_bytes = [0u8; 32];
    let mut b_bytes = [0u8; 32];

    a_bytes.copy_from_slice(&data[..32]);
    b_bytes.copy_from_slice(&data[32..64]);

    let a_scalar = Scalar::from_bytes_mod_order(a_bytes);
    let b_scalar = Scalar::from_bytes_mod_order(b_bytes);

    // Test Edwards point operations
    let a_edwards = EdwardsPoint::mul_base(&a_scalar);
    let b_edwards = EdwardsPoint::mul_base(&b_scalar);

    let _ = &a_edwards + &b_edwards;
    let _ = &a_edwards - &b_edwards;
    let _ = &a_edwards * &a_scalar;
    let _ = a_edwards.double();

    // Test compression/decompression
    let compressed = a_edwards.compress();
    if let Some(decompressed) = compressed.decompress() {
        assert_eq!(a_edwards, decompressed);
    }

    // Test Ristretto point operations
    let a_ristretto = RistrettoPoint::mul_base(&a_scalar);
    let b_ristretto = RistrettoPoint::mul_base(&b_scalar);

    let _ = &a_ristretto + &b_ristretto;
    let _ = &a_ristretto - &b_ristretto;
    let _ = &a_ristretto * &a_scalar;

    // Test Ristretto compression/decompression
    let ristretto_compressed = a_ristretto.compress();
    if let Some(ristretto_decompressed) = ristretto_compressed.decompress() {
        assert_eq!(a_ristretto, ristretto_decompressed);
    }

    // Test commutativity
    assert_eq!(&a_edwards + &b_edwards, &b_edwards + &a_edwards);
    assert_eq!(&a_ristretto + &b_ristretto, &b_ristretto + &a_ristretto);
});