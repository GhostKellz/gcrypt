#![no_main]

use libfuzzer_sys::fuzz_target;
use gcrypt::Scalar;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    let mut a_bytes = [0u8; 32];
    let mut b_bytes = [0u8; 32];

    a_bytes.copy_from_slice(&data[..32]);
    b_bytes.copy_from_slice(&data[32..64]);

    let a = Scalar::from_bytes_mod_order(a_bytes);
    let b = Scalar::from_bytes_mod_order(b_bytes);

    // Test arithmetic operations don't panic
    let _ = &a + &b;
    let _ = &a - &b;
    let _ = &a * &b;
    let _ = -&a;

    // Test serialization roundtrip
    let a_bytes_out = a.to_bytes();
    let a_reconstructed = Scalar::from_bytes_mod_order(a_bytes_out);
    assert_eq!(a, a_reconstructed);

    // Test commutativity
    assert_eq!(&a + &b, &b + &a);
    assert_eq!(&a * &b, &b * &a);

    // Test associativity with zero and one
    assert_eq!(&a + &Scalar::ZERO, a);
    assert_eq!(&a * &Scalar::ONE, a);
});