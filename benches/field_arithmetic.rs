use criterion::{black_box, criterion_group, criterion_main, Criterion, BatchSize};
use gcrypt::{FieldElement, Scalar};
use rand::rngs::OsRng;
use rand::RngCore;

fn bench_field_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_add");
    let mut rng = OsRng;
    
    group.bench_function("gcrypt", |b| {
        b.iter_batched(
            || {
                let mut bytes_a = [0u8; 32];
                let mut bytes_b = [0u8; 32];
                rng.fill_bytes(&mut bytes_a);
                rng.fill_bytes(&mut bytes_b);
                (
                    FieldElement::from_bytes(&bytes_a),
                    FieldElement::from_bytes(&bytes_b),
                )
            },
            |(a, b)| black_box(&a + &b),
            BatchSize::SmallInput,
        );
    });
    
    #[cfg(feature = "comparison")]
    {
        use curve25519_dalek::field::FieldElement as DalekFieldElement;
        
        group.bench_function("curve25519-dalek", |b| {
            b.iter_batched(
                || {
                    let mut bytes_a = [0u8; 32];
                    let mut bytes_b = [0u8; 32];
                    rng.fill_bytes(&mut bytes_a);
                    rng.fill_bytes(&mut bytes_b);
                    (
                        DalekFieldElement::from_bytes(&bytes_a),
                        DalekFieldElement::from_bytes(&bytes_b),
                    )
                },
                |(a, b)| black_box(&a + &b),
                BatchSize::SmallInput,
            );
        });
    }
    
    group.finish();
}

fn bench_field_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_mul");
    let mut rng = OsRng;
    
    group.bench_function("gcrypt", |b| {
        b.iter_batched(
            || {
                let mut bytes_a = [0u8; 32];
                let mut bytes_b = [0u8; 32];
                rng.fill_bytes(&mut bytes_a);
                rng.fill_bytes(&mut bytes_b);
                (
                    FieldElement::from_bytes(&bytes_a),
                    FieldElement::from_bytes(&bytes_b),
                )
            },
            |(a, b)| black_box(&a * &b),
            BatchSize::SmallInput,
        );
    });
    
    #[cfg(feature = "comparison")]
    {
        use curve25519_dalek::field::FieldElement as DalekFieldElement;
        
        group.bench_function("curve25519-dalek", |b| {
            b.iter_batched(
                || {
                    let mut bytes_a = [0u8; 32];
                    let mut bytes_b = [0u8; 32];
                    rng.fill_bytes(&mut bytes_a);
                    rng.fill_bytes(&mut bytes_b);
                    (
                        DalekFieldElement::from_bytes(&bytes_a),
                        DalekFieldElement::from_bytes(&bytes_b),
                    )
                },
                |(a, b)| black_box(&a * &b),
                BatchSize::SmallInput,
            );
        });
    }
    
    group.finish();
}

fn bench_field_square(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_square");
    let mut rng = OsRng;
    
    group.bench_function("gcrypt", |b| {
        b.iter_batched(
            || {
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                FieldElement::from_bytes(&bytes)
            },
            |a| black_box(a.square()),
            BatchSize::SmallInput,
        );
    });
    
    #[cfg(feature = "comparison")]
    {
        use curve25519_dalek::field::FieldElement as DalekFieldElement;
        
        group.bench_function("curve25519-dalek", |b| {
            b.iter_batched(
                || {
                    let mut bytes = [0u8; 32];
                    rng.fill_bytes(&mut bytes);
                    DalekFieldElement::from_bytes(&bytes)
                },
                |a| black_box(a.square()),
                BatchSize::SmallInput,
            );
        });
    }
    
    group.finish();
}

fn bench_field_inversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_invert");
    let mut rng = OsRng;
    
    group.bench_function("gcrypt", |b| {
        b.iter_batched(
            || {
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                bytes[0] |= 1; // Ensure non-zero
                FieldElement::from_bytes(&bytes)
            },
            |a| black_box(a.invert()),
            BatchSize::SmallInput,
        );
    });
    
    #[cfg(feature = "comparison")]
    {
        use curve25519_dalek::field::FieldElement as DalekFieldElement;
        
        group.bench_function("curve25519-dalek", |b| {
            b.iter_batched(
                || {
                    let mut bytes = [0u8; 32];
                    rng.fill_bytes(&mut bytes);
                    bytes[0] |= 1; // Ensure non-zero
                    DalekFieldElement::from_bytes(&bytes)
                },
                |a| black_box(a.invert()),
                BatchSize::SmallInput,
            );
        });
    }
    
    group.finish();
}

fn bench_scalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar_mul");
    let mut rng = OsRng;
    
    group.bench_function("gcrypt", |b| {
        b.iter_batched(
            || {
                let mut bytes_a = [0u8; 32];
                let mut bytes_b = [0u8; 32];
                rng.fill_bytes(&mut bytes_a);
                rng.fill_bytes(&mut bytes_b);
                (
                    Scalar::from_bytes_mod_order(&bytes_a),
                    Scalar::from_bytes_mod_order(&bytes_b),
                )
            },
            |(a, b)| black_box(&a * &b),
            BatchSize::SmallInput,
        );
    });
    
    #[cfg(feature = "comparison")]
    {
        use curve25519_dalek::scalar::Scalar as DalekScalar;
        
        group.bench_function("curve25519-dalek", |b| {
            b.iter_batched(
                || {
                    let mut bytes_a = [0u8; 32];
                    let mut bytes_b = [0u8; 32];
                    rng.fill_bytes(&mut bytes_a);
                    rng.fill_bytes(&mut bytes_b);
                    (
                        DalekScalar::from_bytes_mod_order(bytes_a),
                        DalekScalar::from_bytes_mod_order(bytes_b),
                    )
                },
                |(a, b)| black_box(&a * &b),
                BatchSize::SmallInput,
            );
        });
    }
    
    group.finish();
}

fn bench_scalar_inversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar_invert");
    let mut rng = OsRng;
    
    group.bench_function("gcrypt", |b| {
        b.iter_batched(
            || {
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                bytes[0] |= 1; // Ensure non-zero
                Scalar::from_bytes_mod_order(&bytes)
            },
            |a| black_box(a.invert()),
            BatchSize::SmallInput,
        );
    });
    
    #[cfg(feature = "comparison")]
    {
        use curve25519_dalek::scalar::Scalar as DalekScalar;
        
        group.bench_function("curve25519-dalek", |b| {
            b.iter_batched(
                || {
                    let mut bytes = [0u8; 32];
                    rng.fill_bytes(&mut bytes);
                    bytes[0] |= 1; // Ensure non-zero
                    DalekScalar::from_bytes_mod_order(bytes)
                },
                |a| black_box(a.invert()),
                BatchSize::SmallInput,
            );
        });
    }
    
    group.finish();
}

#[cfg(feature = "simd")]
fn bench_simd_operations(c: &mut Criterion) {
    use gcrypt::backend::simd_avx2::Avx2FieldElement;
    
    let mut group = c.benchmark_group("simd_field_ops");
    let mut rng = OsRng;
    
    // SIMD field multiplication (4-way parallel)
    group.bench_function("gcrypt_avx2_mul_4way", |b| {
        b.iter_batched(
            || {
                let mut elements = Vec::new();
                for _ in 0..8 {
                    let mut bytes = [0u8; 32];
                    rng.fill_bytes(&mut bytes);
                    elements.push(FieldElement::from_bytes(&bytes));
                }
                elements
            },
            |elements| {
                let a = Avx2FieldElement::from_field_elements(&elements[0..4]);
                let b = Avx2FieldElement::from_field_elements(&elements[4..8]);
                black_box(a.mul(&b))
            },
            BatchSize::SmallInput,
        );
    });
    
    // Compare to serial operations
    group.bench_function("gcrypt_serial_mul_4x", |b| {
        b.iter_batched(
            || {
                let mut elements = Vec::new();
                for _ in 0..8 {
                    let mut bytes = [0u8; 32];
                    rng.fill_bytes(&mut bytes);
                    elements.push(FieldElement::from_bytes(&bytes));
                }
                elements
            },
            |elements| {
                let mut results = Vec::new();
                for i in 0..4 {
                    results.push(&elements[i] * &elements[i + 4]);
                }
                black_box(results)
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_field_addition,
    bench_field_multiplication,
    bench_field_square,
    bench_field_inversion,
    bench_scalar_multiplication,
    bench_scalar_inversion,
    #[cfg(feature = "simd")]
    bench_simd_operations
);
criterion_main!(benches);