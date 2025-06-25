use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, BatchSize};
use gcrypt::{EdwardsPoint, Scalar};
use rand::rngs::OsRng;

fn bench_point_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_add");
    let mut rng = OsRng;
    
    group.bench_function("gcrypt", |b| {
        b.iter_batched(
            || {
                let scalar_a = Scalar::random(&mut rng);
                let scalar_b = Scalar::random(&mut rng);
                (
                    EdwardsPoint::mul_base(&scalar_a),
                    EdwardsPoint::mul_base(&scalar_b),
                )
            },
            |(a, b)| black_box(&a + &b),
            BatchSize::SmallInput,
        );
    });
    
    #[cfg(feature = "comparison")]
    {
        use curve25519_dalek::edwards::EdwardsPoint as DalekEdwardsPoint;
        use curve25519_dalek::scalar::Scalar as DalekScalar;
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        
        group.bench_function("curve25519-dalek", |b| {
            b.iter_batched(
                || {
                    let scalar_a = DalekScalar::random(&mut rng);
                    let scalar_b = DalekScalar::random(&mut rng);
                    (
                        &ED25519_BASEPOINT_TABLE * &scalar_a,
                        &ED25519_BASEPOINT_TABLE * &scalar_b,
                    )
                },
                |(a, b)| black_box(&a + &b),
                BatchSize::SmallInput,
            );
        });
    }
    
    group.finish();
}

fn bench_point_doubling(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_double");
    let mut rng = OsRng;
    
    group.bench_function("gcrypt", |b| {
        b.iter_batched(
            || {
                let scalar = Scalar::random(&mut rng);
                EdwardsPoint::mul_base(&scalar)
            },
            |p| black_box(p.double()),
            BatchSize::SmallInput,
        );
    });
    
    #[cfg(feature = "comparison")]
    {
        use curve25519_dalek::edwards::EdwardsPoint as DalekEdwardsPoint;
        use curve25519_dalek::scalar::Scalar as DalekScalar;
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        
        group.bench_function("curve25519-dalek", |b| {
            b.iter_batched(
                || {
                    let scalar = DalekScalar::random(&mut rng);
                    &ED25519_BASEPOINT_TABLE * &scalar
                },
                |p| black_box(p.double()),
                BatchSize::SmallInput,
            );
        });
    }
    
    group.finish();
}

fn bench_scalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_scalar_mul");
    let mut rng = OsRng;
    
    // Test base point multiplication
    group.bench_function("gcrypt_basepoint", |b| {
        b.iter_batched(
            || Scalar::random(&mut rng),
            |s| black_box(EdwardsPoint::mul_base(&s)),
            BatchSize::SmallInput,
        );
    });
    
    // Test arbitrary point multiplication
    let point = EdwardsPoint::mul_base(&Scalar::random(&mut rng));
    group.bench_function("gcrypt_variable", |b| {
        b.iter_batched(
            || Scalar::random(&mut rng),
            |s| black_box(&point * &s),
            BatchSize::SmallInput,
        );
    });
    
    #[cfg(feature = "comparison")]
    {
        use curve25519_dalek::edwards::EdwardsPoint as DalekEdwardsPoint;
        use curve25519_dalek::scalar::Scalar as DalekScalar;
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        
        group.bench_function("curve25519-dalek_basepoint", |b| {
            b.iter_batched(
                || DalekScalar::random(&mut rng),
                |s| black_box(&ED25519_BASEPOINT_TABLE * &s),
                BatchSize::SmallInput,
            );
        });
        
        let dalek_point = &ED25519_BASEPOINT_TABLE * &DalekScalar::random(&mut rng);
        group.bench_function("curve25519-dalek_variable", |b| {
            b.iter_batched(
                || DalekScalar::random(&mut rng),
                |s| black_box(&dalek_point * &s),
                BatchSize::SmallInput,
            );
        });
    }
    
    group.finish();
}

fn bench_multiscalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiscalar_mul");
    let mut rng = OsRng;
    
    for size in [2, 4, 8, 16, 32, 64, 128].iter() {
        // Prepare gcrypt data
        let scalars: Vec<Scalar> = (0..*size).map(|_| Scalar::random(&mut rng)).collect();
        let points: Vec<EdwardsPoint> = scalars.iter()
            .map(|s| EdwardsPoint::mul_base(s))
            .collect();
        
        group.bench_with_input(BenchmarkId::new("gcrypt", size), size, |b, _| {
            b.iter(|| {
                let result = EdwardsPoint::multiscalar_mul(&scalars, &points);
                black_box(result);
            });
        });
        
        // Compare to individual operations
        group.bench_with_input(BenchmarkId::new("gcrypt_individual", size), size, |b, _| {
            b.iter(|| {
                let mut result = EdwardsPoint::IDENTITY;
                for (scalar, point) in scalars.iter().zip(&points) {
                    result = &result + &(point * scalar);
                }
                black_box(result);
            });
        });
        
        #[cfg(feature = "comparison")]
        {
            use curve25519_dalek::edwards::EdwardsPoint as DalekEdwardsPoint;
            use curve25519_dalek::scalar::Scalar as DalekScalar;
            use curve25519_dalek::traits::MultiscalarMul;
            
            let dalek_scalars: Vec<DalekScalar> = (0..*size)
                .map(|_| DalekScalar::random(&mut rng))
                .collect();
            let dalek_points: Vec<DalekEdwardsPoint> = dalek_scalars.iter()
                .map(|s| DalekEdwardsPoint::mul_base(s))
                .collect();
            
            group.bench_with_input(BenchmarkId::new("curve25519-dalek", size), size, |b, _| {
                b.iter(|| {
                    let result = DalekEdwardsPoint::multiscalar_mul(&dalek_scalars, &dalek_points);
                    black_box(result);
                });
            });
        }
    }
    
    group.finish();
}

fn bench_point_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_compress");
    let mut rng = OsRng;
    
    group.bench_function("gcrypt_compress", |b| {
        b.iter_batched(
            || {
                let scalar = Scalar::random(&mut rng);
                EdwardsPoint::mul_base(&scalar)
            },
            |p| black_box(p.compress()),
            BatchSize::SmallInput,
        );
    });
    
    group.bench_function("gcrypt_decompress", |b| {
        b.iter_batched(
            || {
                let scalar = Scalar::random(&mut rng);
                let point = EdwardsPoint::mul_base(&scalar);
                point.compress()
            },
            |c| black_box(c.decompress()),
            BatchSize::SmallInput,
        );
    });
    
    #[cfg(feature = "comparison")]
    {
        use curve25519_dalek::edwards::{EdwardsPoint as DalekEdwardsPoint, CompressedEdwardsY};
        use curve25519_dalek::scalar::Scalar as DalekScalar;
        
        group.bench_function("curve25519-dalek_compress", |b| {
            b.iter_batched(
                || {
                    let scalar = DalekScalar::random(&mut rng);
                    DalekEdwardsPoint::mul_base(&scalar)
                },
                |p| black_box(p.compress()),
                BatchSize::SmallInput,
            );
        });
        
        group.bench_function("curve25519-dalek_decompress", |b| {
            b.iter_batched(
                || {
                    let scalar = DalekScalar::random(&mut rng);
                    let point = DalekEdwardsPoint::mul_base(&scalar);
                    point.compress()
                },
                |c| black_box(c.decompress()),
                BatchSize::SmallInput,
            );
        });
    }
    
    group.finish();
}

#[cfg(feature = "precomputed-tables")]
fn bench_precomputed_tables(c: &mut Criterion) {
    let mut group = c.benchmark_group("precomputed_basepoint");
    let mut rng = OsRng;
    
    // Create precomputed table
    let precomputed = EdwardsPoint::precompute_base();
    
    group.bench_function("gcrypt_precomputed", |b| {
        b.iter_batched(
            || Scalar::random(&mut rng),
            |s| black_box(precomputed.mul(&s)),
            BatchSize::SmallInput,
        );
    });
    
    // Compare to regular multiplication
    group.bench_function("gcrypt_regular", |b| {
        b.iter_batched(
            || Scalar::random(&mut rng),
            |s| black_box(EdwardsPoint::mul_base(&s)),
            BatchSize::SmallInput,
        );
    });
    
    #[cfg(feature = "comparison")]
    {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar as DalekScalar;
        
        group.bench_function("curve25519-dalek_table", |b| {
            b.iter_batched(
                || DalekScalar::random(&mut rng),
                |s| black_box(&ED25519_BASEPOINT_TABLE * &s),
                BatchSize::SmallInput,
            );
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_point_addition,
    bench_point_doubling,
    bench_scalar_multiplication,
    bench_multiscalar_multiplication,
    bench_point_compression,
    #[cfg(feature = "precomputed-tables")]
    bench_precomputed_tables
);
criterion_main!(benches);