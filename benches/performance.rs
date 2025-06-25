//! Performance benchmarks for gcrypt
//!
//! This file contains benchmarks to measure the performance
//! of core cryptographic operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gcrypt::{Scalar, FieldElement, EdwardsPoint};

fn scalar_arithmetic_benchmarks(c: &mut Criterion) {
    let a = Scalar::from_bytes_mod_order([1u8; 32]);
    let b = Scalar::from_bytes_mod_order([2u8; 32]);
    
    c.bench_function("scalar_add", |bench| {
        bench.iter(|| {
            let result = black_box(&a) + black_box(&b);
            black_box(result)
        })
    });
    
    c.bench_function("scalar_mul", |bench| {
        bench.iter(|| {
            let result = black_box(&a) * black_box(&b);
            black_box(result)
        })
    });
    
    c.bench_function("scalar_invert", |bench| {
        bench.iter(|| {
            let result = black_box(a).invert();
            black_box(result)
        })
    });
}

fn field_arithmetic_benchmarks(c: &mut Criterion) {
    let a = FieldElement::from_bytes(&[1u8; 32]);
    let b = FieldElement::from_bytes(&[2u8; 32]);
    
    c.bench_function("field_add", |bench| {
        bench.iter(|| {
            let result = black_box(&a) + black_box(&b);
            black_box(result)
        })
    });
    
    c.bench_function("field_mul", |bench| {
        bench.iter(|| {
            let result = black_box(&a) * black_box(&b);
            black_box(result)
        })
    });
    
    c.bench_function("field_square", |bench| {
        bench.iter(|| {
            let result = black_box(a).square();
            black_box(result)
        })
    });
    
    c.bench_function("field_invert", |bench| {
        bench.iter(|| {
            let result = black_box(a).invert();
            black_box(result)
        })
    });
}

fn point_operation_benchmarks(c: &mut Criterion) {
    let basepoint = EdwardsPoint::basepoint();
    let scalar = Scalar::from_bytes_mod_order([42u8; 32]);
    
    c.bench_function("point_double", |bench| {
        bench.iter(|| {
            let result = black_box(basepoint).double();
            black_box(result)
        })
    });
    
    c.bench_function("point_add", |bench| {
        bench.iter(|| {
            let result = black_box(&basepoint) + black_box(&basepoint);
            black_box(result)
        })
    });
    
    c.bench_function("scalar_mult_basepoint", |bench| {
        bench.iter(|| {
            let result = EdwardsPoint::mul_base(black_box(&scalar));
            black_box(result)
        })
    });
    
    c.bench_function("scalar_mult_variable", |bench| {
        bench.iter(|| {
            let result = black_box(&basepoint) * black_box(&scalar);
            black_box(result)
        })
    });
}

criterion_group!(
    benches,
    scalar_arithmetic_benchmarks,
    field_arithmetic_benchmarks,
    point_operation_benchmarks
);
criterion_main!(benches);