use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use gcrypt::protocols::Ed25519;
use rand::rngs::OsRng;

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_keygen");
    
    group.bench_function("gcrypt", |b| {
        let mut rng = OsRng;
        b.iter(|| {
            let secret_key = Ed25519::SecretKey::generate(&mut rng);
            black_box(secret_key);
        });
    });
    
    #[cfg(feature = "comparison")]
    {
        use ed25519_dalek::Keypair;
        group.bench_function("ed25519-dalek", |b| {
            let mut rng = OsRng;
            b.iter(|| {
                let keypair = Keypair::generate(&mut rng);
                black_box(keypair);
            });
        });
    }
    
    group.finish();
}

fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_sign");
    let mut rng = OsRng;
    
    // Test different message sizes
    for size in [32, 64, 128, 256, 512, 1024, 4096].iter() {
        let message = vec![0u8; *size];
        
        // gcrypt signing
        let secret_key = Ed25519::SecretKey::generate(&mut rng);
        group.bench_with_input(BenchmarkId::new("gcrypt", size), size, |b, _| {
            b.iter(|| {
                let signature = secret_key.sign(&message, &mut rng);
                black_box(signature);
            });
        });
        
        // gcrypt deterministic signing
        group.bench_with_input(BenchmarkId::new("gcrypt_deterministic", size), size, |b, _| {
            b.iter(|| {
                let signature = secret_key.sign_deterministic(&message);
                black_box(signature);
            });
        });
        
        #[cfg(feature = "comparison")]
        {
            use ed25519_dalek::{Keypair, Signer};
            let keypair = Keypair::generate(&mut rng);
            
            group.bench_with_input(BenchmarkId::new("ed25519-dalek", size), size, |b, _| {
                b.iter(|| {
                    let signature = keypair.sign(&message);
                    black_box(signature);
                });
            });
        }
    }
    
    group.finish();
}

fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_verify");
    let mut rng = OsRng;
    
    for size in [32, 64, 128, 256, 512, 1024, 4096].iter() {
        let message = vec![0u8; *size];
        
        // gcrypt verification
        let secret_key = Ed25519::SecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();
        let signature = secret_key.sign(&message, &mut rng);
        
        group.bench_with_input(BenchmarkId::new("gcrypt", size), size, |b, _| {
            b.iter(|| {
                let result = public_key.verify(&message, &signature);
                black_box(result);
            });
        });
        
        #[cfg(feature = "comparison")]
        {
            use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
            let keypair = Keypair::generate(&mut rng);
            let sig = keypair.sign(&message);
            
            group.bench_with_input(BenchmarkId::new("ed25519-dalek", size), size, |b, _| {
                b.iter(|| {
                    let result = keypair.verify(&message, &sig);
                    black_box(result);
                });
            });
        }
    }
    
    group.finish();
}

fn bench_batch_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_batch_verify");
    let mut rng = OsRng;
    
    for batch_size in [8, 16, 32, 64, 128].iter() {
        let message = b"Batch verification test message";
        
        // Prepare gcrypt batch
        let mut messages = Vec::new();
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        
        for _ in 0..*batch_size {
            let secret_key = Ed25519::SecretKey::generate(&mut rng);
            let public_key = secret_key.public_key();
            let signature = secret_key.sign(message, &mut rng);
            
            messages.push(message.as_slice());
            signatures.push(signature);
            public_keys.push(public_key);
        }
        
        group.bench_with_input(BenchmarkId::new("gcrypt", batch_size), batch_size, |b, _| {
            b.iter(|| {
                let result = Ed25519::verify_batch(&messages, &signatures, &public_keys);
                black_box(result);
            });
        });
        
        // Individual verification for comparison
        group.bench_with_input(BenchmarkId::new("gcrypt_individual", batch_size), batch_size, |b, _| {
            b.iter(|| {
                let mut all_valid = true;
                for ((msg, sig), pk) in messages.iter().zip(&signatures).zip(&public_keys) {
                    if pk.verify(msg, sig).is_err() {
                        all_valid = false;
                        break;
                    }
                }
                black_box(all_valid);
            });
        });
        
        #[cfg(feature = "comparison")]
        {
            use ed25519_dalek::{Keypair, Signer, Verifier};
            
            let mut dalek_messages = Vec::new();
            let mut dalek_signatures = Vec::new();
            let mut dalek_public_keys = Vec::new();
            
            for _ in 0..*batch_size {
                let keypair = Keypair::generate(&mut rng);
                let signature = keypair.sign(message);
                
                dalek_messages.push(message);
                dalek_signatures.push(signature);
                dalek_public_keys.push(keypair.public);
            }
            
            group.bench_with_input(BenchmarkId::new("ed25519-dalek_batch", batch_size), batch_size, |b, _| {
                use ed25519_dalek::verify_batch;
                b.iter(|| {
                    let result = verify_batch(&dalek_messages, &dalek_signatures, &dalek_public_keys);
                    black_box(result);
                });
            });
        }
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_signing,
    bench_verification,
    bench_batch_verification
);
criterion_main!(benches);