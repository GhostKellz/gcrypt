use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use gcrypt::protocols::X25519;
use rand::rngs::OsRng;

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519_keygen");
    
    group.bench_function("gcrypt", |b| {
        let mut rng = OsRng;
        b.iter(|| {
            let secret_key = X25519::SecretKey::generate(&mut rng);
            black_box(secret_key);
        });
    });
    
    #[cfg(feature = "comparison")]
    {
        use x25519_dalek::{EphemeralSecret, PublicKey};
        group.bench_function("x25519-dalek", |b| {
            let mut rng = OsRng;
            b.iter(|| {
                let secret = EphemeralSecret::new(&mut rng);
                let public = PublicKey::from(&secret);
                black_box((secret, public));
            });
        });
    }
    
    group.finish();
}

fn bench_diffie_hellman(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519_dh");
    let mut rng = OsRng;
    
    // gcrypt
    let alice_secret = X25519::SecretKey::generate(&mut rng);
    let bob_secret = X25519::SecretKey::generate(&mut rng);
    let bob_public = bob_secret.public_key();
    
    group.bench_function("gcrypt", |b| {
        b.iter(|| {
            let shared = alice_secret.diffie_hellman(&bob_public).unwrap();
            black_box(shared);
        });
    });
    
    #[cfg(feature = "comparison")]
    {
        use x25519_dalek::{StaticSecret, PublicKey};
        let alice_secret_dalek = StaticSecret::new(&mut rng);
        let bob_secret_dalek = StaticSecret::new(&mut rng);
        let bob_public_dalek = PublicKey::from(&bob_secret_dalek);
        
        group.bench_function("x25519-dalek", |b| {
            b.iter(|| {
                let shared = alice_secret_dalek.diffie_hellman(&bob_public_dalek);
                black_box(shared);
            });
        });
    }
    
    #[cfg(feature = "comparison")]
    {
        use sodiumoxide::crypto::box_;
        sodiumoxide::init().unwrap();
        
        let (alice_pk, alice_sk) = box_::gen_keypair();
        let (bob_pk, bob_sk) = box_::gen_keypair();
        
        group.bench_function("libsodium", |b| {
            b.iter(|| {
                let shared = box_::precompute(&bob_pk, &alice_sk);
                black_box(shared);
            });
        });
    }
    
    group.finish();
}

fn bench_ephemeral_exchange(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519_ephemeral");
    let mut rng = OsRng;
    
    let bob_secret = X25519::SecretKey::generate(&mut rng);
    let bob_public = bob_secret.public_key();
    
    group.bench_function("gcrypt", |b| {
        b.iter(|| {
            let (ephemeral_public, shared_secret) = X25519::ephemeral_exchange(&mut rng, &bob_public).unwrap();
            black_box((ephemeral_public, shared_secret));
        });
    });
    
    #[cfg(feature = "comparison")]
    {
        use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
        let bob_secret_dalek = StaticSecret::new(&mut rng);
        let bob_public_dalek = PublicKey::from(&bob_secret_dalek);
        
        group.bench_function("x25519-dalek", |b| {
            b.iter(|| {
                let ephemeral_secret = EphemeralSecret::new(&mut rng);
                let ephemeral_public = PublicKey::from(&ephemeral_secret);
                let shared = ephemeral_secret.diffie_hellman(&bob_public_dalek);
                black_box((ephemeral_public, shared));
            });
        });
    }
    
    group.finish();
}

fn bench_batch_key_exchange(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519_batch");
    let mut rng = OsRng;
    
    for batch_size in [8, 16, 32, 64, 128].iter() {
        // Prepare keys
        let mut alice_secrets = Vec::new();
        let mut bob_publics = Vec::new();
        
        for _ in 0..*batch_size {
            alice_secrets.push(X25519::SecretKey::generate(&mut rng));
            let bob_secret = X25519::SecretKey::generate(&mut rng);
            bob_publics.push(bob_secret.public_key());
        }
        
        group.bench_with_input(BenchmarkId::new("gcrypt", batch_size), batch_size, |b, _| {
            b.iter(|| {
                let mut shared_secrets = Vec::new();
                for (alice_secret, bob_public) in alice_secrets.iter().zip(&bob_publics) {
                    let shared = alice_secret.diffie_hellman(bob_public).unwrap();
                    shared_secrets.push(shared);
                }
                black_box(shared_secrets);
            });
        });
        
        #[cfg(feature = "comparison")]
        {
            use x25519_dalek::{StaticSecret, PublicKey};
            
            let mut alice_secrets_dalek = Vec::new();
            let mut bob_publics_dalek = Vec::new();
            
            for _ in 0..*batch_size {
                alice_secrets_dalek.push(StaticSecret::new(&mut rng));
                let bob_secret = StaticSecret::new(&mut rng);
                bob_publics_dalek.push(PublicKey::from(&bob_secret));
            }
            
            group.bench_with_input(BenchmarkId::new("x25519-dalek", batch_size), batch_size, |b, _| {
                b.iter(|| {
                    let mut shared_secrets = Vec::new();
                    for (alice_secret, bob_public) in alice_secrets_dalek.iter().zip(&bob_publics_dalek) {
                        let shared = alice_secret.diffie_hellman(bob_public);
                        shared_secrets.push(shared);
                    }
                    black_box(shared_secrets);
                });
            });
        }
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_diffie_hellman,
    bench_ephemeral_exchange,
    bench_batch_key_exchange
);
criterion_main!(benches);