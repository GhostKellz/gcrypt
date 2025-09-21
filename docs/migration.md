# Migration Guide

This guide helps you migrate from other cryptographic libraries to gcrypt, with specific focus on curve25519-dalek and integration with the Ghostchain ecosystem.

## From curve25519-dalek

gcrypt provides a modern, blockchain-optimized alternative to curve25519-dalek with enhanced APIs and additional features.

### Basic Type Mapping

| curve25519-dalek | gcrypt | Notes |
|------------------|--------|-------|
| `curve25519_dalek::scalar::Scalar` | `gcrypt::Scalar` | Same underlying representation |
| `curve25519_dalek::edwards::EdwardsPoint` | `gcrypt::EdwardsPoint` | Enhanced API |
| `curve25519_dalek::montgomery::MontgomeryPoint` | `gcrypt::MontgomeryPoint` | X25519 support |
| `curve25519_dalek::ristretto::RistrettoPoint` | `gcrypt::RistrettoPoint` | Prime-order group |
| N/A | `gcrypt::FieldElement` | New field arithmetic type |

### API Migration Examples

#### Scalar Operations

**Before (curve25519-dalek):**
```rust
use curve25519_dalek::scalar::Scalar;

let s1 = Scalar::zero();
let s2 = Scalar::one();
let s3 = Scalar::from_bytes_mod_order(bytes);
let sum = s1 + s2;
let product = s1 * s2;
```

**After (gcrypt):**
```rust
use gcrypt::Scalar;

let s1 = Scalar::zero();
let s2 = Scalar::one();
let s3 = Scalar::from_bytes_mod_order(&bytes); // Note: now takes reference
let sum = &s1 + &s2; // Reference-based operations for better performance
let product = &s1 * &s2;
```

#### Edwards Point Operations

**Before:**
```rust
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;

let basepoint = ED25519_BASEPOINT_POINT;
let scalar = Scalar::from(42u64);
let point = scalar * basepoint;
```

**After:**
```rust
use gcrypt::{EdwardsPoint, Scalar};

let basepoint = EdwardsPoint::basepoint();
let scalar = Scalar::from_u64(42); // Cleaner API
let point = EdwardsPoint::mul_base(&scalar); // Optimized base multiplication
// Or alternatively:
let point = &basepoint * &scalar;
```

#### Point Compression

**Before:**
```rust
let compressed = point.compress();
let decompressed = compressed.decompress().unwrap();
```

**After:**
```rust
// Same API, but with better error handling
let compressed = point.compress();
let decompressed = compressed.decompress().unwrap();
```

#### X25519 Key Exchange

**Before:**
```rust
use curve25519_dalek::montgomery::MontgomeryPoint;

let scalar = Scalar::from_bytes_mod_order(secret_bytes);
let point = scalar * constants::X25519_BASEPOINT;
```

**After:**
```rust
use gcrypt::{MontgomeryPoint, montgomery::x25519};

// More convenient API
let secret_key = [0x77; 32];
let public_key = MontgomeryPoint::mul_base_clamped(secret_key);

// High-level X25519 function
let shared_secret = x25519(alice_secret, bob_public_bytes);
```

### Dependency Migration

**Before:**
```toml
[dependencies]
curve25519-dalek = "4.0"
ed25519-dalek = "2.0"
x25519-dalek = "2.0"
```

**After:**
```toml
[dependencies]
gcrypt = "0.1"
```

### Feature Flag Migration

**Before:**
```toml
curve25519-dalek = { version = "4.0", features = ["serde"] }
```

**After:**
```toml
gcrypt = { version = "0.1", features = ["serde", "batch-operations"] }
```

### Performance Improvements

gcrypt provides several performance enhancements:

1. **Batch Operations**: Process multiple signatures/scalars at once
2. **Hardware Acceleration**: Automatic SIMD utilization
3. **Parallel Processing**: Multi-core support for large batches

**Migration Example:**
```rust
// Before: Individual signature verification
for (pubkey, message, signature) in signatures {
    verify_signature(pubkey, message, signature)?;
}

// After: Batch verification
use gcrypt::batch::batch_signatures;

let all_valid = batch_signatures::verify_ed25519_batch(
    &public_keys,
    &messages,
    &signatures
)?;
```

## From RustCrypto Libraries

### From ed25519-dalek

**Before:**
```rust
use ed25519_dalek::{SigningKey, VerifyingKey, Signature};

let signing_key = SigningKey::generate(&mut rng);
let verifying_key = signing_key.verifying_key();
let signature = signing_key.sign(message);
let is_valid = verifying_key.verify(message, &signature).is_ok();
```

**After:**
```rust
use gcrypt::protocols::ed25519::{SecretKey, PublicKey, sign, verify};

let secret_key = SecretKey::generate(&mut rng);
let public_key = PublicKey::from(&secret_key);
let signature = sign(&secret_key, message);
let is_valid = verify(&public_key, message, &signature);
```

### From x25519-dalek

**Before:**
```rust
use x25519_dalek::{EphemeralSecret, PublicKey};

let alice_secret = EphemeralSecret::random_from_rng(&mut rng);
let alice_public = PublicKey::from(&alice_secret);
let shared_secret = alice_secret.diffie_hellman(&bob_public);
```

**After:**
```rust
use gcrypt::{Scalar, MontgomeryPoint, montgomery::x25519};

let alice_secret = Scalar::random(&mut rng);
let alice_public = MontgomeryPoint::mul_base(&alice_secret);
let shared_secret = x25519(alice_secret.to_bytes(), bob_public.to_bytes());
```

## Blockchain-Specific Migration

### Adding Ghostchain Features

If you're migrating a blockchain application, you can immediately benefit from gcrypt's blockchain-specific features:

#### GQUIC Transport (for Etherlink integration)

```rust
// Add to your network layer
use gcrypt::transport::{GquicTransport, GquicKeyExchange};

let transport = GquicTransport::new();
let session = GquicKeyExchange::derive_session_key(/* ... */)?;

// High-performance packet encryption
let encrypted = transport.encrypt_packet(&mut session, data, header)?;
```

#### Guardian Authentication (for service-to-service auth)

```rust
// Add to your API services
use gcrypt::guardian::{GuardianIssuer, GuardianVerifier};

// Issue tokens
let issuer = GuardianIssuer::new(authority_key);
let token = issuer.issue_token(user_did, permissions, 3600)?;

// Verify in middleware
let mut verifier = GuardianVerifier::new();
verifier.verify_permission(&token, "ghostd", "read")?;
```

#### ZK-Friendly Hashing (for privacy features)

```rust
// Replace SHA-256 with circuit-friendly hashes
use gcrypt::zk_hash::poseidon;

let inputs = vec![
    FieldElement::from_u64(amount),
    FieldElement::from_u64(nonce),
];
let commitment = poseidon::hash_many(&inputs)?;
```

#### Batch Operations (for high-throughput DeFi)

```rust
// Replace individual operations with batch processing
use gcrypt::batch::batch_signatures;

// Instead of:
// for signature in signatures { verify_individual(signature)?; }

// Use:
let all_valid = batch_signatures::verify_ed25519_batch(
    &public_keys,
    &messages,
    &signatures
)?;
```

## Common Migration Patterns

### Error Handling

**Before:**
```rust
// Various error types from different crates
use curve25519_dalek::errors::InternalError;
use ed25519_dalek::SignatureError;
```

**After:**
```rust
// Unified error handling
use gcrypt::error::GcryptError;

match operation() {
    Ok(result) => /* handle success */,
    Err(GcryptError::InvalidInput) => /* handle invalid input */,
    Err(GcryptError::VerificationFailed) => /* handle verification failure */,
    Err(e) => /* handle other errors */,
}
```

### Serialization

**Before:**
```rust
// Manual byte array handling
let bytes = scalar.to_bytes();
let restored = Scalar::from_bytes_mod_order(bytes);
```

**After:**
```rust
// Same low-level API, plus optional serde support
let bytes = scalar.to_bytes();
let restored = Scalar::from_bytes_mod_order(&bytes);

// With serde feature:
#[cfg(feature = "serde")]
{
    let json = serde_json::to_string(&scalar)?;
    let restored: Scalar = serde_json::from_str(&json)?;
}
```

### Random Number Generation

**Before:**
```rust
use rand::rngs::OsRng;
let mut rng = OsRng;
let scalar = Scalar::random(&mut rng);
```

**After:**
```rust
// Same API with rand_core feature
use rand::thread_rng;
let scalar = Scalar::random(&mut thread_rng());

// Or simpler for many use cases:
let scalar = Scalar::random(&mut rand::thread_rng());
```

## No-std Migration

gcrypt provides better no-std support than most alternatives:

**Before:**
```toml
curve25519-dalek = { version = "4.0", default-features = false }
```

**After:**
```toml
# No-std without allocation
gcrypt = { version = "0.1", default-features = false }

# No-std with allocation (enables batch operations)
gcrypt = { version = "0.1", default-features = false, features = ["alloc"] }

# No-std with specific features
gcrypt = {
    version = "0.1",
    default-features = false,
    features = ["alloc", "zk-hash", "batch-operations"]
}
```

## Testing Migration

### Unit Tests

**Before:**
```rust
#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn test_scalar_math() {
        let a = Scalar::from(5u64);
        let b = Scalar::from(3u64);
        assert_eq!(a + b, Scalar::from(8u64));
    }
}
```

**After:**
```rust
#[cfg(test)]
mod tests {
    use gcrypt::Scalar;

    #[test]
    fn test_scalar_math() {
        let a = Scalar::from_u64(5);
        let b = Scalar::from_u64(3);
        assert_eq!(&a + &b, Scalar::from_u64(8));
    }
}
```

### Integration Tests

gcrypt provides comprehensive test suites for the new features:

```rust
// Test Ghostchain-specific functionality
#[cfg(all(feature = "guardian-framework", feature = "gquic-transport"))]
mod ghostchain_tests {
    use gcrypt::guardian::*;
    use gcrypt::transport::*;

    #[test]
    fn test_end_to_end_auth() {
        // Test authentication flow
    }

    #[test]
    fn test_transport_integration() {
        // Test GQUIC transport
    }
}
```

## Performance Migration

### Benchmarking

If you had benchmarks with the old library:

**Before:**
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::scalar::Scalar;

fn scalar_mult_benchmark(c: &mut Criterion) {
    let scalar = Scalar::from(42u64);
    c.bench_function("scalar_mult", |b| {
        b.iter(|| black_box(scalar * ED25519_BASEPOINT_POINT))
    });
}
```

**After:**
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gcrypt::{Scalar, EdwardsPoint};

fn scalar_mult_benchmark(c: &mut Criterion) {
    let scalar = Scalar::from_u64(42);
    c.bench_function("scalar_mult", |b| {
        b.iter(|| black_box(EdwardsPoint::mul_base(&scalar)))
    });
}

// New: Batch benchmarks
fn batch_operations_benchmark(c: &mut Criterion) {
    let scalars: Vec<_> = (0..1000).map(Scalar::from_u64).collect();
    c.bench_function("batch_scalar_mult", |b| {
        b.iter(|| black_box(gcrypt::batch::batch_arithmetic::scalar_mul_base(&scalars)))
    });
}
```

## Troubleshooting

### Common Issues

1. **Reference vs. Owned Operations**
   ```rust
   // Old: let result = a + b;
   // New: let result = &a + &b;
   ```

2. **Feature Flag Requirements**
   ```rust
   // If getting "module not found" errors, check feature flags
   // Add required features to Cargo.toml
   ```

3. **Error Type Changes**
   ```rust
   // Update error handling to use GcryptError
   // Check error variants for appropriate handling
   ```

### Migration Checklist

- [ ] Update `Cargo.toml` dependencies
- [ ] Add required feature flags
- [ ] Update import statements
- [ ] Change operations to use references (`&a + &b`)
- [ ] Update method names (e.g., `from(42u64)` → `from_u64(42)`)
- [ ] Update error handling
- [ ] Consider adding batch operations for performance
- [ ] Add Ghostchain ecosystem features if relevant
- [ ] Update tests and benchmarks
- [ ] Verify no-std compatibility if needed

### Performance Validation

After migration, run benchmarks to validate performance improvements:

```bash
# Run all benchmarks
cargo bench

# Run specific Ghostchain benchmarks
cargo run --example batch_operations --features batch-operations,parallel --release
cargo run --example gquic_transport --features gquic-transport --release
```

Expected improvements:
- 2-10x faster batch signature verification
- 20% faster scalar multiplication (with precomputed tables)
- Lower memory allocation in critical paths
- Better cache locality in batch operations