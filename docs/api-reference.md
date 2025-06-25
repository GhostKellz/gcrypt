# gcrypt API Reference

Complete API documentation for gcrypt with examples and best practices.

## Table of Contents

- [Core Types](#core-types)
- [Scalar Operations](#scalar-operations)
- [Point Operations](#point-operations)
- [Field Operations](#field-operations)
- [Protocol APIs](#protocol-apis)
- [Error Handling](#error-handling)
- [Feature Gates](#feature-gates)

## Core Types

### `Scalar`

Represents an integer modulo the order of the Curve25519 group.

```rust
use gcrypt::Scalar;
use rand::rngs::OsRng;

// Construction
let zero = Scalar::ZERO;
let one = Scalar::ONE;
let random = Scalar::random(&mut OsRng);
let from_bytes = Scalar::from_bytes_mod_order(&[1u8; 32]);
let canonical = Scalar::from_canonical_bytes(&bytes)?;

// Conversion
let bytes: [u8; 32] = scalar.to_bytes();
let is_zero: bool = scalar.is_zero();

// Arithmetic
let sum = &a + &b;
let difference = &a - &b;
let product = &a * &b;
let inverse = a.invert()?;
let negated = -&a;
```

### `EdwardsPoint`

Points on the Edwards form of Curve25519.

```rust
use gcrypt::{EdwardsPoint, Scalar};

// Construction
let identity = EdwardsPoint::IDENTITY;
let basepoint = EdwardsPoint::basepoint();
let generator = EdwardsPoint::mul_base(&scalar);

// Point operations
let sum = &point_a + &point_b;
let doubled = point.double();
let scaled = &point * &scalar;
let negated = -&point;

// Predicates
let is_identity: bool = point.is_identity();
let is_on_curve: bool = point.is_on_curve();
let is_torsion_free: bool = point.is_torsion_free();

// Compression
let compressed = point.compress();
let decompressed = compressed.decompress()?;
```

### `FieldElement`

Elements of the field GF(2^255 - 19).

```rust
use gcrypt::FieldElement;

// Constants
let zero = FieldElement::ZERO;
let one = FieldElement::ONE;
let minus_one = FieldElement::MINUS_ONE;

// Construction
let from_bytes = FieldElement::from_bytes(&[1u8; 32]);
let reduced = FieldElement::from_bytes_mod_order(&bytes);

// Arithmetic
let sum = &a + &b;
let product = &a * &b;
let squared = a.square();
let inverted = a.invert()?;
let sqrt = a.sqrt()?;

// Predicates
let is_zero: bool = element.is_zero();
let is_one: bool = element.is_one();
```

## Scalar Operations

### Basic Arithmetic

```rust
use gcrypt::Scalar;

let a = Scalar::from_bytes_mod_order(&[1u8; 32]);
let b = Scalar::from_bytes_mod_order(&[2u8; 32]);

// Addition (commutative, associative)
let sum = &a + &b;                    // a + b
let sum_assign = a.clone(); sum_assign += &b;  // a += b

// Subtraction 
let diff = &a - &b;                   // a - b
let diff_assign = a.clone(); diff_assign -= &b; // a -= b

// Multiplication (commutative, associative)
let prod = &a * &b;                   // a * b
let prod_assign = a.clone(); prod_assign *= &b; // a *= b

// Negation
let neg_a = -&a;                      // -a
```

### Modular Operations

```rust
// Modular inverse
let inv_a = a.invert().unwrap();      // a^(-1) mod l
assert_eq!(&a * &inv_a, Scalar::ONE);

// Modular exponentiation  
let exp = Scalar::from_bytes_mod_order(&[3u8; 32]);
let pow_result = a.pow(&exp.to_bytes()); // a^exp mod l

// Batch inversion (more efficient for multiple scalars)
let scalars = vec![a, b, c, d];
let inverses = Scalar::batch_invert(&scalars);
```

### Random Generation

```rust
use rand::rngs::OsRng;
use gcrypt::Scalar;

// Cryptographically secure random scalar
let random_scalar = Scalar::random(&mut OsRng);

// Deterministic scalar from seed
let seed = b"deterministic seed";
let det_scalar = Scalar::from_hash(seed);

// Random scalar in specific range [0, n)
let n = Scalar::from_bytes_mod_order(&[100u8; 32]);
let bounded = Scalar::random_mod(&n, &mut OsRng);
```

## Point Operations

### Edwards Point Operations

```rust
use gcrypt::{EdwardsPoint, Scalar};

// Basic point arithmetic
let base = EdwardsPoint::basepoint();
let scalar = Scalar::from_bytes_mod_order(&[5u8; 32]);

// Scalar multiplication
let point = &base * &scalar;          // [scalar]base
let point2 = EdwardsPoint::mul_base(&scalar); // Same as above

// Point addition
let sum = &point + &base;             // point + base
let doubled = point.double();         // 2 * point (more efficient than point + point)

// Multi-scalar multiplication (efficient for multiple operations)
let scalars = vec![scalar1, scalarars2, scalar3];
let points = vec![point1, point2, point3];
let result = EdwardsPoint::multiscalar_mul(&scalars, &points);
```

### Point Validation

```rust
// Check if point is valid
let is_valid = point.is_on_curve();   // Mathematical validity
let is_safe = point.is_torsion_free(); // Cryptographic safety

// Comprehensive validation
fn validate_point(point: &EdwardsPoint) -> bool {
    point.is_on_curve() && point.is_torsion_free()
}

// Validate compressed point before decompression
let compressed = CompressedEdwardsY(bytes);
if let Some(point) = compressed.decompress() {
    if validate_point(&point) {
        // Safe to use point
    }
}
```

### Batch Operations

```rust
// Batch point validation (more efficient)
let points = vec![point1, point2, point3, point4];
let all_valid = EdwardsPoint::batch_validate(&points);

// Batch compression
let compressed_points: Vec<_> = points.iter()
    .map(|p| p.compress())
    .collect();

// Batch decompression with validation
let decompressed: Vec<EdwardsPoint> = compressed_points.iter()
    .filter_map(|c| c.decompress())
    .filter(validate_point)
    .collect();
```

## Protocol APIs

### Ed25519 Digital Signatures

```rust
use gcrypt::protocols::Ed25519;
use rand::rngs::OsRng;

// Key generation
let secret_key = Ed25519::SecretKey::generate(&mut OsRng);
let public_key = secret_key.public_key();

// Signing
let message = b"Hello, Ed25519!";
let signature = secret_key.sign(message, &mut OsRng);
let det_signature = secret_key.sign_deterministic(message);

// Verification
let verify_result = public_key.verify(message, &signature);
assert!(verify_result.is_ok());

// Batch verification (more efficient)
let messages = vec![b"msg1", b"msg2", b"msg3"];
let signatures = vec![sig1, sig2, sig3];
let public_keys = vec![pk1, pk2, pk3];
let batch_result = Ed25519::verify_batch(&messages, &signatures, &public_keys);
```

### X25519 Key Exchange

```rust
use gcrypt::protocols::X25519;
use rand::rngs::OsRng;

// Key generation
let (alice_secret, alice_public) = X25519::generate_keypair(&mut OsRng);
let (bob_secret, bob_public) = X25519::generate_keypair(&mut OsRng);

// Key exchange
let alice_shared = alice_secret.diffie_hellman(&bob_public)?;
let bob_shared = bob_secret.diffie_hellman(&alice_public)?;

assert_eq!(alice_shared.to_bytes(), bob_shared.to_bytes());

// Key derivation
let encryption_key = alice_shared.derive_key(b"encryption", 32);
let (enc_key, auth_key) = alice_shared.split_keys();

// Ephemeral key exchange
let (ephemeral_public, shared_secret) = X25519::ephemeral_exchange(&mut OsRng, &bob_public)?;
```

### VRF (Verifiable Random Functions)

```rust
use gcrypt::protocols::VRF;
use rand::rngs::OsRng;

// Key generation
let vrf_secret = VRF::SecretKey::generate(&mut OsRng);
let vrf_public = vrf_secret.public_key();

// VRF evaluation
let input = b"random seed input";
let (output, proof) = vrf_secret.evaluate(input)?;

// VRF verification
let verify_result = vrf_public.verify(input, &output, &proof);
assert!(verify_result.is_ok());

// Use output as randomness
let random_bytes = output.to_bytes();
let rng_seed = output.as_rng_seed();
```

### Ring Signatures

```rust
use gcrypt::protocols::{RingMember, RingSigner, RingVerifier};
use rand::rngs::OsRng;

// Create ring members
let mut ring = Vec::new();
let mut secret_keys = Vec::new();

for _ in 0..5 {
    let secret = Scalar::random(&mut OsRng);
    let public = EdwardsPoint::mul_base(&secret);
    ring.push(RingMember::new(public));
    secret_keys.push(secret);
}

// Signer (member 2)
let signer = RingSigner::new(ring.clone(), secret_keys[2], 2)?;

// Create ring signature
let message = b"Anonymous message";
let signature = signer.sign(message, &mut OsRng);
let linkable_sig = signer.sign_linkable(message, &mut OsRng);

// Verify signature
let verifier = RingVerifier::new(ring)?;
assert!(verifier.verify(message, &signature).is_ok());
```

### Threshold Signatures

```rust
use gcrypt::protocols::{ThresholdConfig, ThresholdCoordinator};
use rand::rngs::OsRng;

// Create 3-of-5 threshold scheme
let config = ThresholdConfig::new(3, 5)?;
let (master_public, participants) = config.generate_shares(&mut OsRng)?;

// Setup coordinator
let participant_keys: Vec<_> = participants.iter()
    .map(|p| (p.id, p.public_share))
    .collect();
let coordinator = ThresholdCoordinator::new(config, master_public, participant_keys)?;

// Participants create partial signatures
let message = b"Threshold signed message";
let partial_sigs: Vec<_> = participants[0..3].iter()
    .map(|p| p.sign_partial(message, &mut OsRng))
    .collect();

// Aggregate into threshold signature
let threshold_sig = coordinator.aggregate_signatures(message, partial_sigs)?;

// Verify threshold signature
assert!(coordinator.verify_threshold_signature(message, &threshold_sig).is_ok());
```

### Bulletproofs (Zero-Knowledge Range Proofs)

```rust
use gcrypt::protocols::Bulletproofs;
use rand::rngs::OsRng;

// Setup bulletproof parameters
let params = Bulletproofs::BulletproofParams::new(64, &mut OsRng);

// Create commitment to secret value
let secret_value = 12345u64;
let commitment = params.commit(secret_value, &mut OsRng)?;

// Create range proof (prove value is in [0, 2^32))
let range_proof = params.prove_range(&commitment, 32, &mut OsRng)?;

// Verify range proof
assert!(params.verify_range_proof(&range_proof, 32).is_ok());

// Batch verification
let proofs = vec![(range_proof1, 32), (range_proof2, 16), (range_proof3, 64)];
assert!(Bulletproofs::verify_range_proofs_batch(&params, &proofs).is_ok());
```

## Error Handling

### Error Types

```rust
use gcrypt::protocols::{Ed25519Error, X25519Error, VRFError};

// Ed25519 errors
match signature_result {
    Ok(signature) => { /* use signature */ },
    Err(Ed25519Error::InvalidFormat) => { /* handle bad format */ },
    Err(Ed25519Error::InvalidPublicKey) => { /* handle bad key */ },
    Err(Ed25519Error::VerificationFailed) => { /* handle bad signature */ },
    Err(Ed25519Error::InvalidSignature) => { /* handle malformed signature */ },
}

// X25519 errors
match exchange_result {
    Ok(shared_secret) => { /* use shared secret */ },
    Err(X25519Error::InvalidPublicKey) => { /* handle bad key */ },
    Err(X25519Error::LowOrderPoint) => { /* handle weak key */ },
    Err(X25519Error::InvalidLength) => { /* handle wrong size */ },
}
```

### Best Practice Error Handling

```rust
use gcrypt::protocols::Ed25519;

fn secure_verify(
    public_key: &[u8; 32], 
    message: &[u8], 
    signature: &[u8; 64]
) -> Result<(), String> {
    // Parse public key
    let pubkey = Ed25519::PublicKey::from_bytes(public_key)
        .map_err(|_| "Invalid public key format")?;
    
    // Parse signature
    let sig = Ed25519::Signature::from_bytes(signature);
    
    // Verify signature
    pubkey.verify(message, &sig)
        .map_err(|e| format!("Signature verification failed: {}", e))?;
    
    Ok(())
}
```

## Feature Gates

### Conditional Compilation

```rust
// Random number generation
#[cfg(feature = "rand_core")]
use gcrypt::Scalar;
#[cfg(feature = "rand_core")]
let random_scalar = Scalar::random(&mut rng);

// Serialization support
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};
#[cfg(feature = "serde")]
let serialized = serde_json::to_string(&point)?;

// SIMD acceleration
#[cfg(feature = "simd")]
use gcrypt::backend::multiscalar_mul_avx2;
#[cfg(feature = "simd")]
let result = multiscalar_mul_avx2(&scalars, &points);

// Formal verification
#[cfg(feature = "fiat-crypto")]
use gcrypt::backend::fiat_integration;
#[cfg(feature = "fiat-crypto")]
let verified_result = fiat_integration::verified_field_mul(&a, &b);

// Secure memory clearing
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;
#[cfg(feature = "zeroize")]
secret_key.zeroize();
```

### Feature Configuration

```toml
# Minimal configuration (no_std)
[dependencies]
gcrypt = { version = "0.2", default-features = false }

# Standard configuration
[dependencies]
gcrypt = { version = "0.2", features = ["std", "rand_core"] }

# High-performance configuration
[dependencies]
gcrypt = { version = "0.2", features = [
    "std", "rand_core", "simd", "precomputed-tables"
] }

# Security-focused configuration
[dependencies]
gcrypt = { version = "0.2", features = [
    "std", "rand_core", "zeroize", "fiat-crypto", "security-audit"
] }

# Full-featured configuration
[dependencies]
gcrypt = { version = "0.2", features = [
    "std", "rand_core", "serde", "zeroize", "simd", 
    "fiat-crypto", "precomputed-tables"
] }
```

## Performance Tips

### Efficient Patterns

```rust
// Use references for arithmetic to avoid cloning
let result = &a + &b;  // Good
let result = a + b;    // Clones a and b

// Batch operations when possible
let results = EdwardsPoint::multiscalar_mul(&scalars, &points);  // Good
let results: Vec<_> = scalars.iter().zip(points.iter())          // Slower
    .map(|(s, p)| p * s).collect();

// Reuse allocations
let mut buffer = Vec::with_capacity(1000);
for item in items {
    buffer.clear();
    item.serialize_into(&mut buffer);
    // process buffer
}

// Use precomputed tables for repeated base point operations
let precomputed = EdwardsPoint::precompute_base();  // One-time cost
for scalar in scalars {
    let result = precomputed.mul(&scalar);  // Fast repeated operation
}
```

### Memory Optimization

```rust
// Clear sensitive data
#[cfg(feature = "zeroize")]
{
    use zeroize::Zeroize;
    let mut secret = [0u8; 32];
    // ... use secret ...
    secret.zeroize();  // Securely clear
}

// Use stack allocation for small operations
let mut small_buffer = [0u8; 64];  // Stack allocated
serialize_signature(&signature, &mut small_buffer);

// Avoid unnecessary conversions
let bytes = point.compress().to_bytes();  // Good
let bytes = point.compress().decompress()  // Wasteful round-trip
    .unwrap().compress().to_bytes();
```