# gcrypt API Documentation

## Overview

gcrypt provides a comprehensive cryptographic library specifically designed for the Ghostchain blockchain ecosystem. This document covers all public APIs across the core cryptographic primitives and Ghostchain-specific features.

## Core Cryptographic Types

### Scalar
Represents a scalar value modulo the order of the Curve25519 group.

```rust
use gcrypt::Scalar;

// Construction
let s1 = Scalar::zero();
let s2 = Scalar::one();
let s3 = Scalar::from_u64(42);
let s4 = Scalar::from_bytes_mod_order(&bytes);

// Operations
let sum = &s1 + &s2;
let product = &s1 * &s2;
let inverse = s1.invert();

// Serialization
let bytes: [u8; 32] = s1.to_bytes();
let s_restored = Scalar::from_bytes_mod_order(&bytes);
```

### FieldElement
Represents an element in the field GF(2^255 - 19).

```rust
use gcrypt::FieldElement;

// Construction
let f1 = FieldElement::zero();
let f2 = FieldElement::one();
let f3 = FieldElement::from_u64(1337);

// Operations
let sum = &f1 + &f2;
let product = &f1 * &f2;
let square = f1.square();
let inverse = f1.invert();

// Serialization
let bytes: [u8; 32] = f1.to_bytes();
```

### EdwardsPoint
Represents a point on the Edwards25519 curve.

```rust
use gcrypt::{EdwardsPoint, Scalar};

// Construction
let basepoint = EdwardsPoint::basepoint();
let identity = EdwardsPoint::identity();

// Scalar multiplication
let scalar = Scalar::from_u64(42);
let point = EdwardsPoint::mul_base(&scalar);
let point2 = &basepoint * &scalar;

// Point operations
let sum = &point + &point2;
let double = point.double();

// Compression
let compressed = point.compress();
let decompressed = compressed.decompress().unwrap();
```

### MontgomeryPoint
Represents a point on the Montgomery form of Curve25519.

```rust
use gcrypt::{MontgomeryPoint, Scalar};

// Construction
let basepoint = MontgomeryPoint::basepoint();

// Scalar multiplication
let scalar = Scalar::from_u64(42);
let point = MontgomeryPoint::mul_base(&scalar);

// X25519 key exchange
let secret_key = [0x77; 32];
let public_key = MontgomeryPoint::mul_base_clamped(secret_key);
let shared_secret = gcrypt::montgomery::x25519(secret_key, public_key.to_bytes());
```

### RistrettoPoint
Represents a point in the Ristretto255 prime-order group.

```rust
use gcrypt::{RistrettoPoint, Scalar};

// Construction
let basepoint = RistrettoPoint::basepoint();
let identity = RistrettoPoint::identity();

// Scalar multiplication
let scalar = Scalar::from_u64(42);
let point = &basepoint * &scalar;

// Group operations
let sum = &point + &point;
let negation = -&point;
```

## GQUIC Transport Module

### GquicTransport
High-performance packet encryption for the GQUIC protocol.

```rust
use gcrypt::transport::{GquicTransport, SessionKey, ConnectionId};

let transport = GquicTransport::new();

// Single packet encryption
let mut session = SessionKey::from_bytes(&key_bytes, connection_id);
let message = b"Hello, GQUIC!";
let header = b"packet-header";

let encrypted = transport.encrypt_packet(&mut session, message, header)?;
let decrypted = transport.decrypt_packet(&mut session, &encrypted, header)?;

// Batch processing
let mut sessions = vec![session1, session2, session3];
let messages = vec![msg1, msg2, msg3];
let headers = vec![hdr1, hdr2, hdr3];

let encrypted_batch = transport.batch_encrypt_packets(&mut sessions, &messages, &headers)?;
```

### GquicKeyExchange
Key derivation for GQUIC sessions.

```rust
use gcrypt::transport::{GquicKeyExchange, ConnectionId};

let alice_secret = Scalar::from_u64(12345);
let bob_public = MontgomeryPoint::mul_base(&Scalar::from_u64(67890));
let connection_id = ConnectionId::from_bytes([0x12; 16]);
let context = b"session-context";

let session_key = GquicKeyExchange::derive_session_key(
    &alice_secret,
    &bob_public,
    connection_id,
    context
)?;
```

### GquicConnectionManager
Manages multiple GQUIC connections.

```rust
use gcrypt::transport::GquicConnectionManager;

let mut manager = GquicConnectionManager::new();

// Add connections
manager.add_session(session1);
manager.add_session(session2);

// Use specific connection
let connection_id = ConnectionId::from_bytes([0x12; 16]);
let encrypted = manager.encrypt_for_connection(&connection_id, data, header)?;
let decrypted = manager.decrypt_for_connection(&connection_id, &encrypted, header)?;
```

## Guardian Framework Module

### GuardianIssuer
Issues authentication tokens with cryptographic verification.

```rust
use gcrypt::guardian::{GuardianIssuer, Did, Permission};

let secret_key = gcrypt::protocols::ed25519::SecretKey::from_scalar(scalar);
let issuer = GuardianIssuer::new(secret_key);

// Create identity and permissions
let user_did = Did::new("ghostchain".to_string(), "user_alice".to_string())?;
let permissions = vec![
    Permission::new("ghostd".to_string(), vec!["read".to_string(), "write".to_string()]),
    Permission::new("walletd".to_string(), vec!["send_transaction".to_string()]),
];

// Issue token
let token = issuer.issue_token(user_did, permissions, 3600)?; // 1 hour expiry
```

### GuardianVerifier
Verifies authentication tokens and permissions.

```rust
use gcrypt::guardian::GuardianVerifier;

let mut verifier = GuardianVerifier::new();
verifier.add_trusted_issuer(issuer_did, issuer_public_key);

// Verify token
verifier.verify_token(&token)?;

// Check specific permission
verifier.verify_permission(&token, "ghostd", "read")?;
```

### Did (Decentralized Identifier)
Represents a decentralized identifier.

```rust
use gcrypt::guardian::Did;

let did = Did::new("ghostchain".to_string(), "user_alice".to_string())?;
let did_string = did.to_string(); // "did:ghostchain:user_alice"
```

### Permission
Represents service permissions with optional constraints.

```rust
use gcrypt::guardian::{Permission, permissions::*};

// Basic permission
let permission = Permission::new(
    "walletd".to_string(),
    vec!["read".to_string(), "send_transaction".to_string()]
);

// Permission with constraints
let constraints = PermissionConstraints::new()
    .with_time_constraints(TimeConstraints::new().with_validity_period(1000, 5000))
    .with_resource_constraints(ResourceConstraints::new().allow_path("/api/v1/wallets/".to_string()))
    .with_rate_constraints(RateConstraints::new(100, 60)); // 100 requests per minute

let constrained_permission = Permission::with_constraints(
    "walletd".to_string(),
    vec!["read".to_string()],
    constraints
);
```

### Token Serialization
Utilities for token transport.

```rust
use gcrypt::guardian::tokens::{TokenCodec, AuthorizationHeader};

// Binary serialization
let binary_data = TokenCodec::serialize_binary(&token)?;
let token_restored = TokenCodec::deserialize_binary(&binary_data)?;

// Base64 encoding
let base64_token = TokenCodec::encode_base64(&token)?;
let token_decoded = TokenCodec::decode_base64(&base64_token)?;

// HTTP headers
let bearer_header = AuthorizationHeader::bearer(&token)?;
let guardian_header = AuthorizationHeader::guardian(&token)?;

// Parse headers
let token_from_bearer = AuthorizationHeader::parse_bearer(&bearer_header)?;
let token_from_guardian = AuthorizationHeader::parse_guardian(&guardian_header)?;
```

### Predefined Permissions
Common Ghostchain service permissions.

```rust
use gcrypt::guardian::permissions::GhostchainPermissions;

let ghostd_read = GhostchainPermissions::ghostd_read();
let ghostd_write = GhostchainPermissions::ghostd_write();
let ghostd_admin = GhostchainPermissions::ghostd_admin();

let walletd_read = GhostchainPermissions::walletd_read();
let walletd_transact = GhostchainPermissions::walletd_transact();

let cns_read = GhostchainPermissions::cns_read();
let cns_write = GhostchainPermissions::cns_write();

let gid_read = GhostchainPermissions::gid_read();
let gid_write = GhostchainPermissions::gid_write();
```

## ZK-Friendly Hash Functions Module

### Poseidon Hash
Most efficient hash function for zk-SNARKs.

```rust
use gcrypt::{FieldElement, zk_hash::poseidon};

let input1 = FieldElement::from_u64(42);
let input2 = FieldElement::from_u64(1337);

// Two-input hash
let hash = poseidon::hash_two(&input1, &input2)?;

// Many-input hash
let inputs = vec![input1, input2, FieldElement::from_u64(9999)];
let hash = poseidon::hash_many(&inputs)?;

// Sponge construction for variable output
let outputs = poseidon::sponge(&inputs, 3)?; // 3 output field elements
```

### Rescue Hash
Symmetric design with forward and inverse S-boxes.

```rust
use gcrypt::zk_hash::rescue;

// Two-input hash
let hash = rescue::hash_two(&input1, &input2)?;

// Many-input hash
let hash = rescue::hash_many(&inputs)?;

// Sponge construction
let outputs = rescue::sponge(&inputs, 2)?;
```

### MiMC Hash
Minimal multiplicative complexity for constraint optimization.

```rust
use gcrypt::zk_hash::mimc;

// Hash functions
let hash = mimc::hash_two(&input1, &input2)?;
let hash = mimc::hash_many(&inputs)?;

// Permutation
let permuted = mimc::permutation(&input1)?;

// Encryption
let encrypted = mimc::encrypt(&plaintext, &key)?;

// Feistel construction
let (left_out, right_out) = mimc::feistel(&left_in, &right_in, 8)?; // 8 rounds
```

### Pedersen Hash
Elliptic curve-based hash with strong collision resistance.

```rust
use gcrypt::zk_hash::pedersen;

// Hash field elements
let hash = pedersen::hash_two(&input1, &input2)?;
let hash = pedersen::hash_many(&inputs)?;

// Hash byte strings
let message = b"Hello, Pedersen!";
let hash = pedersen::hash_bytes(message)?;

// Hash to elliptic curve point
let point = pedersen::hash_to_point(message)?;
let compressed = point.compress();
```

## Batch Operations Module

### Batch Signature Verification
High-throughput signature verification for DeFi protocols.

```rust
use gcrypt::batch::batch_signatures;

// Ed25519 batch verification
let public_keys: Vec<PublicKey> = /* ... */;
let messages: Vec<&[u8]> = /* ... */;
let signatures: Vec<Signature> = /* ... */;

let all_valid = batch_signatures::verify_ed25519_batch(&public_keys, &messages, &signatures)?;

// Fast batch verification (optimized)
let all_valid = batch_signatures::verify_ed25519_batch_fast(&public_keys, &messages, &signatures)?;
```

### Batch Arithmetic Operations
Parallel processing of cryptographic operations.

```rust
use gcrypt::batch::batch_arithmetic;

let scalars: Vec<Scalar> = /* ... */;

// Batch base scalar multiplication
let points = batch_arithmetic::scalar_mul_base(&scalars)?;

// Batch point addition
let sums = batch_arithmetic::point_add(&points1, &points2)?;

// Multi-scalar multiplication
let combined = batch_arithmetic::multiscalar_mul(&scalars, &points)?;

// Batch scalar inversion
let inverted = batch_arithmetic::scalar_invert(&scalars)?;

// Field element operations
let field_sums = batch_arithmetic::field_add(&field_elements_a, &field_elements_b)?;
let field_products = batch_arithmetic::field_mul(&field_elements_a, &field_elements_b)?;
let field_inverted = batch_arithmetic::field_invert(&field_elements)?;
```

### Batch Merkle Tree Operations
Efficient Merkle tree construction and verification.

```rust
use gcrypt::batch::batch_merkle;

let leaves: Vec<&[u8]> = /* ... */;

// Build Merkle tree
let root = batch_merkle::build_tree_root(&leaves)?;

// Build tree with proofs
let (root, proofs) = batch_merkle::build_tree_with_proofs(&leaves)?;

// Batch verify all proofs
let all_valid = batch_merkle::verify_proofs(&proofs, &leaves)?;
```

## Error Handling

All operations return `Result<T, E>` where `E` implements the standard `Error` trait.

```rust
use gcrypt::error::GcryptError;

match operation() {
    Ok(result) => println!("Success: {:?}", result),
    Err(GcryptError::InvalidInput) => println!("Invalid input provided"),
    Err(GcryptError::VerificationFailed) => println!("Verification failed"),
    Err(GcryptError::SerializationError) => println!("Serialization error"),
    Err(e) => println!("Other error: {:?}", e),
}
```

## Feature-Gated APIs

Some APIs are only available with specific feature flags:

```toml
[dependencies]
gcrypt = { version = "0.1", features = ["gquic-transport", "guardian-framework", "zk-hash", "batch-operations"] }
```

- `gquic-transport`: Enables the `transport` module
- `guardian-framework`: Enables the `guardian` module
- `zk-hash`: Enables the `zk_hash` module
- `batch-operations`: Enables the `batch` module
- `parallel`: Enables parallel processing (requires `batch-operations`)

## Thread Safety

All types in gcrypt are `Send` and `Sync` where appropriate:

- Immutable types (`Scalar`, `EdwardsPoint`, etc.) are `Send + Sync`
- Mutable session types require exclusive access but are `Send`
- Batch operations can be parallelized safely

## Performance Considerations

- Use batch operations for high-throughput scenarios
- Enable the `parallel` feature for CPU-intensive workloads
- Prefer `_fast` variants of verification functions when available
- Use precomputed tables for repeated base scalar multiplications
- Consider memory allocation patterns in no-std environments