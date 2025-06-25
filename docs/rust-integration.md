# Rust Integration Guide

Complete guide for integrating gcrypt into Rust projects, from basic usage to advanced patterns.

## Table of Contents

- [Quick Start](#quick-start)
- [Project Setup](#project-setup)
- [Common Patterns](#common-patterns)
- [Framework Integration](#framework-integration)
- [Performance Optimization](#performance-optimization)
- [Best Practices](#best-practices)

## Quick Start

### Basic Dependencies

```toml
# Cargo.toml
[dependencies]
gcrypt = "0.2"
rand = "0.8"  # For random number generation
```

### Hello World Example

```rust
use gcrypt::protocols::Ed25519;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a key pair
    let secret_key = Ed25519::SecretKey::generate(&mut OsRng);
    let public_key = secret_key.public_key();
    
    // Sign a message
    let message = b"Hello, gcrypt!";
    let signature = secret_key.sign(message, &mut OsRng);
    
    // Verify the signature
    public_key.verify(message, &signature)?;
    
    println!("Signature verified successfully!");
    Ok(())
}
```

## Project Setup

### Feature Configuration

Choose features based on your project needs:

```toml
[dependencies]
gcrypt = { version = "0.2", features = [
    "std",              # Standard library (default)
    "rand_core",        # Random number generation (default)
    "serde",            # Serialization support
    "zeroize",          # Secure memory clearing
    "simd",             # SIMD acceleration
    "fiat-crypto",      # Formal verification
    "precomputed-tables" # Faster base point operations
] }
```

### No-std Embedded Projects

```toml
[dependencies]
gcrypt = { version = "0.2", default-features = false, features = [
    "alloc",            # For Vec and other allocating types
    "rand_core",        # Still need randomness
    "zeroize"           # Security is important
] }
```

### High-Performance Projects

```toml
[dependencies]
gcrypt = { version = "0.2", features = [
    "std", "rand_core", "simd", "precomputed-tables"
] }

# Add these for benchmarking
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
```

## Common Patterns

### Key Management

```rust
use gcrypt::protocols::{Ed25519, X25519};
use rand::rngs::OsRng;
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KeyPair {
    signing_key: Ed25519::SecretKey,
    exchange_key: X25519::SecretKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self {
            signing_key: Ed25519::SecretKey::generate(&mut rng),
            exchange_key: X25519::SecretKey::generate(&mut rng),
        }
    }
    
    pub fn from_seed(seed: &[u8; 64]) -> Self {
        let mut signing_seed = [0u8; 32];
        let mut exchange_seed = [0u8; 32];
        
        signing_seed.copy_from_slice(&seed[0..32]);
        exchange_seed.copy_from_slice(&seed[32..64]);
        
        Self {
            signing_key: Ed25519::SecretKey::from_bytes(&signing_seed),
            exchange_key: X25519::SecretKey::from_bytes(&exchange_seed),
        }
    }
    
    pub fn sign(&self, message: &[u8]) -> Ed25519::Signature {
        self.signing_key.sign_deterministic(message)
    }
    
    pub fn exchange(&self, their_public: &X25519::PublicKey) -> X25519::SharedSecret {
        self.exchange_key.diffie_hellman(their_public)
            .expect("Valid public key")
    }
}
```

### Message Authentication

```rust
use gcrypt::protocols::Ed25519;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct SignedMessage<T> {
    pub payload: T,
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
}

impl<T: Serialize> SignedMessage<T> {
    pub fn new(payload: T, secret_key: &Ed25519::SecretKey) -> Result<Self, serde_json::Error> {
        let serialized = serde_json::to_vec(&payload)?;
        let signature = secret_key.sign_deterministic(&serialized);
        let public_key = secret_key.public_key();
        
        Ok(SignedMessage {
            payload,
            signature: signature.to_bytes(),
            public_key: public_key.to_bytes(),
        })
    }
    
    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let public_key = Ed25519::PublicKey::from_bytes(&self.public_key)?;
        let signature = Ed25519::Signature::from_bytes(&self.signature);
        let serialized = serde_json::to_vec(&self.payload)?;
        
        Ok(public_key.verify(&serialized, &signature).is_ok())
    }
}

// Usage
#[derive(Serialize, Deserialize)]
struct MyData {
    user_id: u64,
    timestamp: u64,
    action: String,
}

let data = MyData {
    user_id: 12345,
    timestamp: 1640995200,
    action: "transfer".to_string(),
};

let signed = SignedMessage::new(data, &secret_key)?;
let json = serde_json::to_string(&signed)?;

// Later...
let parsed: SignedMessage<MyData> = serde_json::from_str(&json)?;
assert!(parsed.verify()?);
```

### Secure Storage

```rust
use gcrypt::{protocols::X25519, FieldElement};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::fs;

#[derive(ZeroizeOnDrop)]
pub struct SecureStorage {
    key: [u8; 32],
}

impl SecureStorage {
    pub fn new(password: &str, salt: &[u8; 16]) -> Self {
        // In practice, use a proper KDF like Argon2
        let mut key = [0u8; 32];
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(password.as_bytes());
        hasher_input.extend_from_slice(salt);
        
        // Simple key derivation (use proper KDF in production)
        for i in 0..1000 {
            hasher_input.extend_from_slice(&i.to_le_bytes());
            let hash = simple_hash(&hasher_input);
            for j in 0..32 {
                key[j] ^= hash[j];
            }
        }
        
        SecureStorage { key }
    }
    
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        // Simplified encryption - use proper AEAD in production
        let mut encrypted = Vec::new();
        for (i, &byte) in data.iter().enumerate() {
            encrypted.push(byte ^ self.key[i % 32]);
        }
        encrypted
    }
    
    pub fn decrypt(&self, encrypted: &[u8]) -> Vec<u8> {
        // XOR is symmetric
        self.encrypt(encrypted)
    }
    
    pub fn store_key_pair(&self, path: &str, keypair: &KeyPair) -> std::io::Result<()> {
        let signing_bytes = keypair.signing_key.to_bytes();
        let exchange_bytes = keypair.exchange_key.to_bytes();
        
        let mut combined = Vec::new();
        combined.extend_from_slice(&signing_bytes);
        combined.extend_from_slice(&exchange_bytes);
        
        let encrypted = self.encrypt(&combined);
        fs::write(path, encrypted)
    }
    
    pub fn load_key_pair(&self, path: &str) -> Result<KeyPair, Box<dyn std::error::Error>> {
        let encrypted = fs::read(path)?;
        let decrypted = self.decrypt(&encrypted);
        
        if decrypted.len() != 64 {
            return Err("Invalid key file".into());
        }
        
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&decrypted);
        
        Ok(KeyPair::from_seed(&seed))
    }
}

fn simple_hash(input: &[u8]) -> [u8; 32] {
    // Simplified hash - use SHA-256 in production
    let mut hash = [0u8; 32];
    for (i, &byte) in input.iter().enumerate() {
        hash[i % 32] ^= byte.wrapping_add(i as u8);
    }
    hash
}
```

## Framework Integration

### Actix Web Integration

```rust
use actix_web::{web, App, HttpServer, HttpResponse, Result, middleware::Logger};
use gcrypt::protocols::Ed25519;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    signing_key: Arc<Ed25519::SecretKey>,
}

#[derive(Deserialize)]
struct SignRequest {
    message: String,
}

#[derive(Serialize)]
struct SignResponse {
    signature: String,
    public_key: String,
}

async fn sign_message(
    data: web::Json<SignRequest>,
    state: web::Data<AppState>,
) -> Result<HttpResponse> {
    let message = data.message.as_bytes();
    let signature = state.signing_key.sign_deterministic(message);
    let public_key = state.signing_key.public_key();
    
    let response = SignResponse {
        signature: hex::encode(signature.to_bytes()),
        public_key: hex::encode(public_key.to_bytes()),
    };
    
    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    let signing_key = Arc::new(Ed25519::SecretKey::generate(&mut rand::rngs::OsRng));
    let app_state = AppState { signing_key };
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(Logger::default())
            .route("/sign", web::post().to(sign_message))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Tokio Async Integration

```rust
use gcrypt::protocols::{Ed25519, X25519};
use tokio::sync::{mpsc, oneshot};
use std::collections::HashMap;

#[derive(Debug)]
enum CryptoRequest {
    Sign {
        message: Vec<u8>,
        response: oneshot::Sender<Ed25519::Signature>,
    },
    Verify {
        message: Vec<u8>,
        signature: Ed25519::Signature,
        public_key: Ed25519::PublicKey,
        response: oneshot::Sender<bool>,
    },
    KeyExchange {
        their_public: X25519::PublicKey,
        response: oneshot::Sender<X25519::SharedSecret>,
    },
}

pub struct CryptoService {
    request_tx: mpsc::UnboundedSender<CryptoRequest>,
}

impl CryptoService {
    pub fn new() -> Self {
        let (request_tx, mut request_rx) = mpsc::unbounded_channel();
        
        let signing_key = Ed25519::SecretKey::generate(&mut rand::rngs::OsRng);
        let exchange_key = X25519::SecretKey::generate(&mut rand::rngs::OsRng);
        
        tokio::spawn(async move {
            while let Some(request) = request_rx.recv().await {
                match request {
                    CryptoRequest::Sign { message, response } => {
                        let signature = signing_key.sign_deterministic(&message);
                        let _ = response.send(signature);
                    }
                    CryptoRequest::Verify { message, signature, public_key, response } => {
                        let is_valid = public_key.verify(&message, &signature).is_ok();
                        let _ = response.send(is_valid);
                    }
                    CryptoRequest::KeyExchange { their_public, response } => {
                        if let Ok(shared) = exchange_key.diffie_hellman(&their_public) {
                            let _ = response.send(shared);
                        }
                    }
                }
            }
        });
        
        CryptoService { request_tx }
    }
    
    pub async fn sign(&self, message: Vec<u8>) -> Result<Ed25519::Signature, ()> {
        let (response_tx, response_rx) = oneshot::channel();
        
        self.request_tx.send(CryptoRequest::Sign { message, response: response_tx })
            .map_err(|_| ())?;
        
        response_rx.await.map_err(|_| ())
    }
    
    pub async fn verify(
        &self,
        message: Vec<u8>,
        signature: Ed25519::Signature,
        public_key: Ed25519::PublicKey,
    ) -> Result<bool, ()> {
        let (response_tx, response_rx) = oneshot::channel();
        
        self.request_tx.send(CryptoRequest::Verify {
            message, signature, public_key, response: response_tx
        }).map_err(|_| ())?;
        
        response_rx.await.map_err(|_| ())
    }
}

// Usage
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crypto_service = CryptoService::new();
    
    let message = b"Hello, async world!".to_vec();
    let signature = crypto_service.sign(message.clone()).await?;
    
    println!("Message signed asynchronously!");
    
    Ok(())
}
```

### Serde Integration

```rust
use gcrypt::{EdwardsPoint, Scalar};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use serde::de::{self, Visitor};
use std::fmt;

// Custom serialization for EdwardsPoint
impl Serialize for EdwardsPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.compress().to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

struct EdwardsPointVisitor;

impl<'de> Visitor<'de> for EdwardsPointVisitor {
    type Value = EdwardsPoint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("32 bytes representing a compressed Edwards point")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() != 32 {
            return Err(E::custom("Invalid point length"));
        }
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(v);
        
        let compressed = gcrypt::edwards::CompressedEdwardsY(bytes);
        compressed.decompress()
            .ok_or_else(|| E::custom("Invalid compressed point"))
    }
}

impl<'de> Deserialize<'de> for EdwardsPoint {
    fn deserialize<D>(deserializer: D) -> Result<EdwardsPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(EdwardsPointVisitor)
    }
}

// Usage in structs
#[derive(Serialize, Deserialize)]
struct CryptoMessage {
    point: EdwardsPoint,
    scalar: Scalar,
    data: Vec<u8>,
}

// JSON serialization example
let message = CryptoMessage {
    point: EdwardsPoint::basepoint(),
    scalar: Scalar::from_bytes_mod_order(&[1u8; 32]),
    data: b"example data".to_vec(),
};

let json = serde_json::to_string(&message)?;
let parsed: CryptoMessage = serde_json::from_str(&json)?;
```

## Performance Optimization

### Batch Operations

```rust
use gcrypt::{EdwardsPoint, Scalar};

// Efficient batch signature verification
fn batch_verify_signatures(
    messages: &[&[u8]],
    signatures: &[Ed25519::Signature],
    public_keys: &[Ed25519::PublicKey],
) -> Result<(), Ed25519::SignatureError> {
    // Use built-in batch verification (more efficient than individual)
    Ed25519::verify_batch(messages, signatures, public_keys)
}

// Efficient multi-scalar multiplication
fn compute_linear_combination(
    scalars: &[Scalar],
    points: &[EdwardsPoint],
) -> EdwardsPoint {
    EdwardsPoint::multiscalar_mul(scalars, points)
}

// Precomputed tables for repeated base point operations
struct PrecomputedBase {
    table: EdwardsPoint::PrecomputedBase,
}

impl PrecomputedBase {
    fn new() -> Self {
        Self {
            table: EdwardsPoint::precompute_base(),
        }
    }
    
    fn mul(&self, scalar: &Scalar) -> EdwardsPoint {
        self.table.mul(scalar)
    }
}

// Use precomputed table
let precomputed = PrecomputedBase::new();  // One-time setup cost
for scalar in scalars {
    let result = precomputed.mul(&scalar);  // Fast repeated operations
    // process result
}
```

### Memory Pool

```rust
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

pub struct PointPool {
    pool: Arc<Mutex<VecDeque<Vec<EdwardsPoint>>>>,
    capacity: usize,
}

impl PointPool {
    pub fn new(capacity: usize) -> Self {
        Self {
            pool: Arc::new(Mutex::new(VecDeque::new())),
            capacity,
        }
    }
    
    pub fn get(&self, size: usize) -> Vec<EdwardsPoint> {
        let mut pool = self.pool.lock().unwrap();
        
        // Try to reuse existing allocation
        if let Some(mut vec) = pool.pop_front() {
            vec.clear();
            vec.reserve(size);
            vec
        } else {
            Vec::with_capacity(size)
        }
    }
    
    pub fn return_vec(&self, mut vec: Vec<EdwardsPoint>) {
        let mut pool = self.pool.lock().unwrap();
        
        if pool.len() < self.capacity {
            vec.clear();
            pool.push_back(vec);
        }
        // Otherwise let it drop
    }
}

// Usage
let pool = PointPool::new(10);

fn compute_batch(scalars: &[Scalar], pool: &PointPool) -> Vec<EdwardsPoint> {
    let mut results = pool.get(scalars.len());
    
    for scalar in scalars {
        results.push(EdwardsPoint::mul_base(scalar));
    }
    
    // Return allocation to pool when done
    let final_results = results.clone();
    pool.return_vec(results);
    
    final_results
}
```

## Best Practices

### Security Guidelines

```rust
use gcrypt::protocols::{Ed25519, X25519};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{rngs::OsRng, CryptoRng, RngCore};

// 1. Always use cryptographically secure randomness
fn generate_secure_key() -> Ed25519::SecretKey {
    Ed25519::SecretKey::generate(&mut OsRng)  // Good
    // Ed25519::SecretKey::from_bytes(&[42; 32])  // BAD - predictable
}

// 2. Clear sensitive data
#[derive(ZeroizeOnDrop)]
struct SecretData {
    key: [u8; 32],
    nonce: [u8; 24],
}

// 3. Validate all inputs
fn safe_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, String> {
    // Validate input lengths
    if public_key_bytes.len() != 32 {
        return Err("Invalid public key length".to_string());
    }
    if signature_bytes.len() != 64 {
        return Err("Invalid signature length".to_string());
    }
    
    // Parse with validation
    let public_key = Ed25519::PublicKey::from_bytes(
        public_key_bytes.try_into().map_err(|_| "Invalid key format")?
    ).map_err(|_| "Invalid public key")?;
    
    let signature = Ed25519::Signature::from_bytes(
        signature_bytes.try_into().map_err(|_| "Invalid signature format")?
    );
    
    // Verify
    Ok(public_key.verify(message, &signature).is_ok())
}

// 4. Use constant-time operations
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    
    if a.len() != b.len() {
        return false;
    }
    
    a.ct_eq(b).into()
}

// 5. Handle errors properly
fn robust_key_exchange(
    secret: &X25519::SecretKey,
    public_bytes: &[u8; 32],
) -> Result<[u8; 32], String> {
    let public_key = X25519::PublicKey::from_bytes(public_bytes)
        .map_err(|_| "Invalid public key")?;
    
    let shared_secret = secret.diffie_hellman(&public_key)
        .map_err(|e| match e {
            X25519::KeyExchangeError::LowOrderPoint => "Weak public key".to_string(),
            _ => "Key exchange failed".to_string(),
        })?;
    
    Ok(shared_secret.to_bytes())
}
```

### Testing Patterns

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use gcrypt::protocols::Ed25519;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // Use deterministic RNG for reproducible tests
    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(12345)
    }

    #[test]
    fn test_signature_roundtrip() {
        let mut rng = test_rng();
        let secret_key = Ed25519::SecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();
        
        let message = b"test message";
        let signature = secret_key.sign(message, &mut rng);
        
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_deterministic() {
        let secret_key = Ed25519::SecretKey::from_bytes(&[1u8; 32]);
        let message = b"deterministic message";
        
        let sig1 = secret_key.sign_deterministic(message);
        let sig2 = secret_key.sign_deterministic(message);
        
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_invalid_signature_rejection() {
        let mut rng = test_rng();
        let secret_key = Ed25519::SecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();
        
        let message = b"original message";
        let signature = secret_key.sign(message, &mut rng);
        
        // Should reject signature on different message
        let wrong_message = b"different message";
        assert!(public_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_batch_verification() {
        let mut rng = test_rng();
        
        let mut messages = Vec::new();
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        
        for i in 0..10 {
            let secret_key = Ed25519::SecretKey::generate(&mut rng);
            let public_key = secret_key.public_key();
            let message = format!("message {}", i);
            let signature = secret_key.sign(message.as_bytes(), &mut rng);
            
            messages.push(message.as_bytes());
            signatures.push(signature);
            public_keys.push(public_key);
        }
        
        let message_refs: Vec<&[u8]> = messages.iter().map(|m| *m).collect();
        assert!(Ed25519::verify_batch(&message_refs, &signatures, &public_keys).is_ok());
    }

    // Property-based testing with proptest
    #[cfg(feature = "proptest")]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;
        
        proptest! {
            #[test]
            fn signature_always_verifies(message in any::<Vec<u8>>()) {
                let mut rng = test_rng();
                let secret_key = Ed25519::SecretKey::generate(&mut rng);
                let public_key = secret_key.public_key();
                
                let signature = secret_key.sign(&message, &mut rng);
                prop_assert!(public_key.verify(&message, &signature).is_ok());
            }
            
            #[test]
            fn wrong_message_never_verifies(
                message1 in any::<Vec<u8>>(),
                message2 in any::<Vec<u8>>()
            ) {
                prop_assume!(message1 != message2);
                
                let mut rng = test_rng();
                let secret_key = Ed25519::SecretKey::generate(&mut rng);
                let public_key = secret_key.public_key();
                
                let signature = secret_key.sign(&message1, &mut rng);
                prop_assert!(public_key.verify(&message2, &signature).is_err());
            }
        }
    }
}
```

This completes the Rust integration guide! The next sections would cover Zig integration and other language bindings. Would you like me to continue with the Zig integration guide?