# Getting Started with gcrypt

Welcome to gcrypt! This guide will help you get up and running with gcrypt for your cryptographic needs.

## Table of Contents

- [Installation](#installation)
- [Quick Examples](#quick-examples)
- [Feature Configuration](#feature-configuration)
- [Common Use Cases](#common-use-cases)
- [Next Steps](#next-steps)

## Installation

### Basic Installation

Add gcrypt to your `Cargo.toml`:

```toml
[dependencies]
gcrypt = "0.2"
rand = "0.8"  # For random number generation
```

### With Specific Features

```toml
[dependencies]
gcrypt = { version = "0.2", features = [
    "std",          # Standard library (default)
    "rand_core",    # Random number generation (default)
    "serde",        # Serialization support
    "zeroize",      # Secure memory clearing
    "simd",         # SIMD acceleration
] }
```

### No-std Embedded Projects

```toml
[dependencies]
gcrypt = { version = "0.2", default-features = false, features = [
    "alloc",        # For Vec and other heap types
    "rand_core",    # Essential for cryptographic operations
    "zeroize"       # Security best practice
] }
```

## Quick Examples

### Digital Signatures (Ed25519)

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
    
    println!("✓ Signature verified successfully!");
    Ok(())
}
```

### Key Exchange (X25519)

```rust
use gcrypt::protocols::X25519;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Alice generates her key pair
    let alice_secret = X25519::SecretKey::generate(&mut OsRng);
    let alice_public = alice_secret.public_key();
    
    // Bob generates his key pair
    let bob_secret = X25519::SecretKey::generate(&mut OsRng);
    let bob_public = bob_secret.public_key();
    
    // Both parties compute the same shared secret
    let alice_shared = alice_secret.diffie_hellman(&bob_public)?;
    let bob_shared = bob_secret.diffie_hellman(&alice_public)?;
    
    assert_eq!(alice_shared.to_bytes(), bob_shared.to_bytes());
    println!("✓ Key exchange successful!");
    
    Ok(())
}
```

### Low-level Scalar and Point Operations

```rust
use gcrypt::{Scalar, EdwardsPoint};
use rand::rngs::OsRng;

fn main() {
    // Scalar arithmetic
    let a = Scalar::random(&mut OsRng);
    let b = Scalar::random(&mut OsRng);
    let sum = &a + &b;
    let product = &a * &b;
    
    // Point operations
    let basepoint = EdwardsPoint::basepoint();
    let point1 = &basepoint * &a;
    let point2 = &basepoint * &b;
    let sum_point = &point1 + &point2;
    
    // Multi-scalar multiplication (efficient)
    let scalars = vec![a, b];
    let points = vec![point1, point2];
    let result = EdwardsPoint::multiscalar_mul(&scalars, &points);
    
    println!("✓ Low-level operations completed!");
}
```

## Feature Configuration

### Available Features

| Feature | Description | Default | Use Case |
|---------|-------------|---------|----------|
| `std` | Standard library support | ✅ | Most applications |
| `alloc` | Heap allocation support | ✅ | no-std with Vec, HashMap |
| `rand_core` | Random number generation | ✅ | Key generation, nonces |
| `serde` | Serialization support | ❌ | JSON, databases, network |
| `zeroize` | Secure memory clearing | ❌ | High-security applications |
| `simd` | SIMD acceleration | ❌ | High-performance computing |
| `fiat-crypto` | Formal verification | ❌ | Maximum assurance |
| `precomputed-tables` | Faster base operations | ❌ | Repeated base point ops |

### Configuration Examples

#### Web Application
```toml
gcrypt = { version = "0.2", features = [
    "std", "rand_core", "serde", "zeroize"
] }
```

#### High-Performance Server
```toml
gcrypt = { version = "0.2", features = [
    "std", "rand_core", "simd", "precomputed-tables"
] }
```

#### Embedded System
```toml
gcrypt = { version = "0.2", default-features = false, features = [
    "alloc", "rand_core", "zeroize"
] }
```

#### Maximum Security
```toml
gcrypt = { version = "0.2", features = [
    "std", "rand_core", "zeroize", "fiat-crypto"
] }
```

## Common Use Cases

### 1. Secure Messaging

```rust
use gcrypt::protocols::{Ed25519, X25519};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct SecureMessage {
    content: Vec<u8>,
    signature: [u8; 64],
    sender_public_key: [u8; 32],
}

impl SecureMessage {
    fn new(
        content: &[u8], 
        sender_secret: &Ed25519::SecretKey
    ) -> Self {
        let signature = sender_secret.sign_deterministic(content);
        let sender_public_key = sender_secret.public_key();
        
        SecureMessage {
            content: content.to_vec(),
            signature: signature.to_bytes(),
            sender_public_key: sender_public_key.to_bytes(),
        }
    }
    
    fn verify(&self) -> bool {
        let public_key = Ed25519::PublicKey::from_bytes(&self.sender_public_key);
        let signature = Ed25519::Signature::from_bytes(&self.signature);
        
        public_key.map(|pk| pk.verify(&self.content, &signature).is_ok())
                  .unwrap_or(false)
    }
}
```

### 2. API Authentication

```rust
use gcrypt::protocols::Ed25519;
use std::time::{SystemTime, UNIX_EPOCH};

struct ApiToken {
    user_id: u64,
    expires_at: u64,
    signature: Ed25519::Signature,
}

impl ApiToken {
    fn create(
        user_id: u64, 
        ttl_seconds: u64, 
        server_key: &Ed25519::SecretKey
    ) -> Self {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + ttl_seconds;
        
        let payload = format!("{}:{}", user_id, expires_at);
        let signature = server_key.sign_deterministic(payload.as_bytes());
        
        ApiToken { user_id, expires_at, signature }
    }
    
    fn verify(&self, server_public: &Ed25519::PublicKey) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if now > self.expires_at {
            return false; // Token expired
        }
        
        let payload = format!("{}:{}", self.user_id, self.expires_at);
        server_public.verify(payload.as_bytes(), &self.signature).is_ok()
    }
}
```

### 3. Blockchain Transactions

```rust
use gcrypt::protocols::Ed25519;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Transaction {
    from: [u8; 32],  // Public key
    to: [u8; 32],    // Public key
    amount: u64,
    nonce: u64,
    signature: [u8; 64],
}

impl Transaction {
    fn new(
        from_secret: &Ed25519::SecretKey,
        to_public: [u8; 32],
        amount: u64,
        nonce: u64,
    ) -> Self {
        let from = from_secret.public_key().to_bytes();
        
        // Create signing payload
        let mut payload = Vec::new();
        payload.extend_from_slice(&from);
        payload.extend_from_slice(&to_public);
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&nonce.to_le_bytes());
        
        let signature = from_secret.sign_deterministic(&payload);
        
        Transaction {
            from,
            to: to_public,
            amount,
            nonce,
            signature: signature.to_bytes(),
        }
    }
    
    fn verify(&self) -> bool {
        let public_key = Ed25519::PublicKey::from_bytes(&self.from);
        let signature = Ed25519::Signature::from_bytes(&self.signature);
        
        if let Ok(pk) = public_key {
            let mut payload = Vec::new();
            payload.extend_from_slice(&self.from);
            payload.extend_from_slice(&self.to);
            payload.extend_from_slice(&self.amount.to_le_bytes());
            payload.extend_from_slice(&self.nonce.to_le_bytes());
            
            pk.verify(&payload, &signature).is_ok()
        } else {
            false
        }
    }
}
```

### 4. File Integrity Protection

```rust
use gcrypt::protocols::Ed25519;
use std::fs;

struct SignedFile {
    content: Vec<u8>,
    signature: Ed25519::Signature,
    signer_public_key: Ed25519::PublicKey,
}

impl SignedFile {
    fn sign_file(
        path: &str, 
        secret_key: &Ed25519::SecretKey
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read(path)?;
        let signature = secret_key.sign_deterministic(&content);
        let signer_public_key = secret_key.public_key();
        
        Ok(SignedFile {
            content,
            signature,
            signer_public_key,
        })
    }
    
    fn verify_integrity(&self) -> bool {
        self.signer_public_key
            .verify(&self.content, &self.signature)
            .is_ok()
    }
    
    fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !self.verify_integrity() {
            return Err("File integrity check failed".into());
        }
        
        fs::write(path, &self.content)?;
        Ok(())
    }
}
```

## Error Handling Best Practices

### Comprehensive Error Handling

```rust
use gcrypt::protocols::{Ed25519, SignatureError};

#[derive(Debug)]
enum CryptoError {
    InvalidInput(String),
    SignatureVerificationFailed,
    KeyGenerationFailed,
    SerializationError(String),
}

impl From<SignatureError> for CryptoError {
    fn from(err: SignatureError) -> Self {
        match err {
            SignatureError::VerificationFailed => CryptoError::SignatureVerificationFailed,
            _ => CryptoError::InvalidInput(format!("Signature error: {:?}", err)),
        }
    }
}

fn safe_verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    // Validate input sizes
    if public_key_bytes.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "Public key must be 32 bytes".to_string()
        ));
    }
    
    if signature_bytes.len() != 64 {
        return Err(CryptoError::InvalidInput(
            "Signature must be 64 bytes".to_string()
        ));
    }
    
    // Convert to fixed-size arrays safely
    let pk_array: [u8; 32] = public_key_bytes.try_into()
        .map_err(|_| CryptoError::InvalidInput("Invalid public key format".to_string()))?;
    
    let sig_array: [u8; 64] = signature_bytes.try_into()
        .map_err(|_| CryptoError::InvalidInput("Invalid signature format".to_string()))?;
    
    // Parse public key
    let public_key = Ed25519::PublicKey::from_bytes(&pk_array)?;
    let signature = Ed25519::Signature::from_bytes(&sig_array);
    
    // Verify signature
    public_key.verify(message, &signature)?;
    
    Ok(())
}
```

## Next Steps

### Learn More
- **[API Reference](api-reference.md)** - Complete API documentation
- **[Rust Integration](rust-integration.md)** - Advanced Rust patterns
- **[Zig Integration](zig-integration.md)** - Using gcrypt from Zig
- **[Performance Guide](performance.md)** - Optimization techniques

### Explore Advanced Features
- **[VRF Implementation](protocols/vrf.md)** - Verifiable Random Functions
- **[Ring Signatures](protocols/ring-signatures.md)** - Anonymous signatures  
- **[Threshold Signatures](protocols/threshold.md)** - Multi-party signatures
- **[Bulletproofs](protocols/bulletproofs.md)** - Zero-knowledge proofs

### Security Considerations
- **[Security Best Practices](security.md)** - Secure implementation patterns
- **[Security Assessment](../SECURITY_ASSESSMENT.md)** - Security audit results
- **[API Stability](../API_STABILITY.md)** - Stability guarantees

### Community
- **GitHub Issues** - Report bugs and request features
- **Discussions** - Ask questions and share use cases
- **Security** - Responsible disclosure of vulnerabilities

## Support

If you encounter any issues or have questions:

1. Check the [API Reference](api-reference.md) for detailed documentation
2. Browse [GitHub Issues](https://github.com/CK-Technology/gcrypt/issues) for known issues
3. Create a new issue with a minimal reproduction case
4. For security issues, follow our [Security Policy](../SECURITY.md)

Welcome to the gcrypt community! 🎉