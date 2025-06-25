# gcrypt Documentation

Welcome to the gcrypt documentation! This directory contains comprehensive guides for using gcrypt in various programming environments and crypto projects.

## Quick Navigation

### 📚 **Core Documentation**
- [**API Reference**](api-reference.md) - Complete API documentation with examples
- [**Getting Started**](getting-started.md) - Quick start guide for new users
- [**Migration Guide**](migration-guide.md) - Migrating from other crypto libraries

### 🛠️ **Language Integration**
- [**Rust Integration**](rust-integration.md) - Using gcrypt in Rust projects
- [**Zig Integration**](zig-integration.md) - Using gcrypt from Zig via C FFI
- [**C/C++ Integration**](c-integration.md) - C bindings and C++ wrappers
- [**Python Integration**](python-integration.md) - Python bindings and usage
- [**JavaScript Integration**](javascript-integration.md) - WASM and Node.js usage

### 🔐 **Cryptographic Protocols**
- [**Ed25519 Signatures**](protocols/ed25519.md) - Digital signature implementation
- [**X25519 Key Exchange**](protocols/x25519.md) - Elliptic curve Diffie-Hellman
- [**VRF Implementation**](protocols/vrf.md) - Verifiable Random Functions
- [**Ring Signatures**](protocols/ring-signatures.md) - Anonymous signatures
- [**Threshold Signatures**](protocols/threshold.md) - Multi-party signatures
- [**Bulletproofs**](protocols/bulletproofs.md) - Zero-knowledge range proofs

### 🚀 **Advanced Topics**
- [**Performance Guide**](performance.md) - Optimization and benchmarking
- [**Security Best Practices**](security.md) - Secure implementation patterns
- [**SIMD Acceleration**](simd.md) - Vectorized operations
- [**Formal Verification**](formal-verification.md) - Mathematical correctness
- [**Cross-Platform Deployment**](deployment.md) - Platform-specific considerations

### 🔗 **Project Integration**
- [**Blockchain Projects**](integration/blockchain.md) - Cryptocurrency and DeFi applications
- [**Web Applications**](integration/web.md) - HTTPS, WebAuthn, and secure messaging
- [**IoT and Embedded**](integration/embedded.md) - Resource-constrained environments
- [**Enterprise Systems**](integration/enterprise.md) - Large-scale deployments

## API Overview

gcrypt provides three main API levels:

### **Level 1: Core Primitives**
```rust
use gcrypt::{Scalar, EdwardsPoint, FieldElement};

// Basic scalar and point operations
let scalar = Scalar::random(&mut rng);
let point = EdwardsPoint::mul_base(&scalar);
```

### **Level 2: Cryptographic Protocols**
```rust
use gcrypt::protocols::{Ed25519, X25519, VRF};

// High-level protocol implementations
let secret_key = Ed25519::SecretKey::generate(&mut rng);
let signature = secret_key.sign(message, &mut rng);
```

### **Level 3: Application Integrations**
```rust
use gcrypt::integrations::{WebCrypto, BlockchainSigning};

// Framework-specific integrations
let web_key = WebCrypto::generate_keypair()?;
let blockchain_tx = BlockchainSigning::sign_transaction(tx, &key)?;
```

## Quick Examples

### Rust
```rust
use gcrypt::protocols::Ed25519;
use rand::rngs::OsRng;

let secret_key = Ed25519::SecretKey::generate(&mut OsRng);
let public_key = secret_key.public_key();
let signature = secret_key.sign(b"message", &mut OsRng);
assert!(public_key.verify(b"message", &signature).is_ok());
```

### Zig
```zig
const gcrypt = @cImport(@cInclude("gcrypt.h"));

var secret_key: gcrypt.Ed25519SecretKey = undefined;
var public_key: gcrypt.Ed25519PublicKey = undefined;
var signature: gcrypt.Ed25519Signature = undefined;

_ = gcrypt.ed25519_generate_keypair(&secret_key, &public_key);
_ = gcrypt.ed25519_sign(&secret_key, "message", 7, &signature);
```

### Python
```python
import gcrypt

secret_key = gcrypt.Ed25519SecretKey.generate()
public_key = secret_key.public_key()
signature = secret_key.sign(b"message")
assert public_key.verify(b"message", signature)
```

## Feature Flags

Configure gcrypt for your specific needs:

```toml
[dependencies]
gcrypt = { version = "0.2", features = [
    "std",           # Standard library support
    "simd",          # SIMD acceleration
    "fiat-crypto",   # Formal verification
    "zeroize",       # Secure memory clearing
    "serde",         # Serialization support
    "rand_core",     # Random number generation
] }
```

## Performance Characteristics

| Operation | Cycles (x86_64) | Throughput | Memory |
|-----------|----------------|------------|---------|
| Scalar Mul | ~250K | 4,000 ops/sec | 160 bytes |
| Ed25519 Sign | ~280K | 3,600 sigs/sec | 192 bytes |
| Ed25519 Verify | ~320K | 3,100 verifs/sec | 160 bytes |
| X25519 Exchange | ~260K | 3,800 exchanges/sec | 128 bytes |

## Community and Support

- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides and examples
- **Security**: Responsible disclosure program
- **Contributing**: Contribution guidelines and code of conduct

## License

gcrypt is licensed under the MIT License. See [LICENSE](../LICENSE) for details.