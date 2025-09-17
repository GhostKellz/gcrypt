<div align="center">
  <img src="assets/gcrypt-logo.png" alt="Gcrypt Logo" width="400"/>

  # gcrypt

  **The Premier Rust Cryptographic Library for Blockchain & DeFi**

  *The backbone of Ghostchain - High-performance, secure cryptographic operations for Web3*

  [![Rust](https://img.shields.io/badge/rust-2024%2B-orange.svg)](https://www.rust-lang.org)
  [![Crates.io](https://img.shields.io/crates/v/gcrypt.svg)](https://crates.io/crates/gcrypt)
  [![Documentation](https://docs.rs/gcrypt/badge.svg)](https://docs.rs/gcrypt)
  [![License](https://img.shields.io/crates/l/gcrypt.svg)](https://github.com/ghostchain/gcrypt#license)
  [![Build Status](https://img.shields.io/github/actions/workflow/status/ghostchain/gcrypt/ci.yml?branch=main)](https://github.com/ghostchain/gcrypt/actions)

</div>

## 🚀 Production-Ready for Web3 & Blockchain

**gcrypt powers the next generation of decentralized applications and blockchain infrastructure!**

### ✅ Enterprise-Grade Features

- **🔒 Constant-time operations** - All operations resist timing attacks and side-channel analysis
- **🚀 Modern Rust 2024** - Latest language features and zero-cost abstractions
- **📦 No-std support** - Perfect for embedded nodes and constrained blockchain environments
- **⚡ Optimized arithmetic** - High-throughput operations for DeFi protocols
- **🛡️ Memory safety** - Written in safe Rust with secure memory clearing
- **🎯 Multiple backends** - Automatic optimization for different architectures
- **🌐 Web3 ready** - Designed specifically for blockchain and DeFi applications

### 🔥 Blockchain-Optimized Cryptographic Primitives

- **✅ Field arithmetic** over GF(2^255 - 19) - Foundation for all Curve25519 operations
- **✅ Scalar arithmetic** with Barrett reduction - Optimized for transaction signing
- **✅ Edwards25519 point operations** - Ed25519 signatures for wallet authentication
- **✅ Montgomery form operations** - X25519 key exchange for secure communications
- **✅ Ristretto255 group** - Advanced protocols for privacy coins and zero-knowledge proofs
- **✅ Sliding window scalar multiplication** - Accelerated operations for high-frequency trading
- **✅ AES-GCM encryption** - Symmetric encryption for off-chain data and node communications

## 🌟 Perfect for Blockchain & DeFi Applications

**gcrypt is specifically designed to meet the demanding requirements of modern blockchain infrastructure:**

### 🏦 DeFi Protocol Support
- **High-throughput signing** for DEX order books and AMM operations
- **Multi-signature schemes** for DAO governance and treasury management
- **Privacy-preserving transactions** using Ristretto255 for confidential transfers
- **Cross-chain bridges** with secure key derivation and validation

### ⛓️ Blockchain Infrastructure
- **Validator node operations** with constant-time signature verification
- **Consensus mechanisms** requiring fast cryptographic operations
- **P2P networking** with X25519 key exchange for secure communications
- **State commitment schemes** using efficient field arithmetic

### 🛡️ Security-First Design
- **Side-channel resistance** crucial for validator and exchange operations
- **Memory safety** preventing exploits in high-value environments
- **Formal verification** readiness for mission-critical applications
- **Zero-allocation paths** for real-time trading systems

## Features

### Core Cryptographic Primitives

- **Scalar arithmetic** modulo the order of the Curve25519 group
- **Edwards25519** point operations for digital signatures (Ed25519)
- **Montgomery form** operations for key exchange (X25519)
- **Ristretto255** prime-order group for advanced protocols
- **Field arithmetic** over GF(2^255 - 19)

### Modern API Design

- Clean, ergonomic APIs with builder patterns
- Comprehensive error handling
- Rich trait ecosystem for extensibility
- Optional allocator support for no-std environments

### Security Features

- Constant-time arithmetic operations
- Secure random number generation (optional)
- Memory zeroing support with `zeroize` feature
- Side-channel resistant implementations

## Quick Start

Add gcrypt to your `Cargo.toml`:

```toml
[dependencies]
gcrypt = "0.1"
```

### Basic Usage

```rust
use gcrypt::{Scalar, EdwardsPoint, MontgomeryPoint};

// Generate a random scalar
let secret = Scalar::random(&mut rand::thread_rng());

// Edwards curve operations (Ed25519)
let public_key = EdwardsPoint::mul_base(&secret);
let signature_point = &public_key * &secret;

// Montgomery curve operations (X25519)
let shared_secret = MontgomeryPoint::mul_base(&secret);

// Point compression and decompression
let compressed = public_key.compress();
let decompressed = compressed.decompress().unwrap();
assert_eq!(public_key, decompressed);
```

### X25519 Key Exchange

```rust
use gcrypt::montgomery::{MontgomeryPoint, x25519};

// Alice generates a key pair
let alice_secret = [0x77; 32]; // In practice, use random bytes
let alice_public = MontgomeryPoint::mul_base_clamped(alice_secret);

// Bob generates a key pair  
let bob_secret = [0x88; 32]; // In practice, use random bytes
let bob_public = MontgomeryPoint::mul_base_clamped(bob_secret);

// Both parties compute the same shared secret
let alice_shared = x25519(alice_secret, bob_public.to_bytes());
let bob_shared = x25519(bob_secret, alice_public.to_bytes());

assert_eq!(alice_shared, bob_shared);
```

### Ristretto255 Group Operations

```rust
use gcrypt::{RistrettoPoint, Scalar};

// Ristretto255 provides a prime-order group
let basepoint = RistrettoPoint::basepoint();
let scalar1 = Scalar::random(&mut rand::thread_rng());
let scalar2 = Scalar::random(&mut rand::thread_rng());

// Group operations
let point1 = &basepoint * &scalar1;
let point2 = &basepoint * &scalar2;
let sum = &point1 + &point2;

// Verify linearity
let scalar_sum = &scalar1 + &scalar2;
let expected = &basepoint * &scalar_sum;
assert_eq!(sum, expected);
```

## Feature Flags

- `std` (default): Enable standard library support
- `alloc` (default): Enable allocator support for no-std environments  
- `rand_core` (default): Enable random number generation
- `serde`: Enable serialization/deserialization support
- `zeroize`: Enable secure memory zeroing
- `group`: Enable compatibility with the `group` trait ecosystem
- `precomputed-tables`: Enable precomputed lookup tables for faster operations

## No-std Usage

gcrypt supports no-std environments:

```toml
[dependencies]
gcrypt = { version = "0.1", default-features = false }
```

For no-std with allocation:

```toml
[dependencies]
gcrypt = { version = "0.1", default-features = false, features = ["alloc"] }
```

## Performance

gcrypt is designed for high performance:

- **Backend selection**: Automatically chooses optimal implementation based on target architecture
- **Constant-time operations**: All operations are constant-time without sacrificing performance
- **SIMD support**: Takes advantage of vector instructions when available
- **Precomputed tables**: Optional lookup tables for faster fixed-base scalar multiplication

Benchmarks can be run with:

```bash
cargo bench
```

## Security

Security is a primary focus of gcrypt:

- **Constant-time implementations**: All operations resist timing attacks
- **Memory safety**: Written in safe Rust
- **Secure defaults**: Sensible defaults that promote secure usage
- **Regular audits**: Code is regularly reviewed for security issues

### Reporting Security Issues

If you discover a security vulnerability, please report it privately to [security@your-org.com](mailto:security@your-org.com).

## Comparison with curve25519-dalek

gcrypt is designed as a modern alternative to curve25519-dalek with several improvements:

| Feature | gcrypt | curve25519-dalek |
|---------|--------|------------------|
| Rust Edition | 2024 | 2021 |
| API Design | Modern, ergonomic | Legacy compatibility |
| Backend Selection | Automatic | Manual configuration |
| Documentation | Comprehensive | Good |
| Performance | Optimized | Good |
| Security Features | Built-in | Add-on |

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/ghostkellz/gcrypt.git
cd gcrypt

# Run tests
cargo test

# Run tests with all features
cargo test --all-features

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy --all-features
```

## License

Licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT)
### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Acknowledgments

This library builds upon the excellent work of:

- The [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) team
- The [RustCrypto](https://github.com/RustCrypto) organization
- The broader Rust cryptography community

Special thanks to the original curve25519-dalek authors for their pioneering work in this space.
