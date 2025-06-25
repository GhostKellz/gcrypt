# gcrypt

A modern, high-performance pure Rust cryptographic library focusing on Curve25519 and related algorithms.

*Built with curve25519-dalek as a reference implementation for mathematical correctness.*

[![Rust](https://github.com/your-org/gcrypt/actions/workflows/rust.yml/badge.svg)](https://github.com/your-org/gcrypt/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/gcrypt.svg)](https://crates.io/crates/gcrypt)
[![Documentation](https://docs.rs/gcrypt/badge.svg)](https://docs.rs/gcrypt)

## 🚀 Production-Ready Status

**gcrypt is now functionally complete for production Curve25519 operations!** 

### ✅ Implemented Features

- **🔒 Constant-time operations** - All operations resist timing attacks
- **🚀 Modern Rust 2024** - Latest language features and best practices  
- **📦 No-std support** - Works in embedded and constrained environments
- **⚡ Optimized arithmetic** - Proper modular reduction and efficient algorithms
- **🛡️ Memory safety** - Written in safe Rust with secure memory clearing
- **🎯 Multiple backends** - Automatic 32-bit/64-bit backend selection

### 🔥 Core Cryptographic Primitives

- **✅ Field arithmetic** over GF(2^255 - 19) with proper reduction
- **✅ Scalar arithmetic** modulo group order with Barrett reduction  
- **✅ Edwards25519 point operations** for digital signatures (Ed25519)
- **✅ Montgomery form operations** for key exchange (X25519)
- **✅ Ristretto255 group** for advanced cryptographic protocols
- **✅ Sliding window scalar multiplication** with precomputed tables

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
git clone https://github.com/your-org/gcrypt.git
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

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Acknowledgments

This library builds upon the excellent work of:

- The [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) team
- The [RustCrypto](https://github.com/RustCrypto) organization
- The broader Rust cryptography community

Special thanks to the original curve25519-dalek authors for their pioneering work in this space.