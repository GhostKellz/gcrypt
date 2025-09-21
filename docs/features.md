# gcrypt Feature Guide

This document provides detailed information about gcrypt's feature flags and their capabilities.

## Core Features

### `std` (enabled by default)
Enables standard library support.

**What it enables:**
- Standard collections (`Vec`, `HashMap`, etc.)
- Standard I/O operations
- Threading primitives
- System time access
- Error trait implementations

**When to disable:**
- Embedded environments
- WebAssembly targets
- Kernel-level code
- Resource-constrained systems

```toml
# Disable for no-std
gcrypt = { version = "0.1", default-features = false }
```

### `alloc` (enabled by default)
Enables allocator support for no-std environments.

**What it enables:**
- Dynamic memory allocation (`Vec`, `Box`, etc.)
- Batch operations that require collection types
- Variable-length data structures

**When to disable:**
- Static-only memory environments
- Strict no-allocation requirements

```toml
# No-std without allocation
gcrypt = { version = "0.1", default-features = false }

# No-std with allocation
gcrypt = { version = "0.1", default-features = false, features = ["alloc"] }
```

### `rand_core` (enabled by default)
Enables random number generation support.

**What it enables:**
- `Scalar::random()` method
- Random key generation utilities
- Probabilistic algorithms

**Dependencies:**
- `rand_core` crate

```toml
# Enable random number generation
gcrypt = { version = "0.1", features = ["rand_core"] }
```

### `serde`
Enables serialization and deserialization support.

**What it enables:**
- `Serialize` and `Deserialize` implementations for all types
- JSON, CBOR, and other format support
- Network and storage serialization

**Dependencies:**
- `serde` crate

```toml
gcrypt = { version = "0.1", features = ["serde"] }

# Example usage
use gcrypt::Scalar;
use serde_json;

let scalar = Scalar::from_u64(42);
let json = serde_json::to_string(&scalar)?;
let restored: Scalar = serde_json::from_str(&json)?;
```

### `zeroize`
Enables secure memory zeroing.

**What it enables:**
- Automatic memory clearing on drop
- Secure key material handling
- Protection against memory dumps

**Dependencies:**
- `zeroize` crate

```toml
gcrypt = { version = "0.1", features = ["zeroize"] }
```

### `group`
Enables compatibility with the `group` trait ecosystem.

**What it enables:**
- `Group` trait implementations
- Interoperability with other elliptic curve libraries
- Generic programming over group operations

**Dependencies:**
- `group` crate

```toml
gcrypt = { version = "0.1", features = ["group"] }
```

### `precomputed-tables`
Enables precomputed lookup tables for faster operations.

**What it enables:**
- Faster fixed-base scalar multiplication
- Precomputed basepoint multiples
- Trading memory for speed

**Performance impact:**
- ~20% faster scalar multiplication
- Additional ~64KB memory usage
- Compile-time table generation

```toml
gcrypt = { version = "0.1", features = ["precomputed-tables"] }
```

## Ghostchain Ecosystem Features

### `gquic-transport`
Enables GQUIC transport integration for Etherlink communication.

**What it enables:**
- `gcrypt::transport` module
- High-performance packet encryption
- Session key management
- Batch packet processing
- Connection management utilities

**Use cases:**
- Etherlink gRPC communication
- High-throughput blockchain networking
- Secure P2P messaging
- Real-time data streams

**Dependencies:**
- `chacha20poly1305` crate
- `blake3` crate for key derivation

```toml
gcrypt = { version = "0.1", features = ["gquic-transport"] }
```

**Example:**
```rust
use gcrypt::transport::{GquicTransport, GquicKeyExchange};

let transport = GquicTransport::new();
let session = GquicKeyExchange::derive_session_key(/* ... */)?;
let encrypted = transport.encrypt_packet(&mut session, data, header)?;
```

### `guardian-framework`
Enables zero-trust authentication with decentralized identifiers.

**What it enables:**
- `gcrypt::guardian` module
- DID-based identity management
- Cryptographic token issuance and verification
- Granular permission systems
- HTTP/gRPC authentication headers

**Use cases:**
- Ghostchain service authentication
- Cross-service authorization
- API access control
- Microservice security
- Zero-trust architecture

**Dependencies:**
- `base64` crate for token encoding
- `serde` and `serde_json` for serialization

```toml
gcrypt = { version = "0.1", features = ["guardian-framework"] }
```

**Example:**
```rust
use gcrypt::guardian::{GuardianIssuer, Did, Permission};

let issuer = GuardianIssuer::new(secret_key);
let did = Did::new("ghostchain".to_string(), "user_alice".to_string())?;
let permissions = vec![Permission::new("ghostd".to_string(), vec!["read".to_string()])];
let token = issuer.issue_token(did, permissions, 3600)?;
```

### `zk-hash`
Enables zero-knowledge friendly hash functions.

**What it enables:**
- `gcrypt::zk_hash` module
- Poseidon hash (most circuit-efficient)
- Rescue hash (symmetric design)
- MiMC hash (minimal multiplicative complexity)
- Pedersen hash (elliptic curve-based)

**Use cases:**
- zk-SNARK circuits
- Merkle trees in zero-knowledge proofs
- Privacy-preserving protocols
- Confidential transactions
- Commitment schemes

**Dependencies:**
- Internal field arithmetic implementations

```toml
gcrypt = { version = "0.1", features = ["zk-hash"] }
```

**Example:**
```rust
use gcrypt::{FieldElement, zk_hash::poseidon};

let input1 = FieldElement::from_u64(42);
let input2 = FieldElement::from_u64(1337);
let hash = poseidon::hash_two(&input1, &input2)?;
```

**Circuit Complexity Comparison:**
| Hash Function | Constraints/Hash | Best Use Case |
|---------------|------------------|---------------|
| Poseidon | ~150-300 | General zk-SNARKs |
| Rescue | ~200-400 | Symmetric security proofs |
| MiMC | ~100-200 | Minimal constraint count |
| Pedersen | ~1000+ | Non-circuit commitments |

### `batch-operations`
Enables high-throughput batch operations for DeFi protocols.

**What it enables:**
- `gcrypt::batch` module
- Batch signature verification
- Parallel arithmetic operations
- Batch Merkle tree operations
- High-throughput transaction processing

**Use cases:**
- DEX order book processing
- Batch transaction validation
- High-frequency trading systems
- Blockchain state updates
- Parallel proof verification

**Dependencies:**
- `rayon` crate (when `parallel` feature is enabled)

```toml
gcrypt = { version = "0.1", features = ["batch-operations"] }
```

**Example:**
```rust
use gcrypt::batch::batch_signatures;

let all_valid = batch_signatures::verify_ed25519_batch(
    &public_keys,
    &messages,
    &signatures
)?;
```

**Performance Benefits:**
- 2-10x faster signature verification
- Parallel processing utilization
- SIMD instruction optimization
- Memory access optimization

### `parallel`
Enables parallel processing with Rayon (requires `batch-operations`).

**What it enables:**
- Multi-threaded batch operations
- Parallel signature verification
- Concurrent arithmetic operations
- CPU core utilization

**System requirements:**
- Multi-core CPU
- Sufficient memory bandwidth
- Thread-safe environment

```toml
gcrypt = { version = "0.1", features = ["batch-operations", "parallel"] }
```

**Performance scaling:**
- Near-linear scaling with CPU cores
- Best for operations on >100 items
- Memory bandwidth can be limiting factor

## Feature Combinations

### Minimal Configuration
For embedded or resource-constrained environments:

```toml
gcrypt = {
    version = "0.1",
    default-features = false,
    # Only core cryptographic primitives
}
```

### Blockchain Node
For running Ghostchain nodes:

```toml
gcrypt = {
    version = "0.1",
    features = [
        "gquic-transport",    # Network communication
        "guardian-framework", # Authentication
        "batch-operations",   # High throughput
        "parallel",          # Multi-core processing
        "zeroize"           # Secure memory
    ]
}
```

### DeFi Application
For high-frequency trading or DEX applications:

```toml
gcrypt = {
    version = "0.1",
    features = [
        "batch-operations",
        "parallel",
        "precomputed-tables",
        "guardian-framework",
        "serde"
    ]
}
```

### Zero-Knowledge Application
For privacy-preserving protocols:

```toml
gcrypt = {
    version = "0.1",
    features = [
        "zk-hash",
        "batch-operations",
        "group",
        "serde"
    ]
}
```

### Full Ghostchain Ecosystem
For complete integration:

```toml
gcrypt = {
    version = "0.1",
    features = [
        "gquic-transport",
        "guardian-framework",
        "zk-hash",
        "batch-operations",
        "parallel",
        "precomputed-tables",
        "serde",
        "zeroize"
    ]
}
```

## Conditional Compilation

Features enable conditional compilation of modules:

```rust
#[cfg(feature = "gquic-transport")]
pub mod transport;

#[cfg(feature = "guardian-framework")]
pub mod guardian;

#[cfg(feature = "zk-hash")]
pub mod zk_hash;

#[cfg(feature = "batch-operations")]
pub mod batch;
```

## Feature Dependencies

Some features depend on others:

- `parallel` requires `batch-operations`
- `gquic-transport` works best with `alloc`
- `guardian-framework` requires `alloc` for token management
- `zk-hash` can work without `alloc` but some functions require it

## Performance Impact

| Feature | Compile Time | Binary Size | Runtime Performance |
|---------|-------------|-------------|-------------------|
| `std` | Minimal | +50KB | Baseline |
| `alloc` | Minimal | +10KB | Baseline |
| `gquic-transport` | +10s | +100KB | High throughput |
| `guardian-framework` | +5s | +80KB | Authentication overhead |
| `zk-hash` | +15s | +120KB | Circuit-optimized |
| `batch-operations` | +5s | +60KB | 2-10x speedup |
| `parallel` | +3s | +40KB | Near-linear scaling |
| `precomputed-tables` | +20s | +64KB | 20% speedup |

## Memory Usage

| Feature | Static Memory | Dynamic Memory |
|---------|--------------|---------------|
| Core types | ~4KB | Variable |
| `precomputed-tables` | +64KB | None |
| `gquic-transport` | +8KB | Session state |
| `guardian-framework` | +4KB | Token cache |
| `batch-operations` | +2KB | Batch size dependent |

## Platform Support

All features are supported on:
- Linux (x86_64, aarch64)
- macOS (x86_64, aarch64)
- Windows (x86_64)
- WebAssembly (with appropriate feature selection)

Platform-specific optimizations:
- SIMD acceleration on supported CPUs
- Hardware RNG when available
- OS-specific secure memory allocation