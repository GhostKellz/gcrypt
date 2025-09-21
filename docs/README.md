# gcrypt Documentation

Welcome to the comprehensive documentation for gcrypt, the premier Rust cryptographic library for the Ghostchain blockchain ecosystem.

## Quick Start

- **[Main README](../README.md)** - Project overview and basic usage examples
- **[API Documentation](api.md)** - Complete API reference for all modules
- **[Feature Guide](features.md)** - Detailed guide to feature flags and capabilities
- **[Migration Guide](migration.md)** - How to migrate from other cryptographic libraries
- **[Performance Benchmarks](benchmarks.md)** - Comprehensive performance analysis

## Documentation Structure

### 📖 Core Documentation

| Document | Description | Target Audience |
|----------|-------------|-----------------|
| [API Documentation](api.md) | Complete API reference with examples | Developers integrating gcrypt |
| [Feature Guide](features.md) | Detailed feature flag documentation | All users |
| [Migration Guide](migration.md) | Migration from other libraries | Existing users of curve25519-dalek, etc. |
| [Performance Benchmarks](benchmarks.md) | Comprehensive performance analysis | Performance-conscious developers |

### 🏗️ Architecture Documentation

#### Core Cryptographic Primitives
- **Scalar Arithmetic**: Operations modulo the Curve25519 group order
- **Edwards25519**: Ed25519 digital signatures and point operations
- **Montgomery Form**: X25519 key exchange and Montgomery ladder
- **Ristretto255**: Prime-order group for advanced protocols
- **Field Elements**: Arithmetic over GF(2^255 - 19)

#### Ghostchain Ecosystem Features
- **GQUIC Transport**: High-performance packet encryption for Etherlink
- **Guardian Framework**: Zero-trust authentication with DIDs
- **ZK-Friendly Hashes**: Circuit-efficient hash functions for privacy
- **Batch Operations**: High-throughput processing for DeFi protocols

### 🚀 Getting Started by Use Case

#### Blockchain Node Operators
```toml
gcrypt = {
    version = "0.1",
    features = ["gquic-transport", "guardian-framework", "batch-operations", "parallel"]
}
```
- Start with: [API Documentation - GQUIC Transport](api.md#gquic-transport-module)
- See: [Performance Benchmarks - DeFi Protocols](benchmarks.md#defi-protocol-benchmarks)

#### DeFi Protocol Developers
```toml
gcrypt = {
    version = "0.1",
    features = ["batch-operations", "parallel", "guardian-framework"]
}
```
- Start with: [API Documentation - Batch Operations](api.md#batch-operations-module)
- See: [Performance Benchmarks - Batch Operations](benchmarks.md#batch-operations-performance)

#### Privacy Application Developers
```toml
gcrypt = {
    version = "0.1",
    features = ["zk-hash", "batch-operations"]
}
```
- Start with: [API Documentation - ZK-Friendly Hashes](api.md#zk-friendly-hash-functions-module)
- See: [Feature Guide - ZK Hash](features.md#zk-hash)

#### Embedded/IoT Developers
```toml
gcrypt = {
    version = "0.1",
    default-features = false,
    features = ["alloc"]  # optional
}
```
- Start with: [Feature Guide - No-std Usage](features.md#minimal-configuration)
- See: [Migration Guide - No-std](migration.md#no-std-migration)

### 📚 Reference Materials

#### Feature Flags Reference
| Flag | Purpose | Dependencies |
|------|---------|--------------|
| `std` | Standard library support | None |
| `alloc` | Allocation support | None |
| `gquic-transport` | GQUIC transport layer | `alloc` |
| `guardian-framework` | Authentication system | `alloc` |
| `zk-hash` | ZK-friendly hash functions | None |
| `batch-operations` | High-throughput operations | `alloc` |
| `parallel` | Multi-core processing | `batch-operations` |

See [Feature Guide](features.md) for complete details.

#### Performance Quick Reference
| Operation | Single | Batch (1000) | Speedup |
|-----------|--------|--------------|---------|
| Signature Verification | 2.0 ms | 48 ms | 10.5x |
| Scalar Multiplication | 52 μs | 28 ms | 1.8x |
| GQUIC Packet Encryption | 2.1 μs | 800 μs | 2.6x |
| Poseidon Hash | 12.3 μs | 8.7 ms | 1.4x |

See [Performance Benchmarks](benchmarks.md) for complete analysis.

### 🔧 Development Resources

#### Examples
Located in the [`examples/`](../examples/) directory:
- `ghostchain_integration.rs` - Complete ecosystem integration
- `gquic_transport.rs` - GQUIC transport usage
- `guardian_auth.rs` - Authentication and authorization
- `batch_operations.rs` - High-throughput operations
- `zk_hash_functions.rs` - Zero-knowledge hash functions

#### Tests
- Unit tests: `cargo test`
- Integration tests: `cargo test --all-features`
- Feature-specific tests: `cargo test --features <feature>`

#### Benchmarks
- Official benchmarks: `cargo bench`
- Example benchmarks: `cargo run --example <name> --release`

### 🏢 Ghostchain Ecosystem Integration

gcrypt is designed as the foundational cryptographic library for:

#### 🔗 [Ghostchain Core](https://github.com/ghostkellz/ghostchain)
- Primary Rust blockchain implementation
- Wallet services and transaction processing
- **Integration**: Core cryptographic operations, batch transaction validation

#### 🌉 [Ghostbridge](https://github.com/ghostkellz/ghostbridge)
- Cross-chain bridge infrastructure
- **Integration**: Guardian framework authentication, high-throughput batch operations

#### 🚀 [Etherlink](https://github.com/ghostkellz/etherlink)
- gRPC communication with GQUIC transport
- **Integration**: GQUIC packet encryption, Guardian authentication headers

#### ⚡ Ghostplane (Work in Progress)
- Layer 2 blockchain in Zig
- **Integration**: FFI bindings for core cryptographic operations

### 🛡️ Security Considerations

#### Constant-Time Operations
All cryptographic operations are implemented to resist timing attacks:
- Scalar arithmetic uses Montgomery representation
- Point operations use complete addition formulas
- Conditional operations use constant-time selection

#### Memory Safety
- Written in safe Rust with minimal unsafe blocks
- Secure memory clearing with zeroize feature
- Protection against double-free and use-after-free

#### Side-Channel Resistance
- Operations resist cache-timing attacks
- Uniform memory access patterns
- No secret-dependent branching

See [API Documentation - Security](api.md#thread-safety) for details.

### 📞 Support and Community

#### Getting Help
- **Documentation Issues**: Check this documentation first
- **API Questions**: See [API Documentation](api.md)
- **Performance Questions**: See [Performance Benchmarks](benchmarks.md)
- **Migration Help**: See [Migration Guide](migration.md)

#### Reporting Issues
- **Security Issues**: Report privately to security contact
- **Bug Reports**: Use GitHub issues with reproduction steps
- **Feature Requests**: Use GitHub issues with use case description

#### Contributing
- Read the main [README](../README.md) for contribution guidelines
- Follow Rust coding standards and conventions
- Include tests and documentation for new features
- Run `cargo test --all-features` and `cargo clippy --all-features`

### 📈 Roadmap and Future Development

#### Current Focus (v0.1.x)
- Stable Ghostchain ecosystem integration
- Performance optimization for DeFi workloads
- Comprehensive testing and documentation

#### Future Versions
- **v0.2**: Post-quantum preparation
- **v0.3**: Hardware acceleration (GPU support)
- **v0.4**: Formal verification integration

See the main [TODO.md](../TODO.md) for detailed roadmap.

### 📄 License and Legal

gcrypt is dual-licensed under:
- MIT License
- Apache License 2.0

This documentation is licensed under the same terms as the codebase.

---

**Last Updated**: January 2025
**gcrypt Version**: 0.1.0
**Rust Edition**: 2024