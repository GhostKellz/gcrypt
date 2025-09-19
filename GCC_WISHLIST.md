# GhostChain Crypto (GCC) Wishlist for GCRYPT

## Overview
This document outlines the cryptographic features and enhancements needed in the [gcrypt](https://github.com/ghostkellz/gcrypt) crate to fully support GhostChain's blockchain, wallet, and identity requirements. GCRYPT will serve as our cryptographic backbone.

## Current GCRYPT Status ✅
- **Curve25519-based cryptography** (Ed25519, X25519, Ristretto255)
- **AES-GCM encryption**
- **Constant-time operations** for timing attack resistance
- **No-std support** for embedded environments
- **Memory safety** and secure clearing

## Required Enhancements for GhostChain 🚀

### 1. Additional Signature Algorithms
**Priority: HIGH**
- [ ] **Secp256k1** - Bitcoin/Ethereum compatibility for cross-chain operations
- [ ] **Secp256r1 (P-256)** - NIST standards compliance, hardware wallet support
- [ ] **BLS signatures** - For aggregate signatures in consensus
- [ ] **Schnorr signatures** - For multi-sig and threshold signatures

### 2. Key Derivation & Management
**Priority: HIGH**
- [ ] **BIP-39** - Mnemonic phrase generation for wallet recovery
- [ ] **BIP-32** - Hierarchical Deterministic (HD) wallet key derivation
- [ ] **BIP-44** - Multi-account hierarchy standard
- [ ] **HKDF (RFC 5869)** - Key derivation for session keys
- [ ] **Argon2id** - Memory-hard KDF for password-based encryption

### 3. Authentication & MAC
**Priority: HIGH**
- [ ] **HMAC-SHA256/SHA512** - Message authentication
- [ ] **HMAC-Blake3** - Fast modern MAC
- [ ] **Poly1305** - For ChaCha20-Poly1305 AEAD

### 4. Additional Hash Functions
**Priority: MEDIUM**
- [ ] **SHA-256/SHA-512** - Standards compliance
- [ ] **SHA-3 (Keccak)** - Ethereum compatibility
- [ ] **Blake3** - Already mentioned but ensure full implementation
- [ ] **Poseidon** - ZK-friendly hash for future proofs

### 5. Threshold & Multi-Party Cryptography
**Priority: HIGH** (For Keystone & GID)
- [ ] **Shamir's Secret Sharing** - Key splitting for recovery
- [ ] **Threshold signatures (t-of-n)** - Multi-sig wallets
- [ ] **MPC primitives** - Secure multi-party computation
- [ ] **Verifiable Secret Sharing (VSS)** - For validator key management

### 6. Zero-Knowledge Proofs
**Priority: MEDIUM** (Future enhancement)
- [ ] **Bulletproofs** - Range proofs for confidential transactions
- [ ] **zk-SNARKs primitives** - For privacy features
- [ ] **Pedersen commitments** - Hiding commitments for amounts

### 7. Symmetric Encryption
**Priority: HIGH**
- [ ] **ChaCha20-Poly1305** - Modern AEAD alternative to AES-GCM
- [ ] **AES-256-CBC** - Legacy compatibility
- [ ] **XChaCha20-Poly1305** - Extended nonce variant

### 8. Identity & DID Support
**Priority: HIGH** (For GID/GhostID)
- [ ] **DID key method support** - did:key generation
- [ ] **WebAuthn/FIDO2 primitives** - Passkey support
- [ ] **Verifiable Credentials** - VC signing/verification
- [ ] **JWK/JWT support** - For OAuth/OIDC bridging

### 9. Post-Quantum Readiness
**Priority: LOW** (Future-proofing)
- [ ] **Dilithium** - PQ signatures
- [ ] **Kyber** - PQ key exchange
- [ ] **Framework for hybrid schemes** - Classical + PQ

### 10. Blockchain-Specific
**Priority: HIGH**
- [ ] **VRF (Verifiable Random Function)** - For consensus randomness
- [ ] **Ring signatures** - Optional privacy features
- [ ] **Aggregate signatures** - For validator efficiency
- [ ] **Merkle tree operations** - For state proofs

## API Design Requirements

### Consistency
```rust
// All APIs should follow this pattern:
gcrypt::algo::operation(input, key) -> Result<Output, Error>

// Examples:
gcrypt::ed25519::sign(message, private_key) -> Result<Signature, Error>
gcrypt::aes_gcm::encrypt(plaintext, key, nonce) -> Result<Ciphertext, Error>
gcrypt::bip39::generate_mnemonic(entropy) -> Result<Mnemonic, Error>
```

### Safety Features
- **Zeroization** - Automatic memory clearing for sensitive data
- **Constant-time** - Timing-safe operations where applicable
- **Type safety** - Strong typing for keys, signatures, etc.

### Performance
- **SIMD optimizations** - Where available
- **Parallel operations** - For batch verification
- **Hardware acceleration** - AES-NI, SHA extensions

## Integration Requirements

### GhostChain Core
- Transaction signing (Ed25519, Secp256k1)
- Block hashing (Blake3)
- Merkle proofs
- VRF for consensus

### GWALLET
- HD wallet derivation (BIP-32/39/44)
- Multi-signature support
- Hardware wallet compatibility
- Key recovery via Shamir's

### GID (Identity)
- DID generation and resolution
- Verifiable Credentials
- WebAuthn/passkey support
- Soulbound token signatures

### Keystone (Key Management)
- Threshold signatures
- Key rotation
- Secure enclave integration
- HSM compatibility

### CNS (Crypto Name Server)
- DNSSEC signatures
- Domain ownership proofs
- ENS compatibility

### RVM (Rust VM)
- Crypto opcodes for smart contracts
- Gas-efficient operations
- Precompiled contracts for common ops

## Testing Requirements
- **RFC test vectors** - All algorithms must pass official test vectors
- **Cross-implementation tests** - Compatibility with other libraries
- **Fuzzing** - Security testing
- **Benchmarks** - Performance metrics

## Documentation Requirements
- **API documentation** - Full rustdoc coverage
- **Security considerations** - When to use each algorithm
- **Migration guides** - From other crypto libraries
- **Examples** - Common use cases

## Compatibility Matrix

| Feature | Bitcoin | Ethereum | Substrate | Cosmos | Solana |
|---------|---------|----------|-----------|---------|---------|
| Secp256k1 | ✅ | ✅ | ⚠️ | ⚠️ | ❌ |
| Ed25519 | ❌ | ❌ | ✅ | ✅ | ✅ |
| BIP-39/32 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Keccak-256 | ❌ | ✅ | ⚠️ | ❌ | ❌ |

## Priority Order for Implementation

### Phase 1 - Core Blockchain (Immediate)
1. Secp256k1 & Secp256r1
2. BIP-39/32/44
3. HMAC & HKDF
4. SHA-256/512 & SHA-3

### Phase 2 - Advanced Features (Q1 2025)
1. Threshold signatures
2. ChaCha20-Poly1305
3. VRF
4. Basic ZK primitives

### Phase 3 - Future Enhancements (Q2 2025+)
1. Full ZK proof systems
2. Post-quantum algorithms
3. Advanced MPC
4. Hardware security modules

## Success Metrics
- [ ] All GhostChain services can use gcrypt exclusively
- [ ] Performance comparable to native implementations
- [ ] Security audit passed
- [ ] 100% test coverage with official test vectors
- [ ] Documentation complete with examples

## Notes
- GCRYPT should become the "libsodium of Rust" - comprehensive, safe, and fast
- Focus on production readiness over experimental features
- Maintain backward compatibility as we add features
- Consider WASM compilation for browser wallets

---
*This wishlist will be updated as GhostChain requirements evolve.*