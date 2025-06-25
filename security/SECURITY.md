# Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

### Critical Security Issues

If you discover a security vulnerability in gcrypt, please report it privately. **DO NOT** open a public issue.

**Security Contact:** security@gcrypt.rs

### Reporting Process

1. **Email security@gcrypt.rs** with:
   - Detailed description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Suggested fix (if available)

2. **Response Timeline:**
   - **Initial response**: Within 24 hours
   - **Triage and assessment**: Within 72 hours
   - **Fix development**: 1-2 weeks (depending on severity)
   - **Public disclosure**: After fix is released + 90 days

3. **Coordination:**
   - We will work with you to understand and validate the issue
   - Credit will be given to security researchers (unless anonymity is requested)
   - We may request a CVE number for significant vulnerabilities

### Security Scope

#### In Scope
- Cryptographic implementation vulnerabilities
- Side-channel attacks (timing, power, electromagnetic)
- Memory safety issues
- Constant-time violations
- API misuse that leads to security issues
- Dependency vulnerabilities

#### Out of Scope
- Issues in example code or documentation
- Social engineering attacks
- Physical access attacks
- Issues requiring unrealistic threat models

## Security Measures

### Implementation Security
- **Constant-time operations**: All cryptographic operations resist timing attacks
- **Memory safety**: 100% safe Rust implementation
- **Formal verification**: Critical operations verified with fiat-crypto
- **Side-channel testing**: Automated testing with dudect
- **Fuzzing**: Continuous fuzzing of all public APIs

### Development Security
- **Security reviews**: All code changes reviewed for security implications
- **Automated scanning**: cargo-audit, clippy, and custom security lints
- **Dependency auditing**: Regular review of all dependencies
- **Secure build process**: Reproducible builds and supply chain security

### Testing Security
- **Adversarial testing**: Red team exercises and penetration testing
- **Differential testing**: Cross-validation against reference implementations
- **Property-based testing**: Mathematical invariants verified
- **Regression testing**: Security test suite prevents regressions

## Security Advisories

Security advisories will be published at:
- GitHub Security Advisories
- RustSec Advisory Database
- Our security mailing list (security-announce@gcrypt.rs)

## Security Bounty Program

We operate a responsible disclosure program:

### Rewards
- **Critical vulnerabilities**: $1,000 - $5,000
- **High severity**: $500 - $1,000  
- **Medium severity**: $100 - $500
- **Low severity**: $50 - $100

### Eligibility
- First to report the vulnerability
- Provide clear reproduction steps
- Follow responsible disclosure guidelines
- No public disclosure before coordinated release

## Cryptographic Claims

### Security Assumptions
- **Curve25519 security**: Based on elliptic curve discrete logarithm problem
- **Implementation security**: Constant-time, side-channel resistant
- **Random number generation**: Uses system CSPRNG (user responsibility)

### Not Provided
- **Quantum resistance**: Curve25519 is not quantum-safe
- **Implementation verification**: While we use formal verification for critical components, full formal verification is not complete
- **Perfect forward secrecy**: Must be implemented at protocol level

## Security Best Practices

### For Users
```rust
// ✅ Good: Use secure random number generation
use rand_core::OsRng;
let scalar = Scalar::random(&mut OsRng);

// ❌ Bad: Don't use weak randomness
let scalar = Scalar::from_bytes_mod_order([42; 32]); // Predictable!

// ✅ Good: Clear sensitive data
use zeroize::Zeroize;
let mut secret = [0u8; 32];
// ... use secret ...
secret.zeroize();

// ✅ Good: Validate inputs
if let Some(point) = CompressedEdwardsY(bytes).decompress() {
    // Use validated point
} else {
    return Err("Invalid point encoding");
}
```

### For Protocol Implementers
- Always validate all inputs before cryptographic operations
- Use constant-time comparisons for secrets
- Implement proper key derivation (don't reuse keys)
- Add domain separation for different protocol contexts
- Consider replay attack prevention

## Compliance

### Standards Compliance
- **FIPS 140-2**: Level 1 compliance for algorithmic implementation
- **NIST SP 800-186**: Elliptic curve recommendations
- **RFC 7748**: X25519 specification compliance
- **RFC 8032**: Ed25519 specification compliance

### Audit History
- **[Date]**: Initial security review (internal)
- **[Planned]**: Third-party cryptographic audit by [Auditor]
- **[Ongoing]**: Continuous automated security testing

## Contact Information

- **Security Team**: security@gcrypt.rs
- **General Contact**: hello@gcrypt.rs
- **Maintainers**: See MAINTAINERS.md

---

*This security policy is modeled after industry best practices and will be updated as the project evolves.*