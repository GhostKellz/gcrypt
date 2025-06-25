# Acknowledgments

gcrypt stands on the shoulders of giants. We acknowledge and thank the following projects and researchers for their foundational work.

## Reference Implementations

### curve25519-dalek
gcrypt was developed with **curve25519-dalek** as a primary reference implementation for mathematical correctness and algorithmic approaches. The excellent work by the curve25519-dalek team provided invaluable guidance for:

- Field arithmetic implementation patterns
- Point operation algorithms  
- Scalar arithmetic and reduction techniques
- Test vector validation approaches
- API design considerations

**Repository:** https://github.com/dalek-cryptography/curve25519-dalek  
**Authors:** Isis Lovecruft, Henry de Valence, and contributors  
**License:** BSD 3-Clause

We deeply appreciate their commitment to high-quality, well-documented cryptographic implementations that serve as exemplars for the Rust cryptography ecosystem.

### ed25519-consensus (eed21115-dev)
Special thanks to **eed21115-dev** and the ed25519-consensus project for additional insights into Ed25519 implementation details and consensus-critical signature verification.

**Repository:** https://github.com/penumbra-zone/ed25519-consensus  
**License:** MIT/Apache-2.0

## Cryptographic Research

### Original Papers
- **"Curve25519: new Diffie-Hellman speed records"** by Daniel J. Bernstein
- **"Ed25519: high-speed high-security signatures"** by Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, and Bo-Yin Yang
- **"Ristretto: prime order from non-prime order"** by Mike Hamburg
- **"The Complete Cost of Cofactor h = 1"** by Craig Costello and Benjamin Smith

### Standardization Efforts
- **RFC 7748** - Elliptic Curves for Security (X25519)
- **RFC 8032** - EdDSA Signature Algorithms (Ed25519)
- **RFC 9381** - Verifiable Random Functions (VRFs) using RSA and Elliptic Curves

## Security Research

### Side-Channel Analysis
- **"dudect: dude, is my code constant time?"** by Oscar Reparaz, Josep Balasch, and Ingrid Verbauwhede
- **"Constant-Time Implementations for Elliptic Curve Cryptography"** research community

### Formal Verification
- **fiat-crypto** project by MIT for formally verified cryptographic implementations
- **Project Everest** for formally verified cryptographic libraries

## Development Tools and Infrastructure

### Rust Ecosystem
- **The Rust Foundation** and **Rust Language Team** for creating a memory-safe systems programming language
- **subtle** crate for constant-time utilities
- **zeroize** crate for secure memory clearing
- **criterion** crate for benchmarking
- **proptest** crate for property-based testing

### Build and CI Tools
- **GitHub Actions** for continuous integration
- **cargo-audit** for security vulnerability scanning
- **clippy** for code quality analysis
- **rustfmt** for consistent code formatting

## Cryptographic Protocols

### Advanced Constructions
- **Bulletproofs** research by Benedikt Bünz, Jonathan Bootle, Dan Boneh, Andrew Poelstra, Pieter Wuille, and Greg Maxwell
- **Ring Signatures** research by Ronald L. Rivest, Adi Shamir, and Yael Tauman
- **Threshold Signatures** research community
- **Verifiable Random Functions** research by Silvio Micali, Michael Rabin, and Salil Vadhan

## Testing and Validation

### Test Vectors
- **Project Wycheproof** by Google for comprehensive cryptographic test vectors
- **IETF RFC test vectors** for standards compliance
- **NIST CAVP** test vectors for algorithm validation

### Cross-Validation
- **libsodium** for reference behavior validation
- **BoringSSL** for additional test cases
- **OpenSSL** for compatibility testing

## Community and Support

### Code Review and Feedback
- Rust Cryptography Working Group
- RustCrypto organization maintainers
- Security researchers and auditors
- Open source contributors and users

### Security Analysis
- Independent security researchers
- Cryptographic protocol analysts
- Side-channel attack specialists
- Formal verification experts

## Legal and Compliance

### Standards Bodies
- **Internet Engineering Task Force (IETF)** for protocol standardization
- **National Institute of Standards and Technology (NIST)** for cryptographic guidelines
- **International Organization for Standardization (ISO)** for security standards

### License Compatibility
All referenced work has been used in accordance with their respective open source licenses. gcrypt is released under the MIT License to ensure maximum compatibility and adoption.

## Responsible Disclosure

gcrypt follows responsible disclosure practices established by the security research community. We acknowledge the importance of coordinated vulnerability disclosure and maintain a security policy for reporting issues.

---

**Note:** This acknowledgment list reflects our gratitude to the broader cryptographic research and development community. If we have inadvertently omitted any significant contribution, please contact us to update this document.

**Disclaimer:** Acknowledgment does not imply endorsement of gcrypt by the mentioned individuals, organizations, or projects. All trademark and project names are the property of their respective owners.

---

*"If I have seen further it is by standing on the shoulders of Giants."* - Isaac Newton

The gcrypt project is made possible by the collective efforts of the cryptographic research community, open source developers, and security practitioners who have dedicated their work to advancing the state of secure computing.