# Legal Compliance Documentation

This document provides comprehensive legal compliance information for the gcrypt cryptographic library.

## Table of Contents

- [License Overview](#license-overview)
- [Export Compliance](#export-compliance)
- [Patent Considerations](#patent-considerations)
- [Dependency Licensing](#dependency-licensing)
- [Compliance Checklist](#compliance-checklist)
- [Security Compliance](#security-compliance)
- [Usage Guidelines](#usage-guidelines)

## License Overview

### Dual Licensing

gcrypt is dual-licensed under:
- **MIT License** - Permissive, simple, widely compatible
- **Apache License 2.0** - Permissive with patent grant

Users may choose either license based on their needs:
- Choose **MIT** for maximum compatibility and simplicity
- Choose **Apache 2.0** for explicit patent protection

### License Compatibility

gcrypt can be used in:
- ✅ Open source projects (any OSI-approved license)
- ✅ Proprietary/commercial software
- ✅ GPL-licensed projects (via MIT license)
- ✅ Apache-licensed projects
- ✅ Embedded systems
- ✅ Cloud services

### Attribution Requirements

**MIT License**: Include copyright notice and permission notice
**Apache 2.0**: Include copyright notice, license copy, and NOTICE file (if applicable)

## Export Compliance

### U.S. Export Classification

gcrypt implements publicly available cryptographic algorithms and is classified as:
- **ECCN**: 5D002 (publicly available encryption software)
- **License Exception**: TSU (Technology and Software - Unrestricted)

### Notification Requirements

As open-source cryptographic software, gcrypt qualifies for:
- TSU exception under EAR 740.13(e)
- No BIS notification required for public domain software
- Self-classification as 5D002 with TSU exception

### International Compliance

**Wassenaar Arrangement**: Category 5, Part 2 (Information Security)
- Publicly available software exception applies
- No export license required for public domain

**Country-Specific Restrictions**:
- 🚫 Not for export to embargoed countries (see current OFAC list)
- ⚠️ Some countries restrict cryptographic imports (check local laws)
- ✅ EU: No restrictions for open-source cryptography
- ✅ Most countries: Legal for publicly available software

### Compliance Statement

```
This software contains cryptographic functionality. The export of this
software may be restricted by the laws and regulations of your country.
It is the responsibility of any user of this software to ensure compliance
with all applicable export control laws and regulations.

The cryptographic algorithms implemented are:
- Curve25519 (key exchange)
- Ed25519 (digital signatures)
- X25519 (ECDH)
- SHA-512 (hashing)

All algorithms are publicly published and widely available.
```

## Patent Considerations

### Patent Status

To the best of our knowledge:
- **Curve25519**: No known patents, designed to avoid patent issues
- **Ed25519**: No known patents, uses publicly available algorithms
- **X25519**: No known patents
- **Ristretto**: No known patents

### Patent Grant (Apache 2.0)

Users choosing Apache 2.0 license receive:
- Express patent grant from all contributors
- Protection against patent litigation
- Automatic license termination for patent aggressors

### Defensive Publication

This software serves as prior art for:
- Implementation techniques described herein
- Optimization methods documented
- API design patterns

## Dependency Licensing

### Direct Dependencies

| Crate | Version | License | Type | Notes |
|-------|---------|---------|------|-------|
| subtle | 2.5 | BSD-3-Clause | Required | Constant-time utilities |
| rand_core | 0.6 | MIT/Apache-2.0 | Optional | RNG traits |
| zeroize | 1.7 | MIT/Apache-2.0 | Optional | Secure memory clearing |
| serde | 1.0 | MIT/Apache-2.0 | Optional | Serialization |
| cfg-if | 1.0 | MIT/Apache-2.0 | Required | Conditional compilation |

### License Compatibility Matrix

| Your License | MIT | Apache-2.0 | GPL-2.0 | GPL-3.0 | BSD | Proprietary |
|--------------|-----|------------|---------|---------|-----|-------------|
| Can Use gcrypt | ✅ | ✅ | ✅* | ✅ | ✅ | ✅ |

*Via MIT license option

### Transitive Dependencies

All transitive dependencies have been reviewed for:
- License compatibility
- Security vulnerabilities
- Export compliance
- Patent issues

## Compliance Checklist

### For Open Source Projects

- [ ] Include LICENSE file (MIT or LICENSE-APACHE)
- [ ] Preserve copyright notices
- [ ] Acknowledge gcrypt in documentation
- [ ] Comply with dependency licenses
- [ ] No additional requirements

### For Commercial Use

- [ ] Choose appropriate license (MIT or Apache 2.0)
- [ ] Include required notices in distribution
- [ ] Review export compliance for your jurisdiction
- [ ] No royalty or fee requirements
- [ ] Optional: Consider support agreement

### For Government Use

- [ ] Verify cryptographic algorithm approval (FIPS, etc.)
- [ ] Check security clearance requirements
- [ ] Validate against approved product lists
- [ ] Review source code if required
- [ ] Document compliance attestation

## Security Compliance

### Standards Compliance

gcrypt aims for compliance with:
- **NIST SP 800-186**: Elliptic curve recommendations
- **RFC 7748**: X25519 specification
- **RFC 8032**: Ed25519 specification
- **FIPS 140-2**: Level 1 algorithmic validation (planned)

### Security Certifications

**Current Status**:
- ✅ Constant-time implementation verified
- ✅ Memory safety guaranteed by Rust
- ✅ Side-channel resistant design
- 🔄 FIPS validation planned
- 🔄 Common Criteria evaluation considered

### Vulnerability Disclosure

- **CVE Process**: Will request CVEs for any security issues
- **Security Policy**: See SECURITY.md
- **Responsible Disclosure**: 90-day disclosure period
- **Security Contact**: security@gcrypt.rs

## Usage Guidelines

### Acceptable Use

gcrypt may be used for:
- ✅ Secure communications
- ✅ Authentication systems
- ✅ Digital signatures
- ✅ Key agreement protocols
- ✅ Cryptocurrency applications
- ✅ Security research
- ✅ Educational purposes

### Restricted Use

Users must NOT use gcrypt for:
- 🚫 Illegal activities in their jurisdiction
- 🚫 Violating export control laws
- 🚫 Breaking terms of service agreements
- 🚫 Circumventing legal access controls

### Compliance Responsibility

Users are responsible for:
1. Ensuring legal use in their jurisdiction
2. Complying with export/import laws
3. Meeting industry-specific regulations
4. Obtaining necessary approvals

## Legal Notices

### Disclaimer of Warranty

```
THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

### Limitation of Liability

```
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### Indemnification

Users agree to indemnify and hold harmless the gcrypt contributors from any claims arising from:
- Violation of export laws
- Patent infringement claims
- Misuse of the software
- Non-compliance with regulations

## Compliance Resources

### Export Control
- [BIS Encryption FAQ](https://www.bis.doc.gov/index.php/policy-guidance/encryption)
- [EAR Guidelines](https://www.bis.doc.gov/index.php/regulations/export-administration-regulations-ear)
- [Wassenaar Arrangement](https://www.wassenaar.org/)

### Standards
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [IETF Security Area](https://datatracker.ietf.org/wg/#sec)
- [FIPS Publications](https://csrc.nist.gov/publications/fips)

### Legal Assistance
- [Software Freedom Law Center](https://softwarefreedom.org/)
- [Open Source Initiative](https://opensource.org/licenses)
- [SPDX License List](https://spdx.org/licenses/)

## Updates and Amendments

This legal compliance documentation is maintained at:
https://github.com/CK-Technology/gcrypt/blob/main/LEGAL.md

Last updated: December 2024
Next review: June 2025

For legal questions, contact: legal@gcrypt.rs