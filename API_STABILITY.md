# gcrypt API Stability and Semantic Versioning

## API Stability Guarantee

### Current Version: 0.1.0 (Pre-release)

gcrypt follows [Semantic Versioning 2.0.0](https://semver.org/) with the following stability guarantees:

## 🔒 **Stable Public API** (Version 1.0.0+)

### Core Types (Stable)
```rust
// These types are considered stable and will not change in breaking ways
pub struct FieldElement { /* ... */ }
pub struct Scalar { /* ... */ }
pub struct EdwardsPoint { /* ... */ }
pub struct MontgomeryPoint { /* ... */ }
pub struct RistrettoPoint { /* ... */ }
pub struct CompressedEdwardsY { /* ... */ }
pub struct CompressedMontgomery { /* ... */ }
pub struct CompressedRistretto { /* ... */ }
```

### Core Operations (Stable)
```rust
// Arithmetic operations - API guaranteed stable
impl Add for FieldElement { /* ... */ }
impl Mul for FieldElement { /* ... */ }
impl Sub for FieldElement { /* ... */ }
impl Neg for FieldElement { /* ... */ }

impl Add for Scalar { /* ... */ }
impl Mul for Scalar { /* ... */ }
impl Sub for Scalar { /* ... */ }

impl Add for EdwardsPoint { /* ... */ }
impl Mul<Scalar> for EdwardsPoint { /* ... */ }
impl Neg for EdwardsPoint { /* ... */ }
```

### Construction and Conversion (Stable)
```rust
// Safe constructors - API guaranteed stable
impl FieldElement {
    pub const ZERO: FieldElement;
    pub const ONE: FieldElement;
    pub const MINUS_ONE: FieldElement;
    
    pub fn from_bytes(bytes: &[u8; 32]) -> FieldElement;
    pub fn to_bytes(&self) -> [u8; 32];
    pub fn from_bytes_mod_order(bytes: &[u8; 32]) -> FieldElement;
    pub fn is_zero(&self) -> bool;
    pub fn is_one(&self) -> bool;
    pub fn square(&self) -> FieldElement;
    pub fn invert(&self) -> CtOption<FieldElement>;
    pub fn sqrt(&self) -> CtOption<FieldElement>;
    pub fn pow(&self, exp: &[u64]) -> FieldElement;
}

impl Scalar {
    pub const ZERO: Scalar;
    pub const ONE: Scalar;
    
    pub fn from_bytes_mod_order(bytes: &[u8; 32]) -> Scalar;
    pub fn from_canonical_bytes(bytes: &[u8; 32]) -> CtOption<Scalar>;
    pub fn to_bytes(&self) -> [u8; 32];
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Scalar;
    pub fn is_zero(&self) -> bool;
    pub fn invert(&self) -> CtOption<Scalar>;
}

impl EdwardsPoint {
    pub const IDENTITY: EdwardsPoint;
    
    pub fn basepoint() -> EdwardsPoint;
    pub fn mul_base(scalar: &Scalar) -> EdwardsPoint;
    pub fn compress(&self) -> CompressedEdwardsY;
    pub fn is_identity(&self) -> bool;
    pub fn is_torsion_free(&self) -> bool;
    pub fn is_on_curve(&self) -> bool;
}

impl CompressedEdwardsY {
    pub fn decompress(&self) -> CtOption<EdwardsPoint>;
    pub fn to_bytes(&self) -> [u8; 32];
    pub fn from_bytes(bytes: &[u8; 32]) -> CompressedEdwardsY;
}
```

## 🔄 **Versioning Strategy**

### Pre-1.0 (Current: 0.1.0)
- **Breaking changes allowed** in minor versions (0.1.x → 0.2.x)
- **API stabilization** in progress
- **Deprecation warnings** for APIs that will change

### Post-1.0 (Stable)
- **Breaking changes** only in major versions (1.x → 2.x)
- **New features** in minor versions (1.0 → 1.1)
- **Bug fixes** in patch versions (1.0.0 → 1.0.1)

## 📋 **API Categories**

### Tier 1: Core Stable APIs
These APIs are frozen and will not change:
- Basic arithmetic operations (`+`, `-`, `*`, `/`)
- Core type definitions (`FieldElement`, `Scalar`, `EdwardsPoint`)
- RFC-compliant constructors and conversions
- Constant-time operations and comparisons

### Tier 2: Stable with Extensions
These APIs are stable but may gain new methods:
- Trait implementations (`From`, `Into`, `Display`, etc.)
- Additional constructors for convenience
- Performance optimizations (internal only)

### Tier 3: Experimental APIs
These APIs may change before 1.0:
- SIMD backend selection
- Advanced protocol implementations
- Formal verification integration
- Custom backend APIs

## 🛡️ **Breaking Change Policy**

### What Constitutes a Breaking Change
1. **Removing public APIs** or changing their signatures
2. **Changing behavior** of existing functions
3. **Adding new required generic parameters**
4. **Changing error types** or error conditions
5. **Modifying trait implementations** in incompatible ways

### What Does NOT Constitute a Breaking Change
1. **Adding new public APIs** (methods, functions, types)
2. **Adding new optional generic parameters** with defaults
3. **Adding new trait implementations**
4. **Performance improvements** that don't change behavior
5. **Internal implementation changes**
6. **Documentation improvements**

## 📖 **Migration Guide Framework**

### Version Migration Pattern
```rust
// Version 0.1.x to 0.2.x example
// OLD (deprecated in 0.1.5, removed in 0.2.0):
let point = EdwardsPoint::from_uniform_bytes(&bytes);

// NEW (available since 0.1.5):
let point = EdwardsPoint::from_bytes_mod_order(&bytes);
```

### Deprecation Timeline
1. **Deprecation announcement** - 1 minor version before removal
2. **Deprecation warnings** - Compile-time warnings added
3. **Migration documentation** - Clear upgrade path provided
4. **Removal** - Only in next major version

## 🔍 **API Review Process**

### New API Checklist
- [ ] **Memory safe** - No unsafe operations in public API
- [ ] **Constant time** - All cryptographic operations are constant-time
- [ ] **Well documented** - Comprehensive documentation with examples
- [ ] **Tested** - Property-based and unit tests
- [ ] **Consistent** - Follows established naming conventions
- [ ] **Minimal** - No unnecessary complexity
- [ ] **Composable** - Works well with other APIs

### API Design Principles
1. **Security first** - Security over convenience
2. **Fail safe** - Errors should be obvious, not silent
3. **Minimal surface** - Smaller API surface = fewer bugs
4. **Consistent naming** - Follow Rust naming conventions
5. **Zero-cost abstractions** - No runtime overhead
6. **Composable** - APIs should work together naturally

## 📊 **Stability Matrix**

| Component | Stability | Version | Notes |
|-----------|-----------|---------|-------|
| `FieldElement` | 🟢 Stable | 1.0+ | Core arithmetic operations |
| `Scalar` | 🟢 Stable | 1.0+ | Scalar field operations |
| `EdwardsPoint` | 🟢 Stable | 1.0+ | Edwards curve points |
| `MontgomeryPoint` | 🟡 Stabilizing | 0.2+ | X25519 key exchange |
| `RistrettoPoint` | 🟡 Stabilizing | 0.2+ | Prime-order group |
| SIMD backends | 🔴 Experimental | 0.x | Performance optimizations |
| Formal verification | 🔴 Experimental | 0.x | Optional verification layer |

## 🚀 **Roadmap to 1.0**

### 0.2.0 - API Refinement
- [ ] Stabilize Montgomery and Ristretto APIs
- [ ] Add comprehensive input validation
- [ ] Implement all missing trait implementations
- [ ] Add batch operation APIs

### 0.3.0 - Performance & Features
- [ ] Finalize SIMD backend APIs
- [ ] Add multi-scalar multiplication
- [ ] Implement constant-time guarantees
- [ ] Add serialization support

### 0.4.0 - Security Hardening
- [ ] Complete constant-time validation
- [ ] Add fuzzing infrastructure
- [ ] Implement side-channel testing
- [ ] Security audit integration

### 1.0.0 - Stable Release
- [ ] API freeze
- [ ] Comprehensive documentation
- [ ] Performance benchmarks
- [ ] Security certifications

## 📝 **API Documentation Standards**

### Required Documentation
```rust
/// Brief one-line description of the function
///
/// Longer description explaining the purpose, behavior, and any important
/// details about the function. Include mathematical context if relevant.
///
/// # Arguments
/// 
/// * `param1` - Description of the first parameter
/// * `param2` - Description of the second parameter
///
/// # Returns
///
/// Description of the return value and its meaning
///
/// # Examples
///
/// ```rust
/// use gcrypt::FieldElement;
/// 
/// let a = FieldElement::from_bytes(&[1u8; 32]);
/// let b = FieldElement::from_bytes(&[2u8; 32]);
/// let sum = &a + &b;
/// ```
///
/// # Security
///
/// This operation is performed in constant time and is resistant to 
/// timing attacks.
///
/// # Panics
///
/// This function panics if... (describe panic conditions)
///
/// # Errors
///
/// This function returns an error if... (describe error conditions)
pub fn example_function(param1: Type1, param2: Type2) -> Result<ReturnType, Error> {
    // Implementation
}
```

## 🔧 **Backward Compatibility Testing**

### Automated Compatibility Checks
```rust
// Integration tests to ensure API compatibility
#[test]
fn test_api_compatibility_v0_1() {
    // Test that old API patterns still work
    let scalar = Scalar::from_bytes_mod_order(&[1u8; 32]);
    let point = EdwardsPoint::mul_base(&scalar);
    let compressed = point.compress();
    assert!(compressed.decompress().is_some());
}
```

### Compatibility Matrix
| gcrypt Version | Rust Version | Features | Status |
|----------------|--------------|----------|--------|
| 0.1.x | 1.85+ | Core APIs | ✅ Supported |
| 0.2.x | 1.85+ | Extended APIs | 🔄 In Development |
| 1.0.x | 1.85+ | Stable APIs | 📋 Planned |

## 📞 **Contact and Feedback**

For API stability questions or suggestions:
- **Issue Tracker**: https://github.com/CK-Technology/gcrypt/issues
- **API Discussion**: Use the `api-design` label
- **Breaking Change Proposals**: Use the `breaking-change` label

---

*This document is living and will be updated as the API evolves toward the 1.0 release.*