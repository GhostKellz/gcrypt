//! Post-Quantum Cryptography
//!
//! This module provides implementations of post-quantum cryptographic
//! algorithms that are resistant to attacks by quantum computers.
//!
//! Features:
//! - Dilithium digital signatures (NIST standard)
//! - Kyber key encapsulation mechanism
//! - ML-KEM (Module Learning with Errors KEM)
//! - Hybrid classical/post-quantum schemes
//! - Migration utilities

pub mod dilithium;
pub mod kyber;
pub mod ml_kem;
pub mod hybrid;
pub mod lattice;

// Re-exports for convenience
pub use dilithium::*;
pub use kyber::*;
pub use ml_kem::*;
pub use hybrid::*;