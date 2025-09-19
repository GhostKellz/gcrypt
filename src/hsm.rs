//! Hardware Security Module (HSM) Integration
//!
//! This module provides a framework for integrating with hardware security
//! modules and secure enclaves for enhanced key protection.

pub mod pkcs11;
pub mod tpm;
pub mod enclave;
pub mod traits;

// Re-exports for convenience
pub use traits::*;
pub use pkcs11::*;
pub use tpm::*;
pub use enclave::*;