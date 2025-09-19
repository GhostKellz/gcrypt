//! Multi-Party Computation (MPC) Protocols
//!
//! This module provides implementations of secure multi-party computation
//! protocols for collaborative cryptographic operations.

pub mod threshold_ecdsa;
pub mod secret_sharing;
pub mod secure_aggregation;
pub mod oblivious_transfer;

// Re-exports for convenience
pub use threshold_ecdsa::*;
pub use secret_sharing::*;
pub use secure_aggregation::*;
pub use oblivious_transfer::*;