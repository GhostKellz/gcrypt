//! Zero-Knowledge Proof Systems
//!
//! This module provides a comprehensive framework for zero-knowledge proof
//! systems, including zk-SNARKs, PLONK, and STARK primitives.
//!
//! Features:
//! - Generic proof system traits and interfaces
//! - zk-SNARKs primitives using arkworks
//! - PLONK proof system support
//! - STARK proof system primitives
//! - Circuit compilation and optimization
//! - Trusted setup management

pub mod primitives;
pub mod snarks;

#[cfg(feature = "plonk")]
pub mod plonk;

#[cfg(feature = "stark")]
pub mod stark;

pub mod circuits;
pub mod setup;

// Re-exports for convenience
pub use primitives::*;
pub use snarks::*;

#[cfg(feature = "plonk")]
pub use plonk::*;

#[cfg(feature = "stark")]
pub use stark::*;

pub use circuits::*;
pub use setup::*;