//! Zero-Knowledge Friendly Hash Functions
//!
//! This module provides hash functions that are optimized for use in
//! zero-knowledge proof systems, with low multiplicative complexity
//! in arithmetic circuits.

pub mod poseidon;
pub mod rescue;
pub mod mimc;
pub mod pedersen;

// Re-exports for convenience
pub use poseidon::*;
pub use rescue::*;
pub use mimc::*;
pub use pedersen::*;