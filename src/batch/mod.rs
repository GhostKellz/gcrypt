//! High-Performance Batch Operations
//!
//! This module provides batch operations optimized for high-throughput
//! scenarios like DeFi protocols, DEX order books, and validator operations.

pub mod signatures;
pub mod verification;
pub mod arithmetic;
pub mod merkle;

// Re-exports for convenience
pub use signatures::*;
pub use verification::*;
pub use arithmetic::*;
pub use merkle::*;