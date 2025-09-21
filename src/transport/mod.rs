//! High-performance transport layer cryptography for Ghostchain ecosystem
//!
//! This module provides cryptographic support for various transport protocols
//! used across the Ghostchain ecosystem, with special focus on GQUIC transport
//! for high-throughput networking.

pub mod gquic;
pub mod session;

// Re-exports for convenience
pub use gquic::*;
pub use session::*;