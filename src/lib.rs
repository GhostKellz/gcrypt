//! # gcrypt
//!
//! A modern, pure Rust cryptographic library focusing on Curve25519 and related algorithms.
//!
//! This library provides:
//! - **Scalar arithmetic** modulo the order of the Curve25519 group
//! - **Point operations** on the Edwards form of Curve25519 (Ed25519)
//! - **Point operations** on the Montgomery form of Curve25519 (X25519)
//! - **Ristretto255** group operations for prime-order group abstraction
//! - **Modern Rust features** with const generics and latest language improvements
//! - **No-std support** with optional allocator features
//! - **SIMD acceleration** for high-performance batch operations
//! - **Formal verification** integration for mathematical correctness
//! - **Constant-time operations** for side-channel attack resistance
//!
//! ## API Stability
//!
//! **Version 0.2.0**: API is stabilizing toward 1.0 release.
//! See [`API_STABILITY.md`](https://github.com/CK-Technology/gcrypt/blob/main/API_STABILITY.md) 
//! for detailed stability guarantees and migration guidance.
//!
//! ## Features
//!
//! - `std` (default): Enable standard library support
//! - `alloc` (default): Enable allocator support for no-std environments  
//! - `rand_core` (default): Enable random number generation support
//! - `serde`: Enable serialization/deserialization support
//! - `zeroize`: Enable secure memory zeroing
//! - `group`: Enable compatibility with the `group` trait ecosystem
//! - `simd`: Enable SIMD vectorization for performance
//! - `fiat-crypto`: Enable formal verification integration
//! - `precomputed-tables`: Enable precomputed lookup tables for faster operations
//! - `aes-gcm`: Enable AES-GCM authenticated encryption support
//!
//! ## Example
//!
//! ```rust
//! use gcrypt::{Scalar, EdwardsPoint};
//!
//! // Generate a random scalar
//! let scalar = Scalar::random(&mut rand::thread_rng());
//!
//! // Scalar multiplication with the base point
//! let point = EdwardsPoint::mul_base(&scalar);
//!
//! // Point addition
//! let doubled = &point + &point;
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg, doc_cfg_hide))]
#![cfg_attr(docsrs, doc(cfg_hide(docsrs)))]
#![warn(
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
#![allow(non_snake_case)] // Allow mathematical notation in variable names

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// Internal macros - must come first
#[macro_use]
mod macros;

// Core modules
pub mod scalar;
pub mod field;
pub mod edwards;
pub mod montgomery;
pub mod ristretto;
pub mod constants;
pub mod traits;

// Cryptographic primitives
pub mod hash;
pub mod mac;
pub mod kdf;
pub mod aead;

// Wallet functionality
#[cfg(any(feature = "bip39", feature = "bip32"))]
pub mod wallet;

// Additional curve support
#[cfg(feature = "secp256k1")]
pub mod secp256k1;

#[cfg(feature = "secp256r1")]
pub mod p256;

#[cfg(feature = "bls12_381")]
pub mod bls12_381;

// Protocol implementations
pub mod protocols;

// Internal modules  
mod backend;
mod window;

// Re-exports for convenience
pub use crate::{
    edwards::EdwardsPoint,
    field::FieldElement,
    montgomery::MontgomeryPoint, 
    ristretto::RistrettoPoint,
    scalar::Scalar,
};

// Version information
pub mod version;
pub use version::{VERSION, version_info, api_compatibility, ApiCompatibility};

// Conditional re-exports based on features
#[cfg(feature = "rand_core")]
pub use rand_core;

#[cfg(feature = "group")]
pub use {group, ff};

#[cfg(feature = "aes-gcm")]
pub use aes_gcm;
