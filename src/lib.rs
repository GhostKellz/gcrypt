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
//! ### Ghostchain Ecosystem Features
//!
//! - `gquic-transport`: GQUIC transport layer integration for high-performance networking
//! - `guardian-framework`: Zero-trust authentication framework for secure gRPC services
//! - `zk-hash`: ZK-friendly hash functions (Poseidon, Rescue, MiMC, Pedersen)
//! - `batch-operations`: High-throughput batch operations for DeFi protocols
//! - `parallel`: Parallel processing support using Rayon
//!
//! ## Examples
//!
//! ### Basic Cryptographic Operations
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
//!
//! ### Ghostchain Ecosystem Features
//!
//! ```rust
//! # #[cfg(all(feature = "guardian-framework", feature = "gquic-transport"))]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use gcrypt::guardian::{GuardianIssuer, Did, Permission};
//! use gcrypt::transport::GquicTransport;
//!
//! // Create a Guardian token for authentication
//! let issuer = GuardianIssuer::new(secret_key);
//! let did = Did::new("ghostchain".to_string(), "user123".to_string())?;
//! let permissions = vec![Permission::new("ghostd".to_string(), vec!["read".to_string()])];
//! let token = issuer.issue_token(did, permissions, 3600)?;
//!
//! // Use GQUIC transport for high-performance networking
//! let transport = GquicTransport::new();
//! let encrypted = transport.encrypt_packet(&mut session, plaintext, additional_data)?;
//! # Ok(())
//! # }
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

// Phase 3 advanced cryptographic modules
#[cfg(feature = "zk-snarks")]
pub mod zk;

#[cfg(feature = "post-quantum")]
pub mod post_quantum;

#[cfg(feature = "mpc")]
pub mod mpc;

#[cfg(feature = "hsm")]
pub mod hsm;

// Ghostchain ecosystem modules
#[cfg(feature = "gquic-transport")]
pub mod transport;

#[cfg(feature = "guardian-framework")]
pub mod guardian;

#[cfg(feature = "zk-hash")]
pub mod zk_hash;

#[cfg(feature = "batch-operations")]
pub mod batch;

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
