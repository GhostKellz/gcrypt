//! Advanced cryptographic protocols built on Curve25519
//!
//! This module implements higher-level cryptographic protocols that use
//! the underlying Curve25519 primitives for real-world applications.

pub mod ed25519;
pub mod x25519;
pub mod vrf;
pub mod ring_signatures;
pub mod threshold;
pub mod bulletproofs;
pub mod aes_gcm;
pub mod noise;
pub mod gossip;

// Phase 2 advanced protocols
pub mod bls;
pub mod schnorr;
pub mod shamir;
pub mod commitments;
pub mod merkle;

pub use ed25519::{SecretKey as Ed25519SecretKey, PublicKey as Ed25519PublicKey, Signature as Ed25519Signature, SignatureError as Ed25519SignatureError};
pub use x25519::{SecretKey as X25519SecretKey, PublicKey as X25519PublicKey, SharedSecret, KeyExchangeError};
pub use vrf::*;
pub use ring_signatures::*;
pub use threshold::*;
pub use bulletproofs::*;
pub use aes_gcm::*;
pub use noise::*;
pub use gossip::*;