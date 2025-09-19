//! ML-KEM (Module Learning with Errors Key Encapsulation Mechanism)
//!
//! NIST standardized version of Kyber with specific parameter sets.

pub use super::kyber::{KyberError as MlKemError, KyberSharedSecret as MlKemSharedSecret};
use super::kyber::{KyberKeyPair, KyberParameterSet};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String};

/// ML-KEM parameter sets (standardized)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemParameterSet {
    /// ML-KEM-512 (128-bit security)
    MlKem512,
    /// ML-KEM-768 (192-bit security)
    MlKem768,
    /// ML-KEM-1024 (256-bit security)
    MlKem1024,
}

impl From<MlKemParameterSet> for KyberParameterSet {
    fn from(params: MlKemParameterSet) -> Self {
        match params {
            MlKemParameterSet::MlKem512 => KyberParameterSet::Kyber512,
            MlKemParameterSet::MlKem768 => KyberParameterSet::Kyber768,
            MlKemParameterSet::MlKem1024 => KyberParameterSet::Kyber1024,
        }
    }
}

/// ML-KEM implementation (wrapper around Kyber)
pub struct MlKem;

impl MlKem {
    /// Generate ML-KEM key pair
    #[cfg(feature = "rand_core")]
    pub fn keygen<R: rand_core::RngCore + rand_core::CryptoRng>(
        params: MlKemParameterSet,
        rng: &mut R,
    ) -> Result<KyberKeyPair, MlKemError> {
        KyberKeyPair::generate(params.into(), rng)
    }

    /// Encapsulate shared secret
    #[cfg(feature = "rand_core")]
    pub fn encaps<R: rand_core::RngCore + rand_core::CryptoRng>(
        public_key: &super::kyber::KyberPublicKey,
        rng: &mut R,
    ) -> Result<(MlKemSharedSecret, super::kyber::KyberCiphertext), MlKemError> {
        KyberKeyPair::encapsulate(public_key, rng)
    }

    /// Decapsulate shared secret
    pub fn decaps(
        secret_key: &super::kyber::KyberSecretKey,
        ciphertext: &super::kyber::KyberCiphertext,
    ) -> Result<MlKemSharedSecret, MlKemError> {
        KyberKeyPair::decapsulate(secret_key, ciphertext)
    }
}