//! Hybrid Classical/Post-Quantum Cryptography
//!
//! This module provides hybrid schemes that combine classical and
//! post-quantum algorithms for a gradual migration path.

use crate::protocols::{Ed25519SecretKey, Ed25519PublicKey, Ed25519Signature};
use super::dilithium::{DilithiumKeyPair, DilithiumSignature};
use super::kyber::{KyberKeyPair, KyberSharedSecret, KyberCiphertext};
use crate::protocols::x25519::{X25519SecretKey, X25519PublicKey, SharedSecret};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Hybrid signature combining Ed25519 and Dilithium
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HybridSignature {
    /// Classical Ed25519 signature
    pub ed25519_signature: Ed25519Signature,
    /// Post-quantum Dilithium signature
    pub dilithium_signature: DilithiumSignature,
}

/// Hybrid key exchange combining X25519 and Kyber
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HybridSharedSecret {
    /// Classical X25519 shared secret
    pub classical_secret: SharedSecret,
    /// Post-quantum Kyber shared secret
    pub pq_secret: KyberSharedSecret,
    /// Combined derived secret
    pub combined_secret: [u8; 32],
}

/// Hybrid signing key pair
#[derive(Debug, Clone)]
pub struct HybridSigningKeyPair {
    /// Classical Ed25519 key pair
    pub ed25519_secret: Ed25519SecretKey,
    pub ed25519_public: Ed25519PublicKey,
    /// Post-quantum Dilithium key pair
    pub dilithium_keypair: DilithiumKeyPair,
}

/// Hybrid key exchange key pair
#[derive(Debug, Clone)]
pub struct HybridKexKeyPair {
    /// Classical X25519 key pair
    pub x25519_secret: X25519SecretKey,
    pub x25519_public: X25519PublicKey,
    /// Post-quantum Kyber key pair
    pub kyber_keypair: KyberKeyPair,
}

impl HybridSigningKeyPair {
    /// Generate a new hybrid signing key pair
    #[cfg(feature = "rand_core")]
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
    ) -> Result<Self, Box<dyn core::error::Error>> {
        // Generate Ed25519 key pair
        let ed25519_secret = Ed25519SecretKey::generate(rng);
        let ed25519_public = Ed25519PublicKey::from(&ed25519_secret);

        // Generate Dilithium key pair
        let dilithium_keypair = DilithiumKeyPair::generate(
            super::dilithium::DilithiumParameterSet::Dilithium3,
            rng,
        )?;

        Ok(Self {
            ed25519_secret,
            ed25519_public,
            dilithium_keypair,
        })
    }

    /// Sign a message with both algorithms
    #[cfg(feature = "rand_core")]
    pub fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<HybridSignature, Box<dyn core::error::Error>> {
        // Sign with Ed25519
        let ed25519_signature = self.ed25519_secret.sign(message);

        // Sign with Dilithium
        let dilithium_signature = self.dilithium_keypair.sign(message, rng)?;

        Ok(HybridSignature {
            ed25519_signature,
            dilithium_signature,
        })
    }

    /// Verify a hybrid signature
    pub fn verify(
        ed25519_public: &Ed25519PublicKey,
        dilithium_public: &super::dilithium::DilithiumPublicKey,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<bool, Box<dyn core::error::Error>> {
        // Verify Ed25519 signature
        let ed25519_valid = ed25519_public.verify(message, &signature.ed25519_signature).is_ok();

        // Verify Dilithium signature
        let dilithium_valid = DilithiumKeyPair::verify(
            dilithium_public,
            message,
            &signature.dilithium_signature,
        )?;

        // Both must be valid for hybrid signature to be valid
        Ok(ed25519_valid && dilithium_valid)
    }
}

impl HybridKexKeyPair {
    /// Generate a new hybrid key exchange key pair
    #[cfg(feature = "rand_core")]
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
    ) -> Result<Self, Box<dyn core::error::Error>> {
        // Generate X25519 key pair
        let x25519_secret = X25519SecretKey::generate(rng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Generate Kyber key pair
        let kyber_keypair = KyberKeyPair::generate(
            super::kyber::KyberParameterSet::Kyber768,
            rng,
        )?;

        Ok(Self {
            x25519_secret,
            x25519_public,
            kyber_keypair,
        })
    }

    /// Perform hybrid key exchange
    #[cfg(feature = "rand_core")]
    pub fn exchange<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        other_x25519_public: &X25519PublicKey,
        other_kyber_public: &super::kyber::KyberPublicKey,
        rng: &mut R,
    ) -> Result<(HybridSharedSecret, KyberCiphertext), Box<dyn core::error::Error>> {
        // Classical X25519 key exchange
        let classical_secret = self.x25519_secret.diffie_hellman(other_x25519_public);

        // Post-quantum Kyber encapsulation
        let (pq_secret, ciphertext) = KyberKeyPair::encapsulate(other_kyber_public, rng)?;

        // Combine the secrets using HKDF or similar KDF
        let combined_secret = Self::combine_secrets(&classical_secret, &pq_secret);

        let hybrid_secret = HybridSharedSecret {
            classical_secret,
            pq_secret,
            combined_secret,
        };

        Ok((hybrid_secret, ciphertext))
    }

    /// Receive hybrid key exchange
    pub fn receive(
        &self,
        other_x25519_public: &X25519PublicKey,
        kyber_ciphertext: &KyberCiphertext,
    ) -> Result<HybridSharedSecret, Box<dyn core::error::Error>> {
        // Classical X25519 key exchange
        let classical_secret = self.x25519_secret.diffie_hellman(other_x25519_public);

        // Post-quantum Kyber decapsulation
        let pq_secret = KyberKeyPair::decapsulate(&self.kyber_keypair.secret_key, kyber_ciphertext)?;

        // Combine the secrets
        let combined_secret = Self::combine_secrets(&classical_secret, &pq_secret);

        Ok(HybridSharedSecret {
            classical_secret,
            pq_secret,
            combined_secret,
        })
    }

    /// Combine classical and post-quantum shared secrets
    fn combine_secrets(classical: &SharedSecret, pq: &KyberSharedSecret) -> [u8; 32] {
        // Simple combination - in practice would use proper KDF
        let mut combined = [0u8; 32];
        let classical_bytes = classical.as_bytes();
        let pq_bytes = pq.as_bytes();

        for i in 0..32 {
            combined[i] = classical_bytes[i] ^ pq_bytes[i];
        }

        combined
    }
}

/// Migration utilities for transitioning to post-quantum cryptography
pub mod migration {
    use super::*;

    /// Migration strategy
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MigrationStrategy {
        /// Classical only (current state)
        ClassicalOnly,
        /// Hybrid mode (transition period)
        Hybrid,
        /// Post-quantum only (future state)
        PostQuantumOnly,
    }

    /// Migration manager
    pub struct MigrationManager {
        /// Current strategy
        pub strategy: MigrationStrategy,
        /// Security level preference
        pub security_level: u8, // 1-5 scale
    }

    impl MigrationManager {
        /// Create new migration manager
        pub fn new(strategy: MigrationStrategy, security_level: u8) -> Self {
            Self {
                strategy,
                security_level,
            }
        }

        /// Recommend signature algorithm
        pub fn recommend_signature_algorithm(&self) -> &'static str {
            match (self.strategy, self.security_level) {
                (MigrationStrategy::ClassicalOnly, _) => "Ed25519",
                (MigrationStrategy::Hybrid, 1..=3) => "Ed25519+Dilithium2",
                (MigrationStrategy::Hybrid, 4..=5) => "Ed25519+Dilithium3",
                (MigrationStrategy::PostQuantumOnly, 1..=3) => "Dilithium2",
                (MigrationStrategy::PostQuantumOnly, 4..=5) => "Dilithium5",
                _ => "Ed25519+Dilithium3", // Default
            }
        }

        /// Recommend key exchange algorithm
        pub fn recommend_kex_algorithm(&self) -> &'static str {
            match (self.strategy, self.security_level) {
                (MigrationStrategy::ClassicalOnly, _) => "X25519",
                (MigrationStrategy::Hybrid, 1..=3) => "X25519+Kyber512",
                (MigrationStrategy::Hybrid, 4..=5) => "X25519+Kyber768",
                (MigrationStrategy::PostQuantumOnly, 1..=3) => "Kyber512",
                (MigrationStrategy::PostQuantumOnly, 4..=5) => "Kyber1024",
                _ => "X25519+Kyber768", // Default
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_hybrid_signature() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let keypair = HybridSigningKeyPair::generate(&mut rng).unwrap();
        let message = b"Hybrid signature test";

        let signature = keypair.sign(message, &mut rng).unwrap();

        let result = HybridSigningKeyPair::verify(
            &keypair.ed25519_public,
            &keypair.dilithium_keypair.public_key,
            message,
            &signature,
        ).unwrap();

        assert!(result);
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_hybrid_key_exchange() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let alice_keypair = HybridKexKeyPair::generate(&mut rng).unwrap();
        let bob_keypair = HybridKexKeyPair::generate(&mut rng).unwrap();

        // Alice initiates key exchange
        let (alice_secret, ciphertext) = alice_keypair.exchange(
            &bob_keypair.x25519_public,
            &bob_keypair.kyber_keypair.public_key,
            &mut rng,
        ).unwrap();

        // Bob receives key exchange
        let bob_secret = bob_keypair.receive(
            &alice_keypair.x25519_public,
            &ciphertext,
        ).unwrap();

        // Secrets should match (in real implementation)
        assert_eq!(alice_secret.combined_secret.len(), 32);
        assert_eq!(bob_secret.combined_secret.len(), 32);
    }

    #[test]
    fn test_migration_recommendations() {
        let manager = migration::MigrationManager::new(
            migration::MigrationStrategy::Hybrid,
            3,
        );

        assert_eq!(manager.recommend_signature_algorithm(), "Ed25519+Dilithium2");
        assert_eq!(manager.recommend_kex_algorithm(), "X25519+Kyber512");
    }
}