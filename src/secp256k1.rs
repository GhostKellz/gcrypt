//! Secp256k1 elliptic curve operations
//!
//! This module provides a high-level interface to secp256k1 operations,
//! commonly used in Bitcoin and Ethereum ecosystems.

#[cfg(feature = "secp256k1")]
pub use secp256k1;

#[cfg(feature = "secp256k1")]
use secp256k1::{PublicKey as Secp256k1PublicKey, SecretKey as Secp256k1SecretKey};

#[cfg(feature = "secp256k1")]
use core::fmt;

/// A secp256k1 private key wrapper
#[cfg(feature = "secp256k1")]
#[derive(Clone, Debug)]
pub struct PrivateKey {
    /// The underlying secp256k1 secret key
    pub(crate) secret_key: Secp256k1SecretKey,
}

/// A secp256k1 public key wrapper
#[cfg(feature = "secp256k1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// The underlying secp256k1 public key
    pub(crate) public_key: Secp256k1PublicKey,
}

/// ECDSA signature using secp256k1
#[cfg(feature = "secp256k1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcdsaSignature {
    /// The underlying secp256k1 ECDSA signature
    pub(crate) signature: secp256k1::ecdsa::Signature,
}

/// Recoverable ECDSA signature (includes recovery ID)
#[cfg(feature = "secp256k1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoverableSignature {
    /// The underlying recoverable signature
    pub(crate) signature: secp256k1::ecdsa::RecoverableSignature,
}

/// Secp256k1 operation errors
#[cfg(feature = "secp256k1")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secp256k1Error {
    /// Invalid private key
    InvalidSecretKey,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid signature
    InvalidSignature,
    /// Invalid message hash
    InvalidMessage,
    /// Recovery failed
    RecoveryFailed,
}

#[cfg(feature = "secp256k1")]
impl fmt::Display for Secp256k1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Secp256k1Error::InvalidSecretKey => write!(f, "Invalid secret key"),
            Secp256k1Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Secp256k1Error::InvalidSignature => write!(f, "Invalid signature"),
            Secp256k1Error::InvalidMessage => write!(f, "Invalid message hash"),
            Secp256k1Error::RecoveryFailed => write!(f, "Public key recovery failed"),
        }
    }
}

#[cfg(feature = "secp256k1")]
impl PrivateKey {
    /// Generate a new random private key
    #[cfg(feature = "rand_core")]
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> PrivateKey {
        let secret_key = Secp256k1SecretKey::new(rng);
        PrivateKey { secret_key }
    }

    /// Create a private key from 32 bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<PrivateKey, Secp256k1Error> {
        let secret_key = Secp256k1SecretKey::from_slice(bytes)
            .map_err(|_| Secp256k1Error::InvalidSecretKey)?;
        Ok(PrivateKey { secret_key })
    }

    /// Convert to 32 bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret_key[..].try_into().unwrap()
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        let public_key = Secp256k1PublicKey::from_secret_key(&secp, &self.secret_key);
        PublicKey { public_key }
    }

    /// Sign a message hash with ECDSA
    pub fn sign_ecdsa(&self, message_hash: &[u8; 32]) -> Result<EcdsaSignature, Secp256k1Error> {
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(message_hash)
            .map_err(|_| Secp256k1Error::InvalidMessage)?;

        let signature = secp.sign_ecdsa(&message, &self.secret_key);
        Ok(EcdsaSignature { signature })
    }

    /// Sign a message hash with recoverable ECDSA
    pub fn sign_ecdsa_recoverable(&self, message_hash: &[u8; 32]) -> Result<RecoverableSignature, Secp256k1Error> {
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(message_hash)
            .map_err(|_| Secp256k1Error::InvalidMessage)?;

        let signature = secp.sign_ecdsa_recoverable(&message, &self.secret_key);
        Ok(RecoverableSignature { signature })
    }
}

#[cfg(feature = "secp256k1")]
impl PublicKey {
    /// Create a public key from SEC1 compressed bytes (33 bytes)
    pub fn from_compressed_bytes(bytes: &[u8; 33]) -> Result<PublicKey, Secp256k1Error> {
        let public_key = Secp256k1PublicKey::from_slice(bytes)
            .map_err(|_| Secp256k1Error::InvalidPublicKey)?;
        Ok(PublicKey { public_key })
    }

    /// Create a public key from SEC1 uncompressed bytes (65 bytes)
    pub fn from_uncompressed_bytes(bytes: &[u8; 65]) -> Result<PublicKey, Secp256k1Error> {
        let public_key = Secp256k1PublicKey::from_slice(bytes)
            .map_err(|_| Secp256k1Error::InvalidPublicKey)?;
        Ok(PublicKey { public_key })
    }

    /// Serialize to compressed SEC1 format (33 bytes)
    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        self.public_key.serialize()
    }

    /// Serialize to uncompressed SEC1 format (65 bytes)
    pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
        self.public_key.serialize_uncompressed()
    }

    /// Verify an ECDSA signature
    pub fn verify_ecdsa(&self, message_hash: &[u8; 32], signature: &EcdsaSignature) -> Result<(), Secp256k1Error> {
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(message_hash)
            .map_err(|_| Secp256k1Error::InvalidMessage)?;

        secp.verify_ecdsa(&message, &signature.signature, &self.public_key)
            .map_err(|_| Secp256k1Error::InvalidSignature)
    }

    /// Recover public key from recoverable signature
    pub fn recover_from_signature(
        message_hash: &[u8; 32],
        signature: &RecoverableSignature
    ) -> Result<PublicKey, Secp256k1Error> {
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(message_hash)
            .map_err(|_| Secp256k1Error::InvalidMessage)?;

        let public_key = secp.recover_ecdsa(&message, &signature.signature)
            .map_err(|_| Secp256k1Error::RecoveryFailed)?;

        Ok(PublicKey { public_key })
    }
}

#[cfg(feature = "secp256k1")]
impl EcdsaSignature {
    /// Create signature from DER bytes
    pub fn from_der(der_bytes: &[u8]) -> Result<EcdsaSignature, Secp256k1Error> {
        let signature = secp256k1::ecdsa::Signature::from_der(der_bytes)
            .map_err(|_| Secp256k1Error::InvalidSignature)?;
        Ok(EcdsaSignature { signature })
    }

    /// Create signature from compact bytes (64 bytes)
    pub fn from_compact(compact_bytes: &[u8; 64]) -> Result<EcdsaSignature, Secp256k1Error> {
        let signature = secp256k1::ecdsa::Signature::from_compact(compact_bytes)
            .map_err(|_| Secp256k1Error::InvalidSignature)?;
        Ok(EcdsaSignature { signature })
    }

    /// Serialize to DER format
    #[cfg(feature = "alloc")]
    pub fn to_der(&self) -> alloc::vec::Vec<u8> {
        self.signature.serialize_der().to_vec()
    }

    /// Serialize to compact format (64 bytes)
    pub fn to_compact(&self) -> [u8; 64] {
        self.signature.serialize_compact()
    }
}

#[cfg(feature = "secp256k1")]
impl RecoverableSignature {
    /// Create recoverable signature from compact bytes plus recovery ID
    pub fn from_compact(compact_bytes: &[u8; 64], recovery_id: u8) -> Result<RecoverableSignature, Secp256k1Error> {
        let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(recovery_id as i32)
            .map_err(|_| Secp256k1Error::InvalidSignature)?;
        let signature = secp256k1::ecdsa::RecoverableSignature::from_compact(compact_bytes, recovery_id)
            .map_err(|_| Secp256k1Error::InvalidSignature)?;
        Ok(RecoverableSignature { signature })
    }

    /// Serialize to compact format plus recovery ID
    pub fn to_compact(&self) -> ([u8; 64], u8) {
        let (recovery_id, compact) = self.signature.serialize_compact();
        (compact, recovery_id.to_i32() as u8)
    }

    /// Convert to non-recoverable signature
    pub fn to_ecdsa_signature(&self) -> EcdsaSignature {
        EcdsaSignature {
            signature: self.signature.to_standard(),
        }
    }
}

/// Ethereum-style address derivation from public key
#[cfg(all(feature = "secp256k1", feature = "alloc"))]
pub fn ethereum_address(public_key: &PublicKey) -> [u8; 20] {
    use bitcoin_hashes::{Hash, sha256};

    // Get uncompressed public key without the 0x04 prefix
    let uncompressed = public_key.to_uncompressed_bytes();
    let public_key_bytes = &uncompressed[1..]; // Skip the 0x04 prefix

    // SHA256 hash (simplified - real Ethereum uses Keccak256)
    let hash = sha256::Hash::hash(public_key_bytes);

    // Take the last 20 bytes
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "secp256k1")]
    fn test_key_generation_and_signing() {
        let mut rng = rand::thread_rng();
        let private_key = PrivateKey::random(&mut rng);
        let public_key = private_key.public_key();

        let message_hash = [0x42u8; 32];
        let signature = private_key.sign_ecdsa(&message_hash).unwrap();

        public_key.verify_ecdsa(&message_hash, &signature).unwrap();
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn test_recoverable_signature() {
        let mut rng = rand::thread_rng();
        let private_key = PrivateKey::random(&mut rng);
        let public_key = private_key.public_key();

        let message_hash = [0x42u8; 32];
        let recoverable_sig = private_key.sign_ecdsa_recoverable(&message_hash).unwrap();

        let recovered_key = PublicKey::recover_from_signature(&message_hash, &recoverable_sig).unwrap();
        assert_eq!(public_key, recovered_key);
    }

    #[test]
    #[cfg(all(feature = "secp256k1", feature = "alloc"))]
    fn test_ethereum_address() {
        let mut rng = rand::thread_rng();
        let private_key = PrivateKey::random(&mut rng);
        let public_key = private_key.public_key();

        let address = ethereum_address(&public_key);
        assert_eq!(address.len(), 20);
    }
}