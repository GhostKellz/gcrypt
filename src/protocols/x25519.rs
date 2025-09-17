//! X25519 key exchange implementation  
//!
//! This module implements the X25519 Elliptic Curve Diffie-Hellman (ECDH) 
//! key exchange as specified in RFC 7748.

use crate::{Scalar, MontgomeryPoint};
use subtle::ConstantTimeEq;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::cmp;

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// An X25519 public key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub(crate) MontgomeryPoint);

/// An X25519 secret key
#[derive(Clone, Debug)]
pub struct SecretKey(pub(crate) Scalar);

/// Shared secret from X25519 key exchange
#[derive(Clone, Debug)]
pub struct SharedSecret(pub(crate) [u8; 32]);

/// X25519 key exchange errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeError {
    /// Invalid public key point
    InvalidPublicKey,
    /// Invalid secret key format
    InvalidSecretKey,
    /// Key exchange resulted in low-order point
    LowOrderPoint,
    /// Invalid key length
    InvalidLength,
}

impl core::fmt::Display for KeyExchangeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeyExchangeError::InvalidPublicKey => write!(f, "Invalid public key"),
            KeyExchangeError::InvalidSecretKey => write!(f, "Invalid secret key"),
            KeyExchangeError::LowOrderPoint => write!(f, "Key exchange resulted in low-order point"),
            KeyExchangeError::InvalidLength => write!(f, "Invalid key length"),
        }
    }
}

impl SecretKey {
    /// Generate a new X25519 secret key
    #[cfg(feature = "rand_core")]
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> SecretKey {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        
        // Apply X25519 clamping
        bytes[0] &= 248;  // Clear bottom 3 bits
        bytes[31] &= 127; // Clear top bit
        bytes[31] |= 64;  // Set second-highest bit
        
        SecretKey(Scalar::from_bytes_mod_order(bytes))
    }
    
    /// Create a secret key from bytes with proper clamping
    pub fn from_bytes(bytes: &[u8; 32]) -> SecretKey {
        let mut clamped = *bytes;
        
        // Apply X25519 clamping
        clamped[0] &= 248;  // Clear bottom 3 bits
        clamped[31] &= 127; // Clear top bit  
        clamped[31] |= 64;  // Set second-highest bit
        
        SecretKey(Scalar::from_bytes_mod_order(clamped))
    }
    
    /// Create a secret key from raw bytes without clamping
    pub fn from_raw_bytes(bytes: &[u8; 32]) -> SecretKey {
        SecretKey(Scalar::from_bytes_mod_order(*bytes))
    }
    
    /// Convert secret key to bytes (clamped)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = self.0.to_bytes();
        
        // Ensure clamping is maintained
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        
        bytes
    }
    
    /// Get the corresponding public key
    pub fn public_key(&self) -> PublicKey {
        let point = MontgomeryPoint::mul_base(&self.0);
        PublicKey(point)
    }
    
    /// Perform X25519 key exchange
    pub fn diffie_hellman(&self, public_key: &PublicKey) -> Result<SharedSecret, KeyExchangeError> {
        // Perform the scalar multiplication
        let shared_point = &public_key.0 * &self.0;
        
        // Check for low-order point (all-zero result)
        let shared_bytes = shared_point.to_bytes();
        if shared_bytes.ct_eq(&[0u8; 32]).into() {
            return Err(KeyExchangeError::LowOrderPoint);
        }
        
        Ok(SharedSecret(shared_bytes))
    }
}

impl PublicKey {
    /// Create a public key from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<PublicKey, KeyExchangeError> {
        // For Montgomery points, all byte arrays are valid public keys
        // except for low-order points which we check during key exchange
        Ok(PublicKey(MontgomeryPoint::from_bytes(*bytes)))
    }
    
    /// Convert public key to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    
    /// Check if this is a low-order point
    pub fn is_low_order(&self) -> bool {
        // In a complete implementation, this would check against
        // the known low-order points for Curve25519
        false // Simplified for now
    }
}

impl SharedSecret {
    /// Convert shared secret to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    
    /// Derive key material from the shared secret using HKDF-like construction
    pub fn derive_key(&self, info: &[u8], length: usize) -> Vec<u8> {
        // Simplified key derivation - real implementation would use HKDF
        let mut output = Vec::with_capacity(length);
        let mut counter = 0u32;
        
        while output.len() < length {
            let mut hasher_input = Vec::new();
            hasher_input.extend_from_slice(&self.0);
            hasher_input.extend_from_slice(info);
            hasher_input.extend_from_slice(&counter.to_be_bytes());
            
            let hash = simple_hash(&hasher_input);
            let remaining = length - output.len();
            let to_take = cmp::min(remaining, 32);
            
            output.extend_from_slice(&hash[..to_take]);
            counter += 1;
        }
        
        output
    }
    
    /// Split the shared secret for encryption and authentication keys
    pub fn split_keys(&self) -> ([u8; 32], [u8; 32]) {
        let keys = self.derive_key(b"encryption|authentication", 64);
        
        let mut enc_key = [0u8; 32];
        let mut auth_key = [0u8; 32];
        
        enc_key.copy_from_slice(&keys[0..32]);  
        auth_key.copy_from_slice(&keys[32..64]);
        
        (enc_key, auth_key)
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Simplified hash function for demonstration
fn simple_hash(input: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    
    for (i, &byte) in input.iter().enumerate() {
        hash[i % 32] ^= byte;
        hash[i % 32] = hash[i % 32].wrapping_add(byte);
    }
    
    hash
}

/// Perform ephemeral key exchange (generates new key each time)
#[cfg(feature = "rand_core")]
pub fn ephemeral_exchange<R: CryptoRng + RngCore>(
    rng: &mut R, 
    their_public: &PublicKey
) -> Result<(PublicKey, SharedSecret), KeyExchangeError> {
    let secret_key = SecretKey::generate(rng);
    let public_key = secret_key.public_key();
    let shared_secret = secret_key.diffie_hellman(their_public)?;
    
    Ok((public_key, shared_secret))
}

/// Generate a key pair for X25519
#[cfg(feature = "rand_core")]
pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SecretKey, PublicKey) {
    let secret_key = SecretKey::generate(rng);
    let public_key = secret_key.public_key();
    (secret_key, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(feature = "rand_core")]
    #[test]
    fn test_x25519_key_exchange() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        
        // Generate two key pairs
        let (alice_secret, alice_public) = generate_keypair(&mut rng);
        let (bob_secret, bob_public) = generate_keypair(&mut rng);
        
        // Perform key exchange from both sides
        let alice_shared = alice_secret.diffie_hellman(&bob_public).unwrap();
        let bob_shared = bob_secret.diffie_hellman(&alice_public).unwrap();
        
        // Shared secrets should be identical
        assert_eq!(alice_shared.to_bytes(), bob_shared.to_bytes());
    }
    
    #[test]
    fn test_key_clamping() {
        let raw_bytes = [255u8; 32]; // All bits set
        let secret_key = SecretKey::from_bytes(&raw_bytes);
        let clamped_bytes = secret_key.to_bytes();
        
        // Check clamping was applied
        assert_eq!(clamped_bytes[0] & 7, 0);     // Bottom 3 bits clear
        assert_eq!(clamped_bytes[31] & 128, 0);  // Top bit clear
        assert_eq!(clamped_bytes[31] & 64, 64);  // Second-highest bit set
    }
    
    #[test]
    fn test_key_serialization() {
        let original_bytes = [42u8; 32];
        let secret_key = SecretKey::from_bytes(&original_bytes);
        let public_key = secret_key.public_key();
        
        // Serialize and deserialize keys
        let secret_bytes = secret_key.to_bytes();
        let public_bytes = public_key.to_bytes();
        
        let recovered_secret = SecretKey::from_bytes(&secret_bytes);
        let recovered_public = PublicKey::from_bytes(&public_bytes).unwrap();
        
        // Public keys should match
        assert_eq!(public_key.to_bytes(), recovered_public.to_bytes());
        
        // Derived public keys should match
        assert_eq!(
            secret_key.public_key().to_bytes(),
            recovered_secret.public_key().to_bytes()
        );
    }
    
    #[test]
    fn test_shared_secret_derivation() {
        let secret_key = SecretKey::from_bytes(&[1u8; 32]);
        let public_key = PublicKey::from_bytes(&[2u8; 32]).unwrap();
        
        let shared_secret = secret_key.diffie_hellman(&public_key).unwrap();
        
        // Test key derivation
        let derived_key = shared_secret.derive_key(b"test", 48);
        assert_eq!(derived_key.len(), 48);
        
        // Test key splitting
        let (enc_key, auth_key) = shared_secret.split_keys();
        assert_ne!(enc_key, auth_key); // Keys should be different
    }
    
    #[cfg(feature = "rand_core")]
    #[test]
    fn test_ephemeral_exchange() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        
        let bob_secret = SecretKey::generate(&mut rng);
        let bob_public = bob_secret.public_key();
        
        // Alice performs ephemeral exchange
        let (alice_public, alice_shared) = ephemeral_exchange(&mut rng, &bob_public).unwrap();
        
        // Bob computes shared secret with Alice's ephemeral public key
        let bob_shared = bob_secret.diffie_hellman(&alice_public).unwrap();
        
        // Shared secrets should match
        assert_eq!(alice_shared.to_bytes(), bob_shared.to_bytes());
    }
}