//! AES-GCM authenticated encryption implementation
//!
//! This module provides AES-GCM (Galois/Counter Mode) authenticated encryption
//! which is commonly used in QUIC protocol implementations for packet protection.
//!
//! AES-GCM provides both confidentiality and authenticity in a single operation,
//! making it ideal for network protocols that require high performance and security.

#[cfg(feature = "aes-gcm")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// AES-128-GCM cipher instance
#[cfg(feature = "aes-gcm")]
pub struct Aes128GcmCipher {
    cipher: Aes128Gcm,
}

/// AES-256-GCM cipher instance  
#[cfg(feature = "aes-gcm")]
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
}

/// AES-GCM encryption/decryption errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesGcmError {
    /// Authentication failed during decryption
    AuthenticationFailed,
    /// Invalid key size
    InvalidKeySize,
    /// Invalid nonce size
    InvalidNonceSize,
}

impl core::fmt::Display for AesGcmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AesGcmError::AuthenticationFailed => write!(f, "Authentication failed"),
            AesGcmError::InvalidKeySize => write!(f, "Invalid key size"),
            AesGcmError::InvalidNonceSize => write!(f, "Invalid nonce size"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AesGcmError {}

#[cfg(feature = "aes-gcm")]
impl Aes128GcmCipher {
    /// Create a new AES-128-GCM cipher from a 128-bit key
    pub fn new(key: &[u8; 16]) -> Self {
        let cipher = Aes128Gcm::new_from_slice(key).expect("Invalid key size");
        Self { cipher }
    }

    /// Encrypt plaintext with associated data
    #[cfg(feature = "alloc")]
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, AesGcmError> {
        let nonce = Nonce::from_slice(nonce);
        
        self.cipher
            .encrypt(nonce, aes_gcm::aead::Payload {
                msg: plaintext,
                aad: associated_data,
            })
            .map_err(|_| AesGcmError::AuthenticationFailed)
    }

    /// Decrypt ciphertext with associated data
    #[cfg(feature = "alloc")]
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, AesGcmError> {
        let nonce = Nonce::from_slice(nonce);
        
        self.cipher
            .decrypt(nonce, aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: associated_data,
            })
            .map_err(|_| AesGcmError::AuthenticationFailed)
    }
}

#[cfg(feature = "aes-gcm")]
impl Aes256GcmCipher {
    /// Create a new AES-256-GCM cipher from a 256-bit key
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("Invalid key size");
        Self { cipher }
    }

    /// Encrypt plaintext with associated data
    #[cfg(feature = "alloc")]
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, AesGcmError> {
        let nonce = Nonce::from_slice(nonce);
        
        self.cipher
            .encrypt(nonce, aes_gcm::aead::Payload {
                msg: plaintext,
                aad: associated_data,
            })
            .map_err(|_| AesGcmError::AuthenticationFailed)
    }

    /// Decrypt ciphertext with associated data
    #[cfg(feature = "alloc")]
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, AesGcmError> {
        let nonce = Nonce::from_slice(nonce);
        
        self.cipher
            .decrypt(nonce, aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: associated_data,
            })
            .map_err(|_| AesGcmError::AuthenticationFailed)
    }
}

/// Generate a random 128-bit AES key
#[cfg(all(feature = "aes-gcm", feature = "rand_core"))]
pub fn generate_aes128_key() -> [u8; 16] {
    use rand_core::RngCore;
    let mut key = [0u8; 16];
    let mut rng = rand_core::OsRng;
    rng.fill_bytes(&mut key);
    key
}

/// Generate a random 256-bit AES key
#[cfg(all(feature = "aes-gcm", feature = "rand_core"))]
pub fn generate_aes256_key() -> [u8; 32] {
    use rand_core::RngCore;
    let mut key = [0u8; 32];
    let mut rng = rand_core::OsRng;
    rng.fill_bytes(&mut key);
    key
}

/// Generate a random 96-bit nonce for AES-GCM
#[cfg(all(feature = "aes-gcm", feature = "rand_core"))]
pub fn generate_nonce() -> [u8; 12] {
    use rand_core::RngCore;
    let mut nonce = [0u8; 12];
    let mut rng = rand_core::OsRng;
    rng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "aes-gcm", feature = "alloc"))]
    fn test_aes128_gcm_encrypt_decrypt() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, world!";
        let aad = b"associated data";

        let cipher = Aes128GcmCipher::new(&key);
        
        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    #[cfg(all(feature = "aes-gcm", feature = "alloc"))]
    fn test_aes256_gcm_encrypt_decrypt() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, world!";
        let aad = b"associated data";

        let cipher = Aes256GcmCipher::new(&key);
        
        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    #[cfg(all(feature = "aes-gcm", feature = "alloc"))]
    fn test_authentication_failure() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, world!";
        let aad = b"associated data";

        let cipher = Aes128GcmCipher::new(&key);
        
        let mut ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        // Corrupt the ciphertext
        ciphertext[0] ^= 1;
        
        let result = cipher.decrypt(&nonce, &ciphertext, aad);
        assert_eq!(result.unwrap_err(), AesGcmError::AuthenticationFailed);
    }

    #[test]
    #[cfg(all(feature = "aes-gcm", feature = "rand_core"))]
    fn test_key_generation() {
        let key1 = generate_aes128_key();
        let key2 = generate_aes128_key();
        assert_ne!(key1, key2);

        let key1 = generate_aes256_key();
        let key2 = generate_aes256_key();
        assert_ne!(key1, key2);
    }

    #[test]
    #[cfg(all(feature = "aes-gcm", feature = "rand_core"))]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2);
    }
}