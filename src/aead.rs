//! Authenticated Encryption with Associated Data (AEAD)
//!
//! This module provides implementations of AEAD ciphers that provide both
//! confidentiality and authenticity in a single operation:
//! - ChaCha20-Poly1305 - Modern, high-performance AEAD
//! - XChaCha20-Poly1305 - Extended nonce variant
//! - AES-GCM - Hardware-accelerated on many platforms (re-exported)

#[cfg(feature = "chacha20-poly1305")]
use chacha20poly1305::{
    ChaCha20Poly1305, XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Key, Nonce, XNonce,
};

#[cfg(feature = "aes-gcm")]
pub use crate::protocols::aes_gcm::{AesGcm128, AesGcm256, AesGcmError};

#[cfg(feature = "rand_core")]
use rand_core::{RngCore, CryptoRng};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String, format};

/// Error types for AEAD operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid key length
    InvalidKeyLength,
    /// Invalid nonce length
    InvalidNonceLength,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed (likely authentication failure)
    DecryptionFailed,
    /// Invalid ciphertext length
    InvalidCiphertextLength,
    /// AEAD library error
    AeadError(String),
}

/// Common trait for AEAD algorithms
pub trait AuthenticatedEncryption {
    type Key;
    type Nonce;

    /// Create a new AEAD instance with the given key
    fn new(key: &Self::Key) -> Result<Self, Error>
    where
        Self: Sized;

    /// Encrypt plaintext with associated data
    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Decrypt ciphertext with associated data
    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Encrypt in-place (plaintext buffer becomes ciphertext + tag)
    fn encrypt_in_place(
        &self,
        nonce: &Self::Nonce,
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let ciphertext = self.encrypt(nonce, buffer, associated_data)?;
        buffer.clear();
        buffer.extend_from_slice(&ciphertext);
        Ok(())
    }

    /// Decrypt in-place (ciphertext + tag buffer becomes plaintext)
    fn decrypt_in_place(
        &self,
        nonce: &Self::Nonce,
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let plaintext = self.decrypt(nonce, buffer, associated_data)?;
        buffer.clear();
        buffer.extend_from_slice(&plaintext);
        Ok(())
    }
}

/// ChaCha20-Poly1305 AEAD implementation
#[cfg(feature = "chacha20-poly1305")]
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

#[cfg(feature = "chacha20-poly1305")]
impl AuthenticatedEncryption for ChaCha20Poly1305Cipher {
    type Key = [u8; 32];
    type Nonce = [u8; 12];

    fn new(key: &Self::Key) -> Result<Self, Error> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Ok(Self { cipher })
    }

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .encrypt(nonce, [associated_data, plaintext].concat().as_slice())
            .map_err(|e| Error::AeadError(format!("{:?}", e)))
    }

    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce = Nonce::from_slice(nonce);
        let combined = [associated_data, ciphertext].concat();
        let decrypted = self.cipher
            .decrypt(nonce, combined.as_slice())
            .map_err(|e| Error::AeadError(format!("{:?}", e)))?;

        // Remove the associated data from the beginning
        if decrypted.len() < associated_data.len() {
            return Err(Error::DecryptionFailed);
        }
        Ok(decrypted[associated_data.len()..].to_vec())
    }
}

#[cfg(feature = "chacha20-poly1305")]
impl ChaCha20Poly1305Cipher {
    /// Generate a random key
    #[cfg(feature = "rand_core")]
    pub fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key
    }

    /// Generate a random nonce
    #[cfg(feature = "rand_core")]
    pub fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        nonce
    }

    /// Create from raw key bytes
    pub fn from_key_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != 32 {
            return Err(Error::InvalidKeyLength);
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);
        Self::new(&key_array)
    }

    /// Get the tag size (always 16 bytes for ChaCha20-Poly1305)
    pub const fn tag_size() -> usize {
        16
    }

    /// Get the key size (always 32 bytes)
    pub const fn key_size() -> usize {
        32
    }

    /// Get the nonce size (always 12 bytes)
    pub const fn nonce_size() -> usize {
        12
    }
}

/// XChaCha20-Poly1305 AEAD implementation (extended nonce)
#[cfg(feature = "chacha20-poly1305")]
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub struct XChaCha20Poly1305Cipher {
    cipher: XChaCha20Poly1305,
}

#[cfg(feature = "chacha20-poly1305")]
impl AuthenticatedEncryption for XChaCha20Poly1305Cipher {
    type Key = [u8; 32];
    type Nonce = [u8; 24]; // Extended 24-byte nonce

    fn new(key: &Self::Key) -> Result<Self, Error> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        Ok(Self { cipher })
    }

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce = XNonce::from_slice(nonce);
        self.cipher
            .encrypt(nonce, [associated_data, plaintext].concat().as_slice())
            .map_err(|e| Error::AeadError(format!("{:?}", e)))
    }

    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce = XNonce::from_slice(nonce);
        let combined = [associated_data, ciphertext].concat();
        let decrypted = self.cipher
            .decrypt(nonce, combined.as_slice())
            .map_err(|e| Error::AeadError(format!("{:?}", e)))?;

        // Remove the associated data from the beginning
        if decrypted.len() < associated_data.len() {
            return Err(Error::DecryptionFailed);
        }
        Ok(decrypted[associated_data.len()..].to_vec())
    }
}

#[cfg(feature = "chacha20-poly1305")]
impl XChaCha20Poly1305Cipher {
    /// Generate a random key
    #[cfg(feature = "rand_core")]
    pub fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key
    }

    /// Generate a random nonce (24 bytes for XChaCha20)
    #[cfg(feature = "rand_core")]
    pub fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        nonce
    }

    /// Get the nonce size (always 24 bytes for XChaCha20)
    pub const fn nonce_size() -> usize {
        24
    }
}

/// Sealed box encryption (anonymous encryption with ephemeral keys)
#[cfg(feature = "chacha20-poly1305")]
pub mod sealed_box {
    use super::*;
    #[cfg(feature = "secp256k1")]
    use crate::secp256k1::{PrivateKey as Secp256k1PrivateKey, PublicKey as Secp256k1PublicKey};
    #[cfg(feature = "secp256r1")]
    use crate::p256::{SecretKey as P256SecretKey, PublicKey as P256PublicKey};

    /// Encrypt data for a recipient's public key (ephemeral key exchange)
    #[cfg(all(feature = "secp256k1", feature = "hkdf", feature = "sha2"))]
    pub fn seal_secp256k1<R: RngCore + CryptoRng>(
        rng: &mut R,
        recipient_pubkey: &Secp256k1PublicKey,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Secp256k1PublicKey, [u8; 12], Vec<u8>), Error> {
        // Generate ephemeral keypair
        let ephemeral_privkey = Secp256k1PrivateKey::random(rng);
        let ephemeral_pubkey = ephemeral_privkey.public_key();

        // Derive shared secret using ECDH
        // Note: This is simplified - real implementation would use proper ECDH
        let shared_secret = [0u8; 32]; // Placeholder

        // Derive encryption key using HKDF
        let kdf = crate::kdf::HkdfSha256::new(Some(b"sealed_box_v1"));
        let encryption_key = kdf.derive(&shared_secret, &[], 32)
            .map_err(|_| Error::EncryptionFailed)?;

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&encryption_key);

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305Cipher::new(&key_array)?;
        let nonce = ChaCha20Poly1305Cipher::generate_nonce(rng);
        let ciphertext = cipher.encrypt(&nonce, plaintext, associated_data)?;

        Ok((ephemeral_pubkey, nonce, ciphertext))
    }

    /// Decrypt data using recipient's private key
    #[cfg(all(feature = "secp256k1", feature = "hkdf", feature = "sha2"))]
    pub fn open_secp256k1(
        recipient_privkey: &Secp256k1PrivateKey,
        ephemeral_pubkey: &Secp256k1PublicKey,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Derive shared secret using ECDH
        // Note: This is simplified - real implementation would use proper ECDH
        let shared_secret = [0u8; 32]; // Placeholder

        // Derive encryption key using HKDF
        let kdf = crate::kdf::HkdfSha256::new(Some(b"sealed_box_v1"));
        let encryption_key = kdf.derive(&shared_secret, &[], 32)
            .map_err(|_| Error::DecryptionFailed)?;

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&encryption_key);

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305Cipher::new(&key_array)?;
        cipher.decrypt(nonce, ciphertext, associated_data)
    }
}

/// Utility functions for AEAD operations
pub mod utils {
    use super::*;

    /// Encrypt with ChaCha20-Poly1305 using random nonce
    #[cfg(all(feature = "chacha20-poly1305", feature = "rand_core"))]
    pub fn chacha20_poly1305_encrypt<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &[u8; 32],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<([u8; 12], Vec<u8>), Error> {
        let cipher = ChaCha20Poly1305Cipher::new(key)?;
        let nonce = ChaCha20Poly1305Cipher::generate_nonce(rng);
        let ciphertext = cipher.encrypt(&nonce, plaintext, associated_data)?;
        Ok((nonce, ciphertext))
    }

    /// Decrypt with ChaCha20-Poly1305
    #[cfg(feature = "chacha20-poly1305")]
    pub fn chacha20_poly1305_decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let cipher = ChaCha20Poly1305Cipher::new(key)?;
        cipher.decrypt(nonce, ciphertext, associated_data)
    }

    /// Encrypt with XChaCha20-Poly1305 using random nonce
    #[cfg(all(feature = "chacha20-poly1305", feature = "rand_core"))]
    pub fn xchacha20_poly1305_encrypt<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &[u8; 32],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<([u8; 24], Vec<u8>), Error> {
        let cipher = XChaCha20Poly1305Cipher::new(key)?;
        let nonce = XChaCha20Poly1305Cipher::generate_nonce(rng);
        let ciphertext = cipher.encrypt(&nonce, plaintext, associated_data)?;
        Ok((nonce, ciphertext))
    }

    /// Decrypt with XChaCha20-Poly1305
    #[cfg(feature = "chacha20-poly1305")]
    pub fn xchacha20_poly1305_decrypt(
        key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let cipher = XChaCha20Poly1305Cipher::new(key)?;
        cipher.decrypt(nonce, ciphertext, associated_data)
    }

    /// Generate a random AEAD key
    #[cfg(feature = "rand_core")]
    pub fn generate_aead_key<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key
    }

    /// Timing-safe comparison for authentication tags
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "chacha20-poly1305", feature = "rand_core"))]
    fn test_chacha20_poly1305() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let key = ChaCha20Poly1305Cipher::generate_key(&mut rng);
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

        let plaintext = b"Hello, ChaCha20-Poly1305!";
        let associated_data = b"version=1";
        let nonce = ChaCha20Poly1305Cipher::generate_nonce(&mut rng);

        // Test encryption/decryption
        let ciphertext = cipher.encrypt(&nonce, plaintext, associated_data).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, associated_data).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    #[cfg(all(feature = "chacha20-poly1305", feature = "rand_core"))]
    fn test_xchacha20_poly1305() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let key = XChaCha20Poly1305Cipher::generate_key(&mut rng);
        let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();

        let plaintext = b"Hello, XChaCha20-Poly1305!";
        let associated_data = b"version=1";
        let nonce = XChaCha20Poly1305Cipher::generate_nonce(&mut rng);

        // Test encryption/decryption
        let ciphertext = cipher.encrypt(&nonce, plaintext, associated_data).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, associated_data).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    #[cfg(feature = "chacha20-poly1305")]
    fn test_authentication_failure() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let key = ChaCha20Poly1305Cipher::generate_key(&mut rng);
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

        let plaintext = b"Hello, world!";
        let associated_data = b"version=1";
        let nonce = ChaCha20Poly1305Cipher::generate_nonce(&mut rng);

        let mut ciphertext = cipher.encrypt(&nonce, plaintext, associated_data).unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 1;
        }

        // Decryption should fail
        let result = cipher.decrypt(&nonce, &ciphertext, associated_data);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(all(feature = "chacha20-poly1305", feature = "rand_core"))]
    fn test_utils() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let key = utils::generate_aead_key(&mut rng);
        let plaintext = b"test message";
        let associated_data = b"test ad";

        let (nonce, ciphertext) = utils::chacha20_poly1305_encrypt(&mut rng, &key, plaintext, associated_data).unwrap();
        let decrypted = utils::chacha20_poly1305_decrypt(&key, &nonce, &ciphertext, associated_data).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(utils::constant_time_eq(&a, &b));
        assert!(!utils::constant_time_eq(&a, &c));
        assert!(!utils::constant_time_eq(&a, &[1, 2, 3])); // Different lengths
    }
}