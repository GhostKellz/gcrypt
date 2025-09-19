//! Message Authentication Codes (MAC)
//!
//! This module provides implementations of various MAC algorithms:
//! - HMAC with SHA-256, SHA-512, and other hash functions
//! - Poly1305 for ChaCha20-Poly1305 AEAD
//! - Blake3-based MAC

#[cfg(feature = "hmac")]
use hmac::{Hmac, Mac, NewMac};

#[cfg(feature = "sha2")]
use sha2::{Sha256, Sha512};

#[cfg(feature = "sha3")]
use sha3::{Sha3_256, Sha3_512};

#[cfg(feature = "blake3")]
use crate::hash::Blake3HasherWrapper;

#[cfg(feature = "chacha20-poly1305")]
use chacha20poly1305::aead::{KeyInit, Mac as AeadMac};

#[cfg(feature = "chacha20-poly1305")]
use chacha20poly1305::Poly1305;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String, format};

/// Error types for MAC operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid key length
    InvalidKeyLength,
    /// MAC verification failed
    VerificationFailed,
    /// Invalid MAC tag
    InvalidTag,
    /// MAC library error
    MacError(String),
}

/// Common trait for MAC algorithms
pub trait MessageAuthenticationCode {
    type Output;

    /// Create a new MAC instance with the given key
    fn new(key: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;

    /// Update the MAC with input data
    fn update(&mut self, data: &[u8]);

    /// Finalize the MAC and return the authentication tag
    fn finalize(self) -> Self::Output;

    /// Verify a MAC tag against the computed value
    fn verify(&self, expected: &[u8]) -> Result<(), Error>;

    /// Convenience method to compute MAC in one call
    fn compute(key: &[u8], data: &[u8]) -> Result<Self::Output, Error>
    where
        Self: Sized,
    {
        let mut mac = Self::new(key)?;
        mac.update(data);
        Ok(mac.finalize())
    }
}

/// HMAC-SHA256 implementation
#[cfg(all(feature = "hmac", feature = "sha2"))]
pub struct HmacSha256 {
    inner: Hmac<Sha256>,
}

#[cfg(all(feature = "hmac", feature = "sha2"))]
impl MessageAuthenticationCode for HmacSha256 {
    type Output = [u8; 32];

    fn new(key: &[u8]) -> Result<Self, Error> {
        let inner = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|e| Error::MacError(format!("{:?}", e)))?;
        Ok(Self { inner })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        self.inner.finalize().into_bytes().into()
    }

    fn verify(&self, expected: &[u8]) -> Result<(), Error> {
        self.inner
            .verify_slice(expected)
            .map_err(|_| Error::VerificationFailed)
    }
}

/// HMAC-SHA512 implementation
#[cfg(all(feature = "hmac", feature = "sha2"))]
pub struct HmacSha512 {
    inner: Hmac<Sha512>,
}

#[cfg(all(feature = "hmac", feature = "sha2"))]
impl MessageAuthenticationCode for HmacSha512 {
    type Output = [u8; 64];

    fn new(key: &[u8]) -> Result<Self, Error> {
        let inner = Hmac::<Sha512>::new_from_slice(key)
            .map_err(|e| Error::MacError(format!("{:?}", e)))?;
        Ok(Self { inner })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        self.inner.finalize().into_bytes().into()
    }

    fn verify(&self, expected: &[u8]) -> Result<(), Error> {
        self.inner
            .verify_slice(expected)
            .map_err(|_| Error::VerificationFailed)
    }
}

/// HMAC-SHA3-256 implementation
#[cfg(all(feature = "hmac", feature = "sha3"))]
pub struct HmacSha3_256 {
    inner: Hmac<Sha3_256>,
}

#[cfg(all(feature = "hmac", feature = "sha3"))]
impl MessageAuthenticationCode for HmacSha3_256 {
    type Output = [u8; 32];

    fn new(key: &[u8]) -> Result<Self, Error> {
        let inner = Hmac::<Sha3_256>::new_from_slice(key)
            .map_err(|e| Error::MacError(format!("{:?}", e)))?;
        Ok(Self { inner })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        self.inner.finalize().into_bytes().into()
    }

    fn verify(&self, expected: &[u8]) -> Result<(), Error> {
        self.inner
            .verify_slice(expected)
            .map_err(|_| Error::VerificationFailed)
    }
}

/// Blake3-based MAC
#[cfg(feature = "blake3")]
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub struct Blake3Mac {
    hasher: Blake3HasherWrapper,
}

/// Poly1305 MAC implementation
#[cfg(feature = "chacha20-poly1305")]
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub struct Poly1305Mac {
    inner: Poly1305,
}

#[cfg(feature = "blake3")]
impl MessageAuthenticationCode for Blake3Mac {
    type Output = [u8; 32];

    fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != 32 {
            return Err(Error::InvalidKeyLength);
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);
        let hasher = Blake3HasherWrapper::new_keyed(&key_array);
        Ok(Self { hasher })
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> Self::Output {
        self.hasher.finalize()
    }

    fn verify(&self, expected: &[u8]) -> Result<(), Error> {
        let computed = self.hasher.clone().finalize();
        if computed.len() != expected.len() {
            return Err(Error::VerificationFailed);
        }

        // Constant-time comparison
        let mut result = 0u8;
        for (a, b) in computed.iter().zip(expected.iter()) {
            result |= a ^ b;
        }

        if result == 0 {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

#[cfg(feature = "chacha20-poly1305")]
impl MessageAuthenticationCode for Poly1305Mac {
    type Output = [u8; 16];

    fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != 32 {
            return Err(Error::InvalidKeyLength);
        }
        let inner = Poly1305::new_from_slice(key)
            .map_err(|e| Error::MacError(format!("{:?}", e)))?;
        Ok(Self { inner })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        self.inner.finalize().into_bytes().into()
    }

    fn verify(&self, expected: &[u8]) -> Result<(), Error> {
        // Clone for verification since finalize consumes self
        let mut verifier = self.inner.clone();
        let computed = verifier.finalize();

        if computed.into_bytes().as_slice() == expected {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

#[cfg(feature = "chacha20-poly1305")]
impl Poly1305Mac {
    /// Create a new Poly1305 MAC with a 32-byte key
    pub fn new_from_key(key: &[u8; 32]) -> Result<Self, Error> {
        Self::new(key)
    }

    /// Get the tag size (always 16 bytes for Poly1305)
    pub const fn tag_size() -> usize {
        16
    }

    /// Get the key size (always 32 bytes)
    pub const fn key_size() -> usize {
        32
    }
}

/// Results from multi-MAC
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MultiMacResults {
    #[cfg(all(feature = "hmac", feature = "sha2"))]
    pub hmac_sha256: Option<[u8; 32]>,
    #[cfg(all(feature = "hmac", feature = "sha2"))]
    pub hmac_sha512: Option<[u8; 64]>,
    #[cfg(all(feature = "hmac", feature = "sha3"))]
    pub hmac_sha3_256: Option<[u8; 32]>,
    #[cfg(feature = "blake3")]
    pub blake3_mac: Option<[u8; 32]>,
}

/// Utility functions for MAC operations
pub mod utils {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::vec;

    /// Compute HMAC-SHA256
    #[cfg(all(feature = "hmac", feature = "sha2"))]
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], Error> {
        HmacSha256::compute(key, data)
    }

    /// Compute HMAC-SHA512
    #[cfg(all(feature = "hmac", feature = "sha2"))]
    pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64], Error> {
        HmacSha512::compute(key, data)
    }

    /// Compute HMAC-SHA3-256
    #[cfg(all(feature = "hmac", feature = "sha3"))]
    pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> Result<[u8; 32], Error> {
        HmacSha3_256::compute(key, data)
    }

    /// Compute Blake3 MAC
    #[cfg(feature = "blake3")]
    pub fn blake3_mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        Blake3Mac::compute(key, data).expect("Blake3 MAC should not fail")
    }

    /// Compute Poly1305 MAC
    #[cfg(feature = "chacha20-poly1305")]
    pub fn poly1305_mac(key: &[u8; 32], data: &[u8]) -> Result<[u8; 16], Error> {
        Poly1305Mac::compute(key, data)
    }

    /// Constant-time MAC verification
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

    /// Generate a random MAC key
    #[cfg(feature = "rand_core")]
    pub fn generate_key<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
        key_length: usize,
    ) -> Vec<u8> {
        let mut key = vec![0u8; key_length];
        rng.fill_bytes(&mut key);
        key
    }
}

/// Multi-MAC that can compute multiple MACs simultaneously
pub struct MultiMac {
    #[cfg(all(feature = "hmac", feature = "sha2"))]
    hmac_sha256: Option<HmacSha256>,
    #[cfg(all(feature = "hmac", feature = "sha2"))]
    hmac_sha512: Option<HmacSha512>,
    #[cfg(all(feature = "hmac", feature = "sha3"))]
    hmac_sha3_256: Option<HmacSha3_256>,
    #[cfg(feature = "blake3")]
    blake3_mac: Option<Blake3Mac>,
}

impl MultiMac {
    /// Create a new multi-MAC with no algorithms enabled
    pub fn new() -> Self {
        Self {
            #[cfg(all(feature = "hmac", feature = "sha2"))]
            hmac_sha256: None,
            #[cfg(all(feature = "hmac", feature = "sha2"))]
            hmac_sha512: None,
            #[cfg(all(feature = "hmac", feature = "sha3"))]
            hmac_sha3_256: None,
            #[cfg(feature = "blake3")]
            blake3_mac: None,
        }
    }

    /// Enable HMAC-SHA256
    #[cfg(all(feature = "hmac", feature = "sha2"))]
    pub fn with_hmac_sha256(mut self, key: &[u8]) -> Result<Self, Error> {
        self.hmac_sha256 = Some(HmacSha256::new(key)?);
        Ok(self)
    }

    /// Enable HMAC-SHA512
    #[cfg(all(feature = "hmac", feature = "sha2"))]
    pub fn with_hmac_sha512(mut self, key: &[u8]) -> Result<Self, Error> {
        self.hmac_sha512 = Some(HmacSha512::new(key)?);
        Ok(self)
    }

    /// Enable HMAC-SHA3-256
    #[cfg(all(feature = "hmac", feature = "sha3"))]
    pub fn with_hmac_sha3_256(mut self, key: &[u8]) -> Result<Self, Error> {
        self.hmac_sha3_256 = Some(HmacSha3_256::new(key)?);
        Ok(self)
    }

    /// Enable Blake3 MAC
    #[cfg(feature = "blake3")]
    pub fn with_blake3_mac(mut self, key: &[u8; 32]) -> Result<Self, Error> {
        self.blake3_mac = Some(Blake3Mac::new(key)?);
        Ok(self)
    }

    /// Update all enabled MACs with data
    pub fn update(&mut self, data: &[u8]) {
        #[cfg(all(feature = "hmac", feature = "sha2"))]
        if let Some(ref mut mac) = self.hmac_sha256 {
            mac.update(data);
        }
        #[cfg(all(feature = "hmac", feature = "sha2"))]
        if let Some(ref mut mac) = self.hmac_sha512 {
            mac.update(data);
        }
        #[cfg(all(feature = "hmac", feature = "sha3"))]
        if let Some(ref mut mac) = self.hmac_sha3_256 {
            mac.update(data);
        }
        #[cfg(feature = "blake3")]
        if let Some(ref mut mac) = self.blake3_mac {
            mac.update(data);
        }
    }

    /// Finalize all MACs and return results
    pub fn finalize(self) -> MultiMacResults {
        MultiMacResults {
            #[cfg(all(feature = "hmac", feature = "sha2"))]
            hmac_sha256: self.hmac_sha256.map(|mac| mac.finalize()),
            #[cfg(all(feature = "hmac", feature = "sha2"))]
            hmac_sha512: self.hmac_sha512.map(|mac| mac.finalize()),
            #[cfg(all(feature = "hmac", feature = "sha3"))]
            hmac_sha3_256: self.hmac_sha3_256.map(|mac| mac.finalize()),
            #[cfg(feature = "blake3")]
            blake3_mac: self.blake3_mac.map(|mac| mac.finalize()),
        }
    }
}

impl Default for MultiMac {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "hmac", feature = "sha2"))]
    fn test_hmac_sha256() {
        let key = b"secret key";
        let data = b"hello world";

        let tag = utils::hmac_sha256(key, data).unwrap();
        assert_eq!(tag.len(), 32);

        // Test verification
        let mut mac = HmacSha256::new(key).unwrap();
        mac.update(data);
        mac.verify(&tag).unwrap();
    }

    #[test]
    #[cfg(all(feature = "hmac", feature = "sha2"))]
    fn test_hmac_sha512() {
        let key = b"secret key";
        let data = b"hello world";

        let tag = utils::hmac_sha512(key, data).unwrap();
        assert_eq!(tag.len(), 64);

        // Test verification
        let mut mac = HmacSha512::new(key).unwrap();
        mac.update(data);
        mac.verify(&tag).unwrap();
    }

    #[test]
    #[cfg(feature = "blake3")]
    fn test_blake3_mac() {
        let key = [0x42u8; 32];
        let data = b"hello world";

        let tag = utils::blake3_mac(&key, data);
        assert_eq!(tag.len(), 32);

        // Test verification
        let mut mac = Blake3Mac::new(&key).unwrap();
        mac.update(data);
        mac.verify(&tag).unwrap();
    }

    #[test]
    #[cfg(all(feature = "hmac", feature = "sha2"))]
    fn test_multi_mac() {
        let key = b"secret key";
        let data = b"hello world";

        let mut multi = MultiMac::new()
            .with_hmac_sha256(key)
            .unwrap();

        multi.update(data);
        let results = multi.finalize();

        assert!(results.hmac_sha256.is_some());
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

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_key_generation() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let key = utils::generate_key(&mut rng, 32);
        assert_eq!(key.len(), 32);

        let key2 = utils::generate_key(&mut rng, 32);
        assert_ne!(key, key2); // Should be different
    }
}