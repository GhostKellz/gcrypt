//! Cryptographic hash functions
//!
//! This module provides implementations of various cryptographic hash functions
//! commonly used in blockchain and cryptographic applications:
//! - SHA-256 and SHA-512 (NIST standards)
//! - SHA-3 family including Keccak-256 (Ethereum compatible)
//! - Blake3 (high performance modern hash)

#[cfg(feature = "sha2")]
use sha2::{Sha256, Sha512, Digest as Sha2Digest};

#[cfg(feature = "sha3")]
use sha3::{Sha3_256, Sha3_512, Keccak256, Digest as Sha3Digest};

#[cfg(feature = "blake3")]
use blake3::{Hasher as Blake3Hasher, Hash as Blake3Hash};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Common trait for hash functions
pub trait Hash {
    type Output;

    /// Create a new hasher instance
    fn new() -> Self;

    /// Update the hasher with input data
    fn update(&mut self, data: &[u8]);

    /// Finalize the hash and return the digest
    fn finalize(self) -> Self::Output;

    /// Convenience method to hash data in one call
    fn hash(data: &[u8]) -> Self::Output
    where
        Self: Sized,
    {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// SHA-256 hasher
#[cfg(feature = "sha2")]
#[derive(Clone)]
pub struct Sha256Hasher {
    inner: Sha256,
}

#[cfg(feature = "sha2")]
impl Hash for Sha256Hasher {
    type Output = [u8; 32];

    fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        self.inner.finalize().into()
    }
}

/// SHA-512 hasher
#[cfg(feature = "sha2")]
#[derive(Clone)]
pub struct Sha512Hasher {
    inner: Sha512,
}

#[cfg(feature = "sha2")]
impl Hash for Sha512Hasher {
    type Output = [u8; 64];

    fn new() -> Self {
        Self {
            inner: Sha512::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        self.inner.finalize().into()
    }
}

/// SHA3-256 hasher
#[cfg(feature = "sha3")]
#[derive(Clone)]
pub struct Sha3_256Hasher {
    inner: Sha3_256,
}

#[cfg(feature = "sha3")]
impl Hash for Sha3_256Hasher {
    type Output = [u8; 32];

    fn new() -> Self {
        Self {
            inner: Sha3_256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        self.inner.finalize().into()
    }
}

/// SHA3-512 hasher
#[cfg(feature = "sha3")]
#[derive(Clone)]
pub struct Sha3_512Hasher {
    inner: Sha3_512,
}

#[cfg(feature = "sha3")]
impl Hash for Sha3_512Hasher {
    type Output = [u8; 64];

    fn new() -> Self {
        Self {
            inner: Sha3_512::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        self.inner.finalize().into()
    }
}

/// Keccak-256 hasher (Ethereum compatible)
#[cfg(feature = "sha3")]
#[derive(Clone)]
pub struct Keccak256Hasher {
    inner: Keccak256,
}

#[cfg(feature = "sha3")]
impl Hash for Keccak256Hasher {
    type Output = [u8; 32];

    fn new() -> Self {
        Self {
            inner: Keccak256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        self.inner.finalize().into()
    }
}

/// Blake3 hasher
#[cfg(feature = "blake3")]
#[derive(Clone)]
pub struct Blake3HasherWrapper {
    inner: Blake3Hasher,
}

#[cfg(feature = "blake3")]
impl Hash for Blake3HasherWrapper {
    type Output = [u8; 32];

    fn new() -> Self {
        Self {
            inner: Blake3Hasher::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Self::Output {
        self.inner.finalize().into()
    }
}

#[cfg(feature = "blake3")]
impl Blake3HasherWrapper {
    /// Create a keyed hasher for MAC functionality
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self {
            inner: Blake3Hasher::new_keyed(key),
        }
    }

    /// Create a hasher for key derivation
    pub fn new_derive_key(context: &str) -> Self {
        Self {
            inner: Blake3Hasher::new_derive_key(context),
        }
    }

    /// Finalize to variable length output
    pub fn finalize_variable(&self, length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        self.inner.finalize_xof().fill(&mut output);
        output
    }
}

/// Results from multi-hasher
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MultiHashResults {
    #[cfg(feature = "sha2")]
    pub sha256: Option<[u8; 32]>,
    #[cfg(feature = "sha2")]
    pub sha512: Option<[u8; 64]>,
    #[cfg(feature = "sha3")]
    pub sha3_256: Option<[u8; 32]>,
    #[cfg(feature = "sha3")]
    pub keccak256: Option<[u8; 32]>,
    #[cfg(feature = "blake3")]
    pub blake3: Option<[u8; 32]>,
}

/// Convenience functions for common hashing operations
pub mod utils {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::{vec::Vec, string::String, format};

    /// Hash with SHA-256
    #[cfg(feature = "sha2")]
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256Hasher::hash(data)
    }

    /// Hash with SHA-512
    #[cfg(feature = "sha2")]
    pub fn sha512(data: &[u8]) -> [u8; 64] {
        Sha512Hasher::hash(data)
    }

    /// Hash with SHA3-256
    #[cfg(feature = "sha3")]
    pub fn sha3_256(data: &[u8]) -> [u8; 32] {
        Sha3_256Hasher::hash(data)
    }

    /// Hash with SHA3-512
    #[cfg(feature = "sha3")]
    pub fn sha3_512(data: &[u8]) -> [u8; 64] {
        Sha3_512Hasher::hash(data)
    }

    /// Hash with Keccak-256 (Ethereum compatible)
    #[cfg(feature = "sha3")]
    pub fn keccak256(data: &[u8]) -> [u8; 32] {
        Keccak256Hasher::hash(data)
    }

    /// Hash with Blake3
    #[cfg(feature = "blake3")]
    pub fn blake3(data: &[u8]) -> [u8; 32] {
        Blake3HasherWrapper::hash(data)
    }

    /// Double SHA-256 (Bitcoin standard)
    #[cfg(feature = "sha2")]
    pub fn double_sha256(data: &[u8]) -> [u8; 32] {
        let first = sha256(data);
        sha256(&first)
    }

    /// Hash160 (RIPEMD160(SHA256(data))) - common in Bitcoin
    #[cfg(all(feature = "sha2", feature = "ripemd160"))]
    pub fn hash160(data: &[u8]) -> [u8; 20] {
        use ripemd::{Ripemd160, Digest};
        let sha = sha256(data);
        let mut hasher = Ripemd160::new();
        hasher.update(&sha);
        hasher.finalize().into()
    }

    /// Ethereum address from public key (Keccak256 of uncompressed public key)
    #[cfg(feature = "sha3")]
    pub fn ethereum_address(uncompressed_pubkey: &[u8; 64]) -> [u8; 20] {
        let hash = keccak256(uncompressed_pubkey);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }

    /// Convert hash to hex string
    pub fn to_hex(hash: &[u8]) -> String {
        hash.iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Parse hex string to bytes
    pub fn from_hex(hex: &str) -> Result<Vec<u8>, &'static str> {
        if hex.len() % 2 != 0 {
            return Err("Hex string must have even length");
        }

        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|_| "Invalid hex character")
            })
            .collect()
    }
}

/// Multi-hasher that can compute multiple hashes simultaneously
#[derive(Clone)]
pub struct MultiHasher {
    #[cfg(feature = "sha2")]
    sha256: Option<Sha256Hasher>,
    #[cfg(feature = "sha2")]
    sha512: Option<Sha512Hasher>,
    #[cfg(feature = "sha3")]
    sha3_256: Option<Sha3_256Hasher>,
    #[cfg(feature = "sha3")]
    keccak256: Option<Keccak256Hasher>,
    #[cfg(feature = "blake3")]
    blake3: Option<Blake3HasherWrapper>,
}

impl MultiHasher {
    /// Create a new multi-hasher with no algorithms enabled
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "sha2")]
            sha256: None,
            #[cfg(feature = "sha2")]
            sha512: None,
            #[cfg(feature = "sha3")]
            sha3_256: None,
            #[cfg(feature = "sha3")]
            keccak256: None,
            #[cfg(feature = "blake3")]
            blake3: None,
        }
    }

    /// Enable SHA-256
    #[cfg(feature = "sha2")]
    pub fn with_sha256(mut self) -> Self {
        self.sha256 = Some(Sha256Hasher::new());
        self
    }

    /// Enable SHA-512
    #[cfg(feature = "sha2")]
    pub fn with_sha512(mut self) -> Self {
        self.sha512 = Some(Sha512Hasher::new());
        self
    }

    /// Enable SHA3-256
    #[cfg(feature = "sha3")]
    pub fn with_sha3_256(mut self) -> Self {
        self.sha3_256 = Some(Sha3_256Hasher::new());
        self
    }

    /// Enable Keccak-256
    #[cfg(feature = "sha3")]
    pub fn with_keccak256(mut self) -> Self {
        self.keccak256 = Some(Keccak256Hasher::new());
        self
    }

    /// Enable Blake3
    #[cfg(feature = "blake3")]
    pub fn with_blake3(mut self) -> Self {
        self.blake3 = Some(Blake3HasherWrapper::new());
        self
    }

    /// Update all enabled hashers with data
    pub fn update(&mut self, data: &[u8]) {
        #[cfg(feature = "sha2")]
        if let Some(ref mut h) = self.sha256 {
            h.update(data);
        }
        #[cfg(feature = "sha2")]
        if let Some(ref mut h) = self.sha512 {
            h.update(data);
        }
        #[cfg(feature = "sha3")]
        if let Some(ref mut h) = self.sha3_256 {
            h.update(data);
        }
        #[cfg(feature = "sha3")]
        if let Some(ref mut h) = self.keccak256 {
            h.update(data);
        }
        #[cfg(feature = "blake3")]
        if let Some(ref mut h) = self.blake3 {
            h.update(data);
        }
    }

    /// Finalize all hashes and return results
    pub fn finalize(self) -> MultiHashResults {
        MultiHashResults {
            #[cfg(feature = "sha2")]
            sha256: self.sha256.map(|h| h.finalize()),
            #[cfg(feature = "sha2")]
            sha512: self.sha512.map(|h| h.finalize()),
            #[cfg(feature = "sha3")]
            sha3_256: self.sha3_256.map(|h| h.finalize()),
            #[cfg(feature = "sha3")]
            keccak256: self.keccak256.map(|h| h.finalize()),
            #[cfg(feature = "blake3")]
            blake3: self.blake3.map(|h| h.finalize()),
        }
    }
}

impl Default for MultiHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "sha2")]
    fn test_sha256() {
        let data = b"hello world";
        let hash = utils::sha256(data);
        let expected = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08,
            0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
            0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
            0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_double_sha256() {
        let data = b"hello";
        let hash = utils::double_sha256(data);
        // This should be SHA256(SHA256("hello"))
        assert_eq!(hash.len(), 32);
    }

    #[test]
    #[cfg(feature = "sha3")]
    fn test_keccak256() {
        let data = b"hello world";
        let hash = utils::keccak256(data);
        // Keccak256 is different from SHA3-256
        assert_eq!(hash.len(), 32);
    }

    #[test]
    #[cfg(feature = "blake3")]
    fn test_blake3() {
        let data = b"hello world";
        let hash = utils::blake3(data);
        assert_eq!(hash.len(), 32);

        // Test keyed Blake3
        let key = [0x42u8; 32];
        let mut keyed_hasher = Blake3HasherWrapper::new_keyed(&key);
        keyed_hasher.update(data);
        let keyed_hash = keyed_hasher.finalize();
        assert_ne!(hash, keyed_hash);
    }

    #[test]
    fn test_multi_hasher() {
        let data = b"hello world";
        let mut multi = MultiHasher::new();

        #[cfg(feature = "sha2")]
        let multi = multi.with_sha256();
        #[cfg(feature = "sha3")]
        let multi = multi.with_keccak256();

        let mut multi = multi;
        multi.update(data);
        let results = multi.finalize();

        #[cfg(feature = "sha2")]
        assert!(results.sha256.is_some());
        #[cfg(feature = "sha3")]
        assert!(results.keccak256.is_some());
    }

    #[test]
    fn test_hex_utils() {
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = utils::to_hex(&data);
        assert_eq!(hex, "0123456789abcdef");

        let parsed = utils::from_hex(&hex).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    #[cfg(feature = "sha3")]
    fn test_ethereum_address() {
        // Test with a known public key
        let pubkey = [0u8; 64]; // Simplified test
        let address = utils::ethereum_address(&pubkey);
        assert_eq!(address.len(), 20);
    }
}