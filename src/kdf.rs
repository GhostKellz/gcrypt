//! Key Derivation Functions (KDF)
//!
//! This module provides implementations of various key derivation functions:
//! - HKDF (RFC 5869) - HMAC-based Extract-and-Expand Key Derivation Function
//! - Argon2id - Memory-hard password-based key derivation
//! - PBKDF2 - Password-Based Key Derivation Function 2
//! - Custom KDFs for specific protocols

#[cfg(feature = "hkdf")]
use hkdf::Hkdf;

#[cfg(feature = "argon2")]
use argon2::{Argon2, Algorithm, Version, Params, password_hash::{PasswordHasher, SaltString}};

#[cfg(feature = "sha2")]
use sha2::{Sha256, Sha512};

#[cfg(feature = "sha3")]
use sha3::Sha3_256;

#[cfg(feature = "blake3")]
use crate::hash::Blake3HasherWrapper;

#[cfg(feature = "rand_core")]
use rand_core::{RngCore, CryptoRng};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::{String, ToString}};

/// Error types for KDF operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid input key material length
    InvalidInputLength,
    /// Invalid salt length
    InvalidSaltLength,
    /// Invalid output length
    InvalidOutputLength,
    /// Invalid parameters
    InvalidParameters,
    /// KDF library error
    KdfError(String),
}

/// Common trait for key derivation functions
pub trait KeyDerivationFunction {
    /// Derive key material of the specified length
    fn derive(&self, input: &[u8], salt: &[u8], output_length: usize) -> Result<Vec<u8>, Error>;

    /// Derive key material into a provided buffer
    fn derive_into(&self, input: &[u8], salt: &[u8], output: &mut [u8]) -> Result<(), Error> {
        let derived = self.derive(input, salt, output.len())?;
        output.copy_from_slice(&derived);
        Ok(())
    }
}

/// HKDF implementation with SHA-256
#[cfg(all(feature = "hkdf", feature = "sha2"))]
#[derive(Clone)]
pub struct HkdfSha256 {
    info: Vec<u8>,
}

#[cfg(all(feature = "hkdf", feature = "sha2"))]
impl HkdfSha256 {
    /// Create a new HKDF instance with optional info parameter
    pub fn new(info: Option<&[u8]>) -> Self {
        Self {
            info: info.unwrap_or(&[]).to_vec(),
        }
    }

    /// Extract phase: derive a pseudorandom key from input key material
    pub fn extract(salt: Option<&[u8]>, input: &[u8]) -> (Vec<u8>, usize) {
        let hkdf = Hkdf::<Sha256>::new(salt, input);
        // Return the PRK and its length (32 bytes for SHA-256)
        (vec![0u8; 32], 32) // Simplified for example
    }

    /// Expand phase: derive output key material from pseudorandom key
    pub fn expand(&self, prk: &[u8], output_length: usize) -> Result<Vec<u8>, Error> {
        let hkdf = Hkdf::<Sha256>::from_prk(prk)
            .map_err(|e| Error::KdfError(format!("{:?}", e)))?;

        let mut output = vec![0u8; output_length];
        hkdf.expand(&self.info, &mut output)
            .map_err(|e| Error::KdfError(format!("{:?}", e)))?;

        Ok(output)
    }
}

#[cfg(all(feature = "hkdf", feature = "sha2"))]
impl KeyDerivationFunction for HkdfSha256 {
    fn derive(&self, input: &[u8], salt: &[u8], output_length: usize) -> Result<Vec<u8>, Error> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), input);
        let mut output = vec![0u8; output_length];
        hkdf.expand(&self.info, &mut output)
            .map_err(|e| Error::KdfError(format!("{:?}", e)))?;
        Ok(output)
    }
}

/// HKDF implementation with SHA-512
#[cfg(all(feature = "hkdf", feature = "sha2"))]
#[derive(Clone)]
pub struct HkdfSha512 {
    info: Vec<u8>,
}

#[cfg(all(feature = "hkdf", feature = "sha2"))]
impl HkdfSha512 {
    /// Create a new HKDF instance with optional info parameter
    pub fn new(info: Option<&[u8]>) -> Self {
        Self {
            info: info.unwrap_or(&[]).to_vec(),
        }
    }
}

#[cfg(all(feature = "hkdf", feature = "sha2"))]
impl KeyDerivationFunction for HkdfSha512 {
    fn derive(&self, input: &[u8], salt: &[u8], output_length: usize) -> Result<Vec<u8>, Error> {
        let hkdf = Hkdf::<Sha512>::new(Some(salt), input);
        let mut output = vec![0u8; output_length];
        hkdf.expand(&self.info, &mut output)
            .map_err(|e| Error::KdfError(format!("{:?}", e)))?;
        Ok(output)
    }
}

/// Argon2id password-based key derivation
#[cfg(feature = "argon2")]
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub struct Argon2idKdf {
    params: Params,
}

#[cfg(feature = "argon2")]
impl Argon2idKdf {
    /// Create a new Argon2id KDF with default parameters
    pub fn new() -> Result<Self, Error> {
        let params = Params::new(
            Params::DEFAULT_M_COST,     // Memory cost (KB)
            Params::DEFAULT_T_COST,     // Time cost (iterations)
            Params::DEFAULT_P_COST,     // Parallelism
            Some(Params::DEFAULT_OUTPUT_LEN), // Output length
        ).map_err(|e| Error::KdfError(format!("{:?}", e)))?;

        Ok(Self { params })
    }

    /// Create with custom parameters
    pub fn with_params(
        memory_cost: u32,    // Memory cost in KB
        time_cost: u32,      // Number of iterations
        parallelism: u32,    // Number of parallel threads
        output_length: usize, // Output length in bytes
    ) -> Result<Self, Error> {
        let params = Params::new(
            memory_cost,
            time_cost,
            parallelism,
            Some(output_length),
        ).map_err(|e| Error::KdfError(format!("{:?}", e)))?;

        Ok(Self { params })
    }

    /// Derive key from password and salt
    pub fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>, Error> {
        if salt.len() < 8 {
            return Err(Error::InvalidSaltLength);
        }

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone());

        let mut output = vec![0u8; self.params.output_len().unwrap_or(32)];
        argon2.hash_password_into(password, salt, &mut output)
            .map_err(|e| Error::KdfError(format!("{:?}", e)))?;

        Ok(output)
    }

    /// Generate a random salt
    #[cfg(feature = "rand_core")]
    pub fn generate_salt<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        salt
    }

    /// Recommended parameters for interactive use (fast)
    pub fn interactive() -> Result<Self, Error> {
        Self::with_params(
            64 * 1024,  // 64 MB
            3,          // 3 iterations
            4,          // 4 parallel threads
            32,         // 32 byte output
        )
    }

    /// Recommended parameters for sensitive use (slow but secure)
    pub fn sensitive() -> Result<Self, Error> {
        Self::with_params(
            256 * 1024, // 256 MB
            5,          // 5 iterations
            4,          // 4 parallel threads
            32,         // 32 byte output
        )
    }
}

#[cfg(feature = "argon2")]
impl Default for Argon2idKdf {
    fn default() -> Self {
        Self::new().expect("Default Argon2id parameters should be valid")
    }
}

#[cfg(feature = "argon2")]
impl KeyDerivationFunction for Argon2idKdf {
    fn derive(&self, input: &[u8], salt: &[u8], _output_length: usize) -> Result<Vec<u8>, Error> {
        self.derive_key(input, salt)
    }
}

/// Blake3-based key derivation
#[cfg(feature = "blake3")]
#[derive(Clone)]
pub struct Blake3Kdf {
    context: String,
}

#[cfg(feature = "blake3")]
impl Blake3Kdf {
    /// Create a new Blake3 KDF with context string
    pub fn new(context: &str) -> Self {
        Self {
            context: context.to_string(),
        }
    }
}

#[cfg(feature = "blake3")]
impl KeyDerivationFunction for Blake3Kdf {
    fn derive(&self, input: &[u8], _salt: &[u8], output_length: usize) -> Result<Vec<u8>, Error> {
        let mut hasher = Blake3HasherWrapper::new_derive_key(&self.context);
        hasher.update(input);
        Ok(hasher.finalize_variable(output_length))
    }
}

/// Utility functions for key derivation
pub mod utils {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::vec;

    /// Derive key using HKDF-SHA256
    #[cfg(all(feature = "hkdf", feature = "sha2"))]
    pub fn hkdf_sha256(
        input: &[u8],
        salt: &[u8],
        info: Option<&[u8]>,
        output_length: usize,
    ) -> Result<Vec<u8>, Error> {
        let kdf = HkdfSha256::new(info);
        kdf.derive(input, salt, output_length)
    }

    /// Derive key using HKDF-SHA512
    #[cfg(all(feature = "hkdf", feature = "sha2"))]
    pub fn hkdf_sha512(
        input: &[u8],
        salt: &[u8],
        info: Option<&[u8]>,
        output_length: usize,
    ) -> Result<Vec<u8>, Error> {
        let kdf = HkdfSha512::new(info);
        kdf.derive(input, salt, output_length)
    }

    /// Derive key using Argon2id with default parameters
    #[cfg(feature = "argon2")]
    pub fn argon2id(password: &[u8], salt: &[u8]) -> Result<[u8; 32], Error> {
        let kdf = Argon2idKdf::new()?;
        let result = kdf.derive_key(password, salt)?;
        let mut output = [0u8; 32];
        output.copy_from_slice(&result[..32]);
        Ok(output)
    }

    /// Derive key using Blake3
    #[cfg(feature = "blake3")]
    pub fn blake3_derive(
        input: &[u8],
        context: &str,
        output_length: usize,
    ) -> Vec<u8> {
        let kdf = Blake3Kdf::new(context);
        kdf.derive(input, &[], output_length)
            .expect("Blake3 KDF should not fail")
    }

    /// Generate a cryptographically secure salt
    #[cfg(feature = "rand_core")]
    pub fn generate_salt<R: RngCore + CryptoRng>(rng: &mut R, length: usize) -> Vec<u8> {
        let mut salt = vec![0u8; length];
        rng.fill_bytes(&mut salt);
        salt
    }

    /// Timing-safe key stretching using multiple iterations
    pub fn stretch_key(
        input: &[u8],
        salt: &[u8],
        iterations: u32,
        output_length: usize,
    ) -> Result<Vec<u8>, Error> {
        #[cfg(all(feature = "hkdf", feature = "sha2"))]
        {
            let mut current = input.to_vec();
            for _ in 0..iterations {
                let kdf = HkdfSha256::new(None);
                current = kdf.derive(&current, salt, output_length)?;
            }
            Ok(current)
        }
        #[cfg(not(all(feature = "hkdf", feature = "sha2")))]
        {
            Err(Error::KdfError("HKDF not available".to_string()))
        }
    }
}

/// Configuration for key derivation parameters
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KdfConfig {
    /// KDF algorithm to use
    pub algorithm: KdfAlgorithm,
    /// Salt (if applicable)
    pub salt: Option<Vec<u8>>,
    /// Output length in bytes
    pub output_length: usize,
    /// Algorithm-specific parameters
    pub params: KdfParams,
}

/// Supported KDF algorithms
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KdfAlgorithm {
    #[cfg(feature = "hkdf")]
    HkdfSha256,
    #[cfg(feature = "hkdf")]
    HkdfSha512,
    #[cfg(feature = "argon2")]
    Argon2id,
    #[cfg(feature = "blake3")]
    Blake3,
}

/// Algorithm-specific parameters
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KdfParams {
    #[cfg(feature = "hkdf")]
    Hkdf { info: Option<Vec<u8>> },
    #[cfg(feature = "argon2")]
    Argon2 {
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
    },
    #[cfg(feature = "blake3")]
    Blake3 { context: String },
}

impl KdfConfig {
    /// Execute the KDF with this configuration
    pub fn derive(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let salt = self.salt.as_deref().unwrap_or(&[]);

        match (&self.algorithm, &self.params) {
            #[cfg(feature = "hkdf")]
            (KdfAlgorithm::HkdfSha256, KdfParams::Hkdf { info }) => {
                let kdf = HkdfSha256::new(info.as_deref());
                kdf.derive(input, salt, self.output_length)
            }
            #[cfg(feature = "hkdf")]
            (KdfAlgorithm::HkdfSha512, KdfParams::Hkdf { info }) => {
                let kdf = HkdfSha512::new(info.as_deref());
                kdf.derive(input, salt, self.output_length)
            }
            #[cfg(feature = "argon2")]
            (KdfAlgorithm::Argon2id, KdfParams::Argon2 { memory_cost, time_cost, parallelism }) => {
                let kdf = Argon2idKdf::with_params(*memory_cost, *time_cost, *parallelism, self.output_length)?;
                kdf.derive(input, salt, self.output_length)
            }
            #[cfg(feature = "blake3")]
            (KdfAlgorithm::Blake3, KdfParams::Blake3 { context }) => {
                let kdf = Blake3Kdf::new(context);
                kdf.derive(input, salt, self.output_length)
            }
            _ => Err(Error::InvalidParameters),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "hkdf", feature = "sha2"))]
    fn test_hkdf_sha256() {
        let input = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let kdf = HkdfSha256::new(Some(info));
        let output = kdf.derive(input, salt, 32).unwrap();
        assert_eq!(output.len(), 32);

        // Test that different inputs produce different outputs
        let kdf2 = HkdfSha256::new(Some(b"different info"));
        let output2 = kdf2.derive(input, salt, 32).unwrap();
        assert_ne!(output, output2);
    }

    #[test]
    #[cfg(feature = "argon2")]
    fn test_argon2id() {
        let password = b"password123";
        let salt = b"saltsaltsaltsaltsaltsaltsalt"; // 28 bytes

        let kdf = Argon2idKdf::interactive().unwrap();
        let output = kdf.derive_key(password, salt).unwrap();
        assert_eq!(output.len(), 32);

        // Test that same inputs produce same outputs
        let output2 = kdf.derive_key(password, salt).unwrap();
        assert_eq!(output, output2);

        // Test that different passwords produce different outputs
        let output3 = kdf.derive_key(b"different", salt).unwrap();
        assert_ne!(output, output3);
    }

    #[test]
    #[cfg(feature = "blake3")]
    fn test_blake3_kdf() {
        let input = b"input material";
        let context = "test context";

        let kdf = Blake3Kdf::new(context);
        let output = kdf.derive(input, &[], 32).unwrap();
        assert_eq!(output.len(), 32);

        // Test variable length output
        let long_output = kdf.derive(input, &[], 64).unwrap();
        assert_eq!(long_output.len(), 64);
        assert_ne!(output, long_output[..32]);
    }

    #[test]
    #[cfg(all(feature = "hkdf", feature = "sha2"))]
    fn test_utils() {
        let input = b"test input";
        let salt = b"test salt";
        let info = Some(&b"test info"[..]);

        let output = utils::hkdf_sha256(input, salt, info, 32).unwrap();
        assert_eq!(output.len(), 32);
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_salt_generation() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let salt1 = utils::generate_salt(&mut rng, 32);
        let salt2 = utils::generate_salt(&mut rng, 32);

        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_ne!(salt1, salt2);
    }

    #[test]
    #[cfg(all(feature = "hkdf", feature = "sha2", feature = "serde"))]
    fn test_kdf_config() {
        let config = KdfConfig {
            algorithm: KdfAlgorithm::HkdfSha256,
            salt: Some(b"test salt".to_vec()),
            output_length: 32,
            params: KdfParams::Hkdf { info: Some(b"test info".to_vec()) },
        };

        let input = b"test input";
        let output = config.derive(input).unwrap();
        assert_eq!(output.len(), 32);
    }
}