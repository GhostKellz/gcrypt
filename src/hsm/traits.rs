//! HSM Integration Traits
//!
//! Common traits for hardware security module integration.

use crate::Scalar;

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String, boxed::Box};

/// Error types for HSM operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HsmError {
    /// HSM not available
    NotAvailable,
    /// Authentication failed
    AuthenticationFailed,
    /// Invalid key handle
    InvalidKeyHandle,
    /// Operation not supported
    OperationNotSupported,
    /// HSM communication error
    CommunicationError,
    /// Key generation failed
    KeyGenerationFailed,
    /// Signature operation failed
    SignatureFailed,
}

/// Key handle for HSM-stored keys
pub type KeyHandle = u64;

/// HSM key attributes
#[derive(Debug, Clone)]
pub struct KeyAttributes {
    /// Key usage flags
    pub usage: KeyUsage,
    /// Whether key is extractable
    pub extractable: bool,
    /// Key label/identifier
    pub label: Option<String>,
}

/// Key usage flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage {
    /// Can be used for signing
    pub sign: bool,
    /// Can be used for verification
    pub verify: bool,
    /// Can be used for encryption
    pub encrypt: bool,
    /// Can be used for decryption
    pub decrypt: bool,
    /// Can be used for key derivation
    pub derive: bool,
}

impl KeyUsage {
    /// Signing key usage
    pub const SIGN: Self = Self {
        sign: true,
        verify: false,
        encrypt: false,
        decrypt: false,
        derive: false,
    };

    /// Key exchange usage
    pub const KEY_EXCHANGE: Self = Self {
        sign: false,
        verify: false,
        encrypt: false,
        decrypt: false,
        derive: true,
    };

    /// General purpose usage
    pub const ALL: Self = Self {
        sign: true,
        verify: true,
        encrypt: true,
        decrypt: true,
        derive: true,
    };
}

/// Trait for HSM providers
pub trait HsmProvider {
    /// Initialize connection to HSM
    fn initialize(&mut self) -> Result<(), HsmError>;

    /// Check if HSM is available
    fn is_available(&self) -> bool;

    /// Generate a key pair in the HSM
    fn generate_keypair(&mut self, attributes: KeyAttributes) -> Result<KeyHandle, HsmError>;

    /// Sign data using HSM-stored key
    fn sign(&self, key_handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Verify signature using HSM-stored key
    fn verify(&self, key_handle: KeyHandle, data: &[u8], signature: &[u8]) -> Result<bool, HsmError>;

    /// Get public key from HSM
    fn get_public_key(&self, key_handle: KeyHandle) -> Result<Vec<u8>, HsmError>;

    /// Delete key from HSM
    fn delete_key(&mut self, key_handle: KeyHandle) -> Result<(), HsmError>;

    /// List available keys
    fn list_keys(&self) -> Result<Vec<(KeyHandle, KeyAttributes)>, HsmError>;
}

/// Trait for secure random number generation
pub trait SecureRandom {
    /// Generate random bytes
    fn random_bytes(&mut self, output: &mut [u8]) -> Result<(), HsmError>;

    /// Generate random scalar
    fn random_scalar(&mut self) -> Result<Scalar, HsmError> {
        let mut bytes = [0u8; 32];
        self.random_bytes(&mut bytes)?;
        Ok(Scalar::from_bytes_mod_order(bytes))
    }
}

/// Trait for secure key storage
pub trait SecureStorage {
    /// Store encrypted data
    fn store(&mut self, key: &str, data: &[u8]) -> Result<(), HsmError>;

    /// Retrieve encrypted data
    fn retrieve(&self, key: &str) -> Result<Vec<u8>, HsmError>;

    /// Delete stored data
    fn delete(&mut self, key: &str) -> Result<(), HsmError>;

    /// List stored keys
    fn list(&self) -> Result<Vec<String>, HsmError>;
}

/// Mock HSM implementation for testing
#[derive(Debug, Default)]
pub struct MockHsm {
    /// In-memory key storage
    pub keys: std::collections::HashMap<KeyHandle, (KeyAttributes, Vec<u8>)>,
    /// Next key handle
    pub next_handle: KeyHandle,
    /// Whether HSM is initialized
    pub initialized: bool,
}

impl MockHsm {
    /// Create new mock HSM
    pub fn new() -> Self {
        Self::default()
    }
}

impl HsmProvider for MockHsm {
    fn initialize(&mut self) -> Result<(), HsmError> {
        self.initialized = true;
        Ok(())
    }

    fn is_available(&self) -> bool {
        self.initialized
    }

    fn generate_keypair(&mut self, attributes: KeyAttributes) -> Result<KeyHandle, HsmError> {
        if !self.initialized {
            return Err(HsmError::NotAvailable);
        }

        let handle = self.next_handle;
        self.next_handle += 1;

        // Generate mock key data
        let key_data = vec![0u8; 32]; // Placeholder

        self.keys.insert(handle, (attributes, key_data));
        Ok(handle)
    }

    fn sign(&self, key_handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        if !self.initialized {
            return Err(HsmError::NotAvailable);
        }

        let (attributes, _key_data) = self.keys.get(&key_handle)
            .ok_or(HsmError::InvalidKeyHandle)?;

        if !attributes.usage.sign {
            return Err(HsmError::OperationNotSupported);
        }

        // Mock signature (just hash the data)
        let mut hasher = crate::hash::Sha256Hasher::new();
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    fn verify(&self, key_handle: KeyHandle, data: &[u8], signature: &[u8]) -> Result<bool, HsmError> {
        if !self.initialized {
            return Err(HsmError::NotAvailable);
        }

        let (attributes, _key_data) = self.keys.get(&key_handle)
            .ok_or(HsmError::InvalidKeyHandle)?;

        if !attributes.usage.verify {
            return Err(HsmError::OperationNotSupported);
        }

        // Mock verification (check if signature matches hash)
        let mut hasher = crate::hash::Sha256Hasher::new();
        hasher.update(data);
        let expected = hasher.finalize();

        Ok(signature == expected.as_slice())
    }

    fn get_public_key(&self, key_handle: KeyHandle) -> Result<Vec<u8>, HsmError> {
        if !self.initialized {
            return Err(HsmError::NotAvailable);
        }

        let (_attributes, key_data) = self.keys.get(&key_handle)
            .ok_or(HsmError::InvalidKeyHandle)?;

        Ok(key_data.clone())
    }

    fn delete_key(&mut self, key_handle: KeyHandle) -> Result<(), HsmError> {
        if !self.initialized {
            return Err(HsmError::NotAvailable);
        }

        self.keys.remove(&key_handle)
            .ok_or(HsmError::InvalidKeyHandle)?;

        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<(KeyHandle, KeyAttributes)>, HsmError> {
        if !self.initialized {
            return Err(HsmError::NotAvailable);
        }

        Ok(self.keys.iter()
            .map(|(&handle, (attrs, _))| (handle, attrs.clone()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_hsm() {
        let mut hsm = MockHsm::new();
        assert!(!hsm.is_available());

        hsm.initialize().unwrap();
        assert!(hsm.is_available());

        let attrs = KeyAttributes {
            usage: KeyUsage::SIGN,
            extractable: false,
            label: Some("test-key".to_string()),
        };

        let handle = hsm.generate_keypair(attrs).unwrap();
        assert_eq!(handle, 0);

        let data = b"test message";
        let signature = hsm.sign(handle, data).unwrap();
        let result = hsm.verify(handle, data, &signature).unwrap();
        assert!(result);

        hsm.delete_key(handle).unwrap();
        assert!(hsm.get_public_key(handle).is_err());
    }

    #[test]
    fn test_key_usage() {
        let signing = KeyUsage::SIGN;
        assert!(signing.sign);
        assert!(!signing.encrypt);

        let kex = KeyUsage::KEY_EXCHANGE;
        assert!(!kex.sign);
        assert!(kex.derive);

        let all = KeyUsage::ALL;
        assert!(all.sign && all.verify && all.encrypt && all.decrypt && all.derive);
    }
}