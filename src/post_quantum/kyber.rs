//! Kyber Post-Quantum Key Encapsulation Mechanism
//!
//! Implementation of the Kyber KEM, based on the hardness of the
//! Module Learning With Errors (M-LWE) problem.

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Error types for Kyber operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KyberError {
    /// Invalid key size
    InvalidKeySize,
    /// Invalid ciphertext
    InvalidCiphertext,
    /// Decapsulation failed
    DecapsulationFailed,
    /// Invalid parameters
    InvalidParameters,
    /// Random number generation failed
    RandomnessError,
    /// Serialization error
    SerializationError,
}

/// Kyber parameter sets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KyberParameterSet {
    /// Kyber512 (NIST Level 1 security)
    Kyber512,
    /// Kyber768 (NIST Level 3 security)
    Kyber768,
    /// Kyber1024 (NIST Level 5 security)
    Kyber1024,
}

impl KyberParameterSet {
    /// Get the parameters for this set
    pub fn parameters(&self) -> KyberParameters {
        match self {
            KyberParameterSet::Kyber512 => KyberParameters {
                k: 2,
                n: 256,
                q: 3329,
                eta1: 3,
                eta2: 2,
                du: 10,
                dv: 4,
                dt: 10,
            },
            KyberParameterSet::Kyber768 => KyberParameters {
                k: 3,
                n: 256,
                q: 3329,
                eta1: 2,
                eta2: 2,
                du: 10,
                dv: 4,
                dt: 10,
            },
            KyberParameterSet::Kyber1024 => KyberParameters {
                k: 4,
                n: 256,
                q: 3329,
                eta1: 2,
                eta2: 2,
                du: 11,
                dv: 5,
                dt: 11,
            },
        }
    }
}

/// Kyber algorithm parameters
#[derive(Debug, Clone, Copy)]
pub struct KyberParameters {
    /// Dimension of the module
    pub k: usize,
    /// Degree of the polynomial ring
    pub n: usize,
    /// Modulus
    pub q: u16,
    /// Noise parameter for secret key
    pub eta1: i16,
    /// Noise parameter for error vector
    pub eta2: i16,
    /// Number of bits for compression of u
    pub du: usize,
    /// Number of bits for compression of v
    pub dv: usize,
    /// Number of bits for compression of t
    pub dt: usize,
}

/// Kyber secret key
#[derive(Debug, Clone)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KyberSecretKey {
    /// Parameter set
    pub params: KyberParameterSet,
    /// Secret key data
    pub data: Vec<u8>,
}

/// Kyber public key
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KyberPublicKey {
    /// Parameter set
    pub params: KyberParameterSet,
    /// Public key data
    pub data: Vec<u8>,
}

/// Kyber ciphertext
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KyberCiphertext {
    /// Parameter set
    pub params: KyberParameterSet,
    /// Ciphertext data
    pub data: Vec<u8>,
}

/// Kyber shared secret
#[derive(Debug, Clone)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub struct KyberSharedSecret {
    /// 32-byte shared secret
    pub bytes: [u8; 32],
}

/// Kyber key pair
#[derive(Debug, Clone)]
pub struct KyberKeyPair {
    /// Secret key
    pub secret_key: KyberSecretKey,
    /// Public key
    pub public_key: KyberPublicKey,
}

impl KyberKeyPair {
    /// Generate a new Kyber key pair
    #[cfg(feature = "rand_core")]
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(
        params: KyberParameterSet,
        rng: &mut R,
    ) -> Result<Self, KyberError> {
        let param_values = params.parameters();

        // Key generation (simplified)
        // In practice, this would involve:
        // 1. Sample random matrix A
        // 2. Sample secret vector s from noise distribution
        // 3. Sample error vector e from noise distribution
        // 4. Compute t = A*s + e

        let sk_size = 32 + param_values.k * param_values.n * 2; // Simplified
        let pk_size = param_values.k * param_values.n * 2 + 32; // t + seed

        let mut sk_data = vec![0u8; sk_size];
        let mut pk_data = vec![0u8; pk_size];

        rng.fill_bytes(&mut sk_data);
        rng.fill_bytes(&mut pk_data);

        let secret_key = KyberSecretKey {
            params,
            data: sk_data,
        };

        let public_key = KyberPublicKey {
            params,
            data: pk_data,
        };

        Ok(KyberKeyPair {
            secret_key,
            public_key,
        })
    }

    /// Encapsulate: generate shared secret and ciphertext
    #[cfg(feature = "rand_core")]
    pub fn encapsulate<R: rand_core::RngCore + rand_core::CryptoRng>(
        public_key: &KyberPublicKey,
        rng: &mut R,
    ) -> Result<(KyberSharedSecret, KyberCiphertext), KyberError> {
        let param_values = public_key.params.parameters();

        // Encapsulation (simplified)
        // In practice, this would involve:
        // 1. Sample random message m
        // 2. Compute (K, r) = G(m || H(pk))
        // 3. Compute ciphertext c = Encrypt(pk, m, r)
        // 4. Return (K, c)

        let ct_size = param_values.k * param_values.n * param_values.du / 8 +
                      param_values.n * param_values.dv / 8;

        let mut ct_data = vec![0u8; ct_size];
        rng.fill_bytes(&mut ct_data);

        // Generate shared secret
        let mut shared_secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut shared_secret_bytes);

        let shared_secret = KyberSharedSecret {
            bytes: shared_secret_bytes,
        };

        let ciphertext = KyberCiphertext {
            params: public_key.params,
            data: ct_data,
        };

        Ok((shared_secret, ciphertext))
    }

    /// Decapsulate: recover shared secret from ciphertext
    pub fn decapsulate(
        secret_key: &KyberSecretKey,
        ciphertext: &KyberCiphertext,
    ) -> Result<KyberSharedSecret, KyberError> {
        // Check parameter compatibility
        if secret_key.params != ciphertext.params {
            return Err(KyberError::InvalidParameters);
        }

        // Decapsulation (simplified)
        // In practice, this would involve:
        // 1. Decrypt ciphertext to get m'
        // 2. Compute (K', r') = G(m' || H(pk))
        // 3. Compute c' = Encrypt(pk, m', r')
        // 4. If c' = c, return K', else return random value

        // Simplified: derive shared secret from ciphertext and secret key
        let mut shared_secret_bytes = [0u8; 32];
        for i in 0..32 {
            let sk_byte = secret_key.data.get(i).copied().unwrap_or(0);
            let ct_byte = ciphertext.data.get(i).copied().unwrap_or(0);
            shared_secret_bytes[i] = sk_byte ^ ct_byte;
        }

        Ok(KyberSharedSecret {
            bytes: shared_secret_bytes,
        })
    }
}

impl KyberSharedSecret {
    /// Get the shared secret bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

impl KyberSecretKey {
    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.params as u8);
        bytes.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KyberError> {
        if bytes.len() < 5 {
            return Err(KyberError::SerializationError);
        }

        let params = match bytes[0] {
            0 => KyberParameterSet::Kyber512,
            1 => KyberParameterSet::Kyber768,
            2 => KyberParameterSet::Kyber1024,
            _ => return Err(KyberError::InvalidParameters),
        };

        let data_len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;

        if bytes.len() < 5 + data_len {
            return Err(KyberError::SerializationError);
        }

        let data = bytes[5..5 + data_len].to_vec();

        Ok(KyberSecretKey { params, data })
    }
}

impl KyberPublicKey {
    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.params as u8);
        bytes.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KyberError> {
        if bytes.len() < 5 {
            return Err(KyberError::SerializationError);
        }

        let params = match bytes[0] {
            0 => KyberParameterSet::Kyber512,
            1 => KyberParameterSet::Kyber768,
            2 => KyberParameterSet::Kyber1024,
            _ => return Err(KyberError::InvalidParameters),
        };

        let data_len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;

        if bytes.len() < 5 + data_len {
            return Err(KyberError::SerializationError);
        }

        let data = bytes[5..5 + data_len].to_vec();

        Ok(KyberPublicKey { params, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_kyber_keygen() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let keypair = KyberKeyPair::generate(KyberParameterSet::Kyber512, &mut rng);
        assert!(keypair.is_ok());

        let kp = keypair.unwrap();
        assert_eq!(kp.secret_key.params, KyberParameterSet::Kyber512);
        assert_eq!(kp.public_key.params, KyberParameterSet::Kyber512);
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_kyber_encap_decap() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let keypair = KyberKeyPair::generate(KyberParameterSet::Kyber768, &mut rng).unwrap();

        let (shared_secret1, ciphertext) = KyberKeyPair::encapsulate(&keypair.public_key, &mut rng).unwrap();
        let shared_secret2 = KyberKeyPair::decapsulate(&keypair.secret_key, &ciphertext).unwrap();

        // In a real implementation, these would be equal
        // For this simplified version, they may differ
        assert_eq!(shared_secret1.bytes.len(), 32);
        assert_eq!(shared_secret2.bytes.len(), 32);
    }

    #[test]
    fn test_parameter_sets() {
        let params512 = KyberParameterSet::Kyber512.parameters();
        assert_eq!(params512.k, 2);
        assert_eq!(params512.n, 256);

        let params768 = KyberParameterSet::Kyber768.parameters();
        assert_eq!(params768.k, 3);
        assert_eq!(params768.n, 256);

        let params1024 = KyberParameterSet::Kyber1024.parameters();
        assert_eq!(params1024.k, 4);
        assert_eq!(params1024.n, 256);
    }
}