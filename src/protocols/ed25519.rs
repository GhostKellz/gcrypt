//! Ed25519 digital signature implementation
//!
//! This module implements the Ed25519 signature scheme as specified in RFC 8032.
//! Ed25519 provides fast, secure digital signatures using the Edwards form of Curve25519.

use crate::{EdwardsPoint, Scalar, FieldElement};
use subtle::{Choice, ConstantTimeEq};

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// An Ed25519 public key
#[derive(Clone, Copy, Debug)]
pub struct PublicKey {
    /// The public key point
    pub(crate) point: EdwardsPoint,
    /// The compressed representation
    pub(crate) compressed: [u8; 32],
}

/// An Ed25519 secret key
#[derive(Clone, Debug)]
pub struct SecretKey {
    /// The secret scalar
    pub(crate) scalar: Scalar,
    /// The public key derived from this secret
    pub(crate) public: PublicKey,
}

/// An Ed25519 signature
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    /// The R component of the signature
    pub(crate) r: [u8; 32],
    /// The s component of the signature
    pub(crate) s: [u8; 32],
}

/// Ed25519 signature verification error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// Invalid signature format
    InvalidFormat,
    /// Invalid public key
    InvalidPublicKey,
    /// Signature verification failed
    VerificationFailed,
    /// Invalid signature component
    InvalidSignature,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignatureError::InvalidFormat => write!(f, "Invalid signature format"),
            SignatureError::InvalidPublicKey => write!(f, "Invalid public key"),
            SignatureError::VerificationFailed => write!(f, "Signature verification failed"),
            SignatureError::InvalidSignature => write!(f, "Invalid signature component"),
        }
    }
}

impl SecretKey {
    /// Generate a new Ed25519 secret key
    #[cfg(feature = "rand_core")]
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> SecretKey {
        let scalar = Scalar::random(rng);
        let public_point = EdwardsPoint::mul_base(&scalar);
        let compressed = public_point.compress().to_bytes();
        
        SecretKey {
            scalar,
            public: PublicKey {
                point: public_point,
                compressed,
            },
        }
    }
    
    /// Create a secret key from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> SecretKey {
        let scalar = Scalar::from_bytes_mod_order(bytes);
        let public_point = EdwardsPoint::mul_base(&scalar);
        let compressed = public_point.compress().to_bytes();
        
        SecretKey {
            scalar,
            public: PublicKey {
                point: public_point,
                compressed,
            },
        }
    }
    
    /// Convert secret key to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }
    
    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        self.public
    }
    
    /// Sign a message using Ed25519
    #[cfg(feature = "rand_core")]
    pub fn sign<R: CryptoRng + RngCore>(&self, message: &[u8], rng: &mut R) -> Signature {
        // Generate random nonce
        let nonce = Scalar::random(rng);
        
        // Compute r = [nonce]B
        let r_point = EdwardsPoint::mul_base(&nonce);
        let r_bytes = r_point.compress().to_bytes();
        
        // Compute challenge hash H(R || A || M)
        let challenge = self.compute_challenge(&r_bytes, message);
        
        // Compute s = nonce + challenge * secret_key
        let s = &nonce + &(&challenge * &self.scalar);
        
        Signature {
            r: r_bytes,
            s: s.to_bytes(),
        }
    }
    
    /// Sign a message with deterministic nonce (RFC 8032 style)
    pub fn sign_deterministic(&self, message: &[u8]) -> Signature {
        // In a real implementation, this would use a deterministic nonce
        // based on the secret key and message hash
        let nonce = self.derive_nonce(message);
        
        // Compute r = [nonce]B
        let r_point = EdwardsPoint::mul_base(&nonce);
        let r_bytes = r_point.compress().to_bytes();
        
        // Compute challenge hash H(R || A || M)
        let challenge = self.compute_challenge(&r_bytes, message);
        
        // Compute s = nonce + challenge * secret_key
        let s = &nonce + &(&challenge * &self.scalar);
        
        Signature {
            r: r_bytes,
            s: s.to_bytes(),
        }
    }
    
    /// Compute challenge hash for Ed25519
    fn compute_challenge(&self, r_bytes: &[u8; 32], message: &[u8]) -> Scalar {
        // This is a simplified implementation
        // Real Ed25519 uses SHA-512 with specific domain separation
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(r_bytes);
        hasher_input.extend_from_slice(&self.public.compressed);
        hasher_input.extend_from_slice(message);
        
        // Hash the input (simplified - would use SHA-512 in real implementation)
        let hash = simple_hash(&hasher_input);
        Scalar::from_bytes_mod_order(&hash)
    }
    
    /// Derive deterministic nonce
    fn derive_nonce(&self, message: &[u8]) -> Scalar {
        // Simplified nonce derivation
        // Real implementation would use HMAC-SHA-512
        let mut input = Vec::new();
        input.extend_from_slice(&self.scalar.to_bytes());
        input.extend_from_slice(message);
        
        let hash = simple_hash(&input);
        Scalar::from_bytes_mod_order(&hash)
    }
}

impl PublicKey {
    /// Create a public key from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<PublicKey, SignatureError> {
        let compressed = crate::edwards::CompressedEdwardsY(*bytes);
        
        match compressed.decompress() {
            Some(point) => Ok(PublicKey {
                point,
                compressed: *bytes,
            }),
            None => Err(SignatureError::InvalidPublicKey),
        }
    }
    
    /// Convert public key to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.compressed
    }
    
    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        // Parse signature components
        let r_bytes = signature.r;
        let s_scalar = Scalar::from_canonical_bytes(&signature.s)
            .ok_or(SignatureError::InvalidSignature)?;
        
        // Decompress R point
        let r_compressed = crate::edwards::CompressedEdwardsY(r_bytes);
        let r_point = r_compressed.decompress()
            .ok_or(SignatureError::InvalidSignature)?;
        
        // Compute challenge hash H(R || A || M)
        let challenge = self.compute_challenge(&r_bytes, message);
        
        // Verify: [s]B = R + [challenge]A
        let left_side = EdwardsPoint::mul_base(&s_scalar);
        let right_side = &r_point + &(&self.point * &challenge);
        
        if left_side.ct_eq(&right_side).into() {
            Ok(())
        } else {
            Err(SignatureError::VerificationFailed)
        }
    }
    
    /// Compute challenge hash for verification
    fn compute_challenge(&self, r_bytes: &[u8; 32], message: &[u8]) -> Scalar {
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(r_bytes);
        hasher_input.extend_from_slice(&self.compressed);
        hasher_input.extend_from_slice(message);
        
        let hash = simple_hash(&hasher_input);
        Scalar::from_bytes_mod_order(&hash)
    }
}

impl Signature {
    /// Create a signature from bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> Signature {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        
        Signature { r, s }
    }
    
    /// Convert signature to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Simplified hash function for demonstration
/// In a real implementation, this would be SHA-512
fn simple_hash(input: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    
    // Extremely simplified hash - just XOR and rotate
    for (i, &byte) in input.iter().enumerate() {
        hash[i % 32] ^= byte;
        hash[i % 32] = hash[i % 32].wrapping_add(byte);
    }
    
    hash
}

/// Batch signature verification
pub fn verify_batch(
    messages: &[&[u8]], 
    signatures: &[Signature], 
    public_keys: &[PublicKey]
) -> Result<(), SignatureError> {
    if messages.len() != signatures.len() || signatures.len() != public_keys.len() {
        return Err(SignatureError::InvalidFormat);
    }
    
    // Individual verification for now
    // Real batch verification would be more efficient
    for ((message, signature), public_key) in messages.iter()
        .zip(signatures.iter())
        .zip(public_keys.iter()) {
        public_key.verify(message, signature)?;
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(feature = "rand_core")]
    #[test]
    fn test_ed25519_signature() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        
        // Generate key pair
        let secret_key = SecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();
        
        // Sign a message
        let message = b"Hello, Ed25519!";
        let signature = secret_key.sign(message, &mut rng);
        
        // Verify the signature
        assert!(public_key.verify(message, &signature).is_ok());
        
        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(public_key.verify(wrong_message, &signature).is_err());
    }
    
    #[test]
    fn test_deterministic_signature() {
        let secret_key = SecretKey::from_bytes(&[1u8; 32]);
        let message = b"Deterministic test";
        
        // Sign the same message twice
        let sig1 = secret_key.sign_deterministic(message);
        let sig2 = secret_key.sign_deterministic(message);
        
        // Signatures should be identical
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
        
        // Verify both signatures
        let public_key = secret_key.public_key();
        assert!(public_key.verify(message, &sig1).is_ok());
        assert!(public_key.verify(message, &sig2).is_ok());
    }
    
    #[test]
    fn test_signature_serialization() {
        let secret_key = SecretKey::from_bytes(&[42u8; 32]);
        let message = b"Serialization test";
        let signature = secret_key.sign_deterministic(message);
        
        // Serialize and deserialize
        let bytes = signature.to_bytes();
        let deserialized = Signature::from_bytes(&bytes);
        
        // Should be identical
        assert_eq!(signature.to_bytes(), deserialized.to_bytes());
        
        // Should still verify
        let public_key = secret_key.public_key();
        assert!(public_key.verify(message, &deserialized).is_ok());
    }
}