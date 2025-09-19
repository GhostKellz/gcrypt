//! P-256 (secp256r1) elliptic curve cryptography
//!
//! This module provides NIST P-256 compatible cryptographic operations
//! using the secp256r1 elliptic curve. It includes support for:
//! - ECDSA signature generation and verification
//! - Key generation and management
//! - Hardware wallet compatibility
//! - Constant-time operations for security

#[cfg(feature = "secp256r1")]
use p256::{
    ecdsa::{SigningKey, VerifyingKey, Signature as P256Signature, signature::Signer, signature::Verifier},
    EncodedPoint, SecretKey as P256SecretKey, PublicKey as P256PublicKey,
    elliptic_curve::{
        generic_array::GenericArray,
        rand_core::{RngCore, CryptoRng},
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field, Group,
    },
    AffinePoint, ProjectivePoint, Scalar,
};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Error types for P-256 operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid secret key
    InvalidSecretKey,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid signature
    InvalidSignature,
    /// Invalid point encoding
    InvalidPointEncoding,
    /// P-256 library error
    P256(String),
}

/// A P-256 secret key
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub struct SecretKey {
    #[cfg(feature = "secp256r1")]
    inner: P256SecretKey,
    #[cfg(not(feature = "secp256r1"))]
    _phantom: (),
}

impl SecretKey {
    /// Generate a new random secret key
    #[cfg(all(feature = "secp256r1", feature = "rand_core"))]
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = P256SecretKey::random(rng);
        Self { inner: secret_key }
    }

    /// Create a secret key from raw bytes
    #[cfg(feature = "secp256r1")]
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let secret_key = P256SecretKey::from_slice(bytes)
            .map_err(|e| Error::P256(format!("{:?}", e)))?;
        Ok(Self { inner: secret_key })
    }

    /// Convert the secret key to raw bytes
    #[cfg(feature = "secp256r1")]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    /// Get the corresponding public key
    #[cfg(feature = "secp256r1")]
    pub fn public_key(&self) -> PublicKey {
        let public_key = self.inner.public_key();
        PublicKey { inner: public_key }
    }

    /// Sign a message hash using ECDSA
    #[cfg(feature = "secp256r1")]
    pub fn sign(&self, message_hash: &[u8; 32]) -> Result<Signature, Error> {
        let signing_key = SigningKey::from(&self.inner);
        let signature: P256Signature = signing_key.try_sign(message_hash)
            .map_err(|e| Error::P256(format!("{:?}", e)))?;
        Ok(Signature { inner: signature })
    }

    /// Get the scalar value (for advanced operations)
    #[cfg(feature = "secp256r1")]
    pub fn to_scalar(&self) -> Scalar {
        *self.inner.to_nonzero_scalar()
    }
}

/// A P-256 public key
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey {
    #[cfg(feature = "secp256r1")]
    inner: P256PublicKey,
    #[cfg(not(feature = "secp256r1"))]
    _phantom: (),
}

impl PublicKey {
    /// Create a public key from SEC1 encoded bytes
    #[cfg(feature = "secp256r1")]
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let encoded_point = EncodedPoint::from_bytes(bytes)
            .map_err(|e| Error::P256(format!("{:?}", e)))?;
        let public_key = P256PublicKey::from_encoded_point(&encoded_point)
            .map_err(|e| Error::P256(format!("{:?}", e)))?;
        Ok(Self { inner: public_key })
    }

    /// Create a public key from compressed bytes (33 bytes)
    #[cfg(feature = "secp256r1")]
    pub fn from_compressed_bytes(bytes: &[u8; 33]) -> Result<Self, Error> {
        Self::from_sec1_bytes(bytes)
    }

    /// Create a public key from uncompressed bytes (65 bytes)
    #[cfg(feature = "secp256r1")]
    pub fn from_uncompressed_bytes(bytes: &[u8; 65]) -> Result<Self, Error> {
        Self::from_sec1_bytes(bytes)
    }

    /// Convert the public key to SEC1 compressed bytes
    #[cfg(feature = "secp256r1")]
    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        let encoded = self.inner.to_encoded_point(true);
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(encoded.as_bytes());
        bytes
    }

    /// Convert the public key to SEC1 uncompressed bytes
    #[cfg(feature = "secp256r1")]
    pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
        let encoded = self.inner.to_encoded_point(false);
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(encoded.as_bytes());
        bytes
    }

    /// Verify an ECDSA signature
    #[cfg(feature = "secp256r1")]
    pub fn verify(&self, message_hash: &[u8; 32], signature: &Signature) -> Result<(), Error> {
        let verifying_key = VerifyingKey::from(&self.inner);
        verifying_key.verify(message_hash, &signature.inner)
            .map_err(|e| Error::P256(format!("{:?}", e)))
    }

    /// Get the affine point representation
    #[cfg(feature = "secp256r1")]
    pub fn to_affine_point(&self) -> AffinePoint {
        self.inner.to_projective().to_affine()
    }

    /// Create from affine point
    #[cfg(feature = "secp256r1")]
    pub fn from_affine_point(point: &AffinePoint) -> Result<Self, Error> {
        let public_key = P256PublicKey::from_affine(*point)
            .map_err(|e| Error::P256(format!("{:?}", e)))?;
        Ok(Self { inner: public_key })
    }
}

/// A P-256 ECDSA signature
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    #[cfg(feature = "secp256r1")]
    inner: P256Signature,
    #[cfg(not(feature = "secp256r1"))]
    _phantom: (),
}

impl Signature {
    /// Create a signature from DER bytes
    #[cfg(feature = "secp256r1")]
    pub fn from_der(bytes: &[u8]) -> Result<Self, Error> {
        let signature = P256Signature::from_der(bytes)
            .map_err(|e| Error::P256(format!("{:?}", e)))?;
        Ok(Self { inner: signature })
    }

    /// Create a signature from fixed-size bytes (64 bytes: r || s)
    #[cfg(feature = "secp256r1")]
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let signature = P256Signature::from_slice(bytes)
            .map_err(|e| Error::P256(format!("{:?}", e)))?;
        Ok(Self { inner: signature })
    }

    /// Convert the signature to DER format
    #[cfg(feature = "secp256r1")]
    pub fn to_der(&self) -> Vec<u8> {
        self.inner.to_der().as_bytes().to_vec()
    }

    /// Convert the signature to fixed-size bytes (64 bytes: r || s)
    #[cfg(feature = "secp256r1")]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes().into()
    }

    /// Split signature into r and s components
    #[cfg(feature = "secp256r1")]
    pub fn split(&self) -> ([u8; 32], [u8; 32]) {
        let bytes = self.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        (r, s)
    }

    /// Create signature from r and s components
    #[cfg(feature = "secp256r1")]
    pub fn from_scalars(r: &[u8; 32], s: &[u8; 32]) -> Result<Self, Error> {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(r);
        bytes[32..64].copy_from_slice(s);
        Self::from_bytes(&bytes)
    }
}

/// Key pair combining secret and public keys
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub struct KeyPair {
    /// Secret key
    pub secret_key: SecretKey,
    /// Public key
    pub public_key: PublicKey,
}

impl KeyPair {
    /// Generate a new random key pair
    #[cfg(all(feature = "secp256r1", feature = "rand_core"))]
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = SecretKey::generate(rng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Create a key pair from a secret key
    #[cfg(feature = "secp256r1")]
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Sign a message hash
    #[cfg(feature = "secp256r1")]
    pub fn sign(&self, message_hash: &[u8; 32]) -> Result<Signature, Error> {
        self.secret_key.sign(message_hash)
    }

    /// Verify a signature
    #[cfg(feature = "secp256r1")]
    pub fn verify(&self, message_hash: &[u8; 32], signature: &Signature) -> Result<(), Error> {
        self.public_key.verify(message_hash, signature)
    }
}

/// Utilities for NIST P-256 operations
#[cfg(feature = "secp256r1")]
pub mod utils {
    use super::*;
    use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
    use sha2::Sha256;

    /// Hash-to-curve operation (for advanced protocols)
    pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> ProjectivePoint {
        ProjectivePoint::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg], &[dst])
            .expect("Hash-to-curve should not fail")
    }

    /// Point compression check
    pub fn is_point_compressed(bytes: &[u8]) -> bool {
        bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03)
    }

    /// Point decompression
    pub fn decompress_point(compressed: &[u8; 33]) -> Result<[u8; 65], Error> {
        let point = PublicKey::from_compressed_bytes(compressed)?;
        Ok(point.to_uncompressed_bytes())
    }

    /// Point compression
    pub fn compress_point(uncompressed: &[u8; 65]) -> Result<[u8; 33], Error> {
        let point = PublicKey::from_uncompressed_bytes(uncompressed)?;
        Ok(point.to_compressed_bytes())
    }
}

#[cfg(all(test, feature = "secp256r1"))]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_key_generation() {
        let mut rng = thread_rng();
        let key_pair = KeyPair::generate(&mut rng);

        // Test serialization roundtrip
        let secret_bytes = key_pair.secret_key.to_bytes();
        let recovered_secret = SecretKey::from_bytes(&secret_bytes).unwrap();
        assert_eq!(key_pair.secret_key.to_bytes(), recovered_secret.to_bytes());

        let public_compressed = key_pair.public_key.to_compressed_bytes();
        let recovered_public = PublicKey::from_compressed_bytes(&public_compressed).unwrap();
        assert_eq!(key_pair.public_key, recovered_public);
    }

    #[test]
    fn test_sign_verify() {
        let mut rng = thread_rng();
        let key_pair = KeyPair::generate(&mut rng);

        let message = b"Hello, P-256!";
        let mut hasher = sha2::Sha256::new();
        hasher.update(message);
        let message_hash: [u8; 32] = hasher.finalize().into();

        let signature = key_pair.sign(&message_hash).unwrap();
        key_pair.verify(&message_hash, &signature).unwrap();
    }

    #[test]
    fn test_signature_serialization() {
        let mut rng = thread_rng();
        let key_pair = KeyPair::generate(&mut rng);

        let message_hash = [0x42u8; 32];
        let signature = key_pair.sign(&message_hash).unwrap();

        // Test DER roundtrip
        let der_bytes = signature.to_der();
        let recovered_sig = Signature::from_der(&der_bytes).unwrap();
        assert_eq!(signature, recovered_sig);

        // Test fixed-size bytes roundtrip
        let fixed_bytes = signature.to_bytes();
        let recovered_sig2 = Signature::from_bytes(&fixed_bytes).unwrap();
        assert_eq!(signature, recovered_sig2);
    }

    #[test]
    fn test_point_compression() {
        let mut rng = thread_rng();
        let key_pair = KeyPair::generate(&mut rng);

        let compressed = key_pair.public_key.to_compressed_bytes();
        let uncompressed = key_pair.public_key.to_uncompressed_bytes();

        // Test that both formats represent the same key
        let from_compressed = PublicKey::from_compressed_bytes(&compressed).unwrap();
        let from_uncompressed = PublicKey::from_uncompressed_bytes(&uncompressed).unwrap();

        assert_eq!(from_compressed, from_uncompressed);
        assert_eq!(from_compressed, key_pair.public_key);
    }

    #[test]
    fn test_utils() {
        let compressed = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];

        assert!(utils::is_point_compressed(&compressed));
        let uncompressed = utils::decompress_point(&compressed).unwrap();
        assert_eq!(uncompressed.len(), 65);

        let recompressed = utils::compress_point(&uncompressed).unwrap();
        assert_eq!(compressed, recompressed);
    }
}