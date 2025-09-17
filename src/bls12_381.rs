//! BLS12-381 elliptic curve operations and BLS signatures
//!
//! This module provides BLS (Boneh-Lynn-Shacham) signature support using the BLS12-381 curve,
//! commonly used in blockchain consensus mechanisms and multi-signature schemes.

#[cfg(feature = "bls12_381")]
pub use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar as BlsScalar};

#[cfg(feature = "bls12_381")]
use bls12_381::{pairing, Gt, hash_to_curve::{HashToCurve, ExpandMsgXmd}};

#[cfg(feature = "bls12_381")]
extern crate sha2;

#[cfg(feature = "rand_core")]
use rand_core::{RngCore, CryptoRng};

#[cfg(feature = "bls12_381")]
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// BLS private key (scalar in Fr)
#[cfg(feature = "bls12_381")]
#[derive(Clone, Debug)]
pub struct PrivateKey {
    /// The private scalar
    pub(crate) scalar: BlsScalar,
}

/// BLS public key (point in G1)
#[cfg(feature = "bls12_381")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// The public key point in G1
    pub(crate) point: G1Projective,
}

/// BLS signature (point in G2)
#[cfg(feature = "bls12_381")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The signature point in G2
    pub(crate) point: G2Projective,
}

/// Aggregate signature combining multiple signatures
#[cfg(feature = "bls12_381")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateSignature {
    /// The aggregated signature point in G2
    pub(crate) point: G2Projective,
}

/// BLS operation errors
#[cfg(feature = "bls12_381")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlsError {
    /// Invalid private key
    InvalidPrivateKey,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid signature
    InvalidSignature,
    /// Invalid message
    InvalidMessage,
    /// Verification failed
    VerificationFailed,
    /// Aggregation failed
    AggregationFailed,
    /// Invalid serialization
    InvalidSerialization,
}

#[cfg(feature = "bls12_381")]
impl fmt::Display for BlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlsError::InvalidPrivateKey => write!(f, "Invalid private key"),
            BlsError::InvalidPublicKey => write!(f, "Invalid public key"),
            BlsError::InvalidSignature => write!(f, "Invalid signature"),
            BlsError::InvalidMessage => write!(f, "Invalid message"),
            BlsError::VerificationFailed => write!(f, "Signature verification failed"),
            BlsError::AggregationFailed => write!(f, "Signature aggregation failed"),
            BlsError::InvalidSerialization => write!(f, "Invalid serialization"),
        }
    }
}

/// Domain separation tag for message hashing
#[cfg(feature = "bls12_381")]
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[cfg(feature = "bls12_381")]
impl PrivateKey {
    /// Generate a new random private key
    #[cfg(feature = "rand_core")]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> PrivateKey {
        // Generate random bytes and reduce modulo the field order
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let scalar = BlsScalar::from_bytes_wide(&bytes);
        PrivateKey { scalar }
    }

    /// Create a private key from 32 bytes (little-endian)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<PrivateKey, BlsError> {
        let scalar = BlsScalar::from_bytes(bytes).unwrap_or(BlsScalar::zero());
        if scalar.is_zero().into() {
            return Err(BlsError::InvalidPrivateKey);
        }
        Ok(PrivateKey { scalar })
    }

    /// Convert to 32 bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> PublicKey {
        let point = G1Projective::generator() * self.scalar;
        PublicKey { point }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<Signature, BlsError> {
        let hash_point = G2Projective::hash_to_curve(message, DST);
        let signature_point = hash_point * self.scalar;
        Ok(Signature { point: signature_point })
    }

    /// Sign a message that has already been hashed to G2
    pub fn sign_hashed(&self, hash_point: &G2Projective) -> Signature {
        let signature_point = hash_point * self.scalar;
        Signature { point: signature_point }
    }
}

#[cfg(feature = "bls12_381")]
impl PublicKey {
    /// Create a public key from compressed bytes (48 bytes)
    pub fn from_compressed_bytes(bytes: &[u8; 48]) -> Result<PublicKey, BlsError> {
        let affine = G1Affine::from_compressed(bytes);
        if bool::from(affine.is_some()) {
            let point = G1Projective::from(affine.unwrap());
            Ok(PublicKey { point })
        } else {
            Err(BlsError::InvalidPublicKey)
        }
    }

    /// Create a public key from uncompressed bytes (96 bytes)
    pub fn from_uncompressed_bytes(bytes: &[u8; 96]) -> Result<PublicKey, BlsError> {
        let affine = G1Affine::from_uncompressed(bytes);
        if bool::from(affine.is_some()) {
            let point = G1Projective::from(affine.unwrap());
            Ok(PublicKey { point })
        } else {
            Err(BlsError::InvalidPublicKey)
        }
    }

    /// Serialize to compressed bytes (48 bytes)
    pub fn to_compressed_bytes(&self) -> [u8; 48] {
        G1Affine::from(self.point).to_compressed()
    }

    /// Serialize to uncompressed bytes (96 bytes)
    pub fn to_uncompressed_bytes(&self) -> [u8; 96] {
        G1Affine::from(self.point).to_uncompressed()
    }

    /// Verify a signature on a message
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), BlsError> {
        let hash_point = G2Projective::hash_to_curve(message, DST);
        self.verify_hashed(&hash_point, signature)
    }

    /// Verify a signature on a pre-hashed message
    pub fn verify_hashed(&self, hash_point: &G2Projective, signature: &Signature) -> Result<(), BlsError> {
        // e(P, H(m)) = e(G, S)
        // where P is public key, H(m) is hash of message, G is generator, S is signature

        let lhs = pairing(&G1Affine::from(self.point), &G2Affine::from(*hash_point));
        let rhs = pairing(&G1Affine::generator(), &G2Affine::from(signature.point));

        if lhs == rhs {
            Ok(())
        } else {
            Err(BlsError::VerificationFailed)
        }
    }

    /// Aggregate multiple public keys
    #[cfg(feature = "alloc")]
    pub fn aggregate(public_keys: &[PublicKey]) -> Result<PublicKey, BlsError> {
        if public_keys.is_empty() {
            return Err(BlsError::AggregationFailed);
        }

        let mut aggregated = public_keys[0].point;
        for pk in &public_keys[1..] {
            aggregated += pk.point;
        }

        Ok(PublicKey { point: aggregated })
    }
}

#[cfg(feature = "bls12_381")]
impl Signature {
    /// Create a signature from compressed bytes (96 bytes)
    pub fn from_compressed_bytes(bytes: &[u8; 96]) -> Result<Signature, BlsError> {
        let affine = G2Affine::from_compressed(bytes);
        if bool::from(affine.is_some()) {
            let point = G2Projective::from(affine.unwrap());
            Ok(Signature { point })
        } else {
            Err(BlsError::InvalidSignature)
        }
    }

    /// Create a signature from uncompressed bytes (192 bytes)
    pub fn from_uncompressed_bytes(bytes: &[u8; 192]) -> Result<Signature, BlsError> {
        let affine = G2Affine::from_uncompressed(bytes);
        if bool::from(affine.is_some()) {
            let point = G2Projective::from(affine.unwrap());
            Ok(Signature { point })
        } else {
            Err(BlsError::InvalidSignature)
        }
    }

    /// Serialize to compressed bytes (96 bytes)
    pub fn to_compressed_bytes(&self) -> [u8; 96] {
        G2Affine::from(self.point).to_compressed()
    }

    /// Serialize to uncompressed bytes (192 bytes)
    pub fn to_uncompressed_bytes(&self) -> [u8; 192] {
        G2Affine::from(self.point).to_uncompressed()
    }

    /// Aggregate multiple signatures
    #[cfg(feature = "alloc")]
    pub fn aggregate(signatures: &[Signature]) -> Result<AggregateSignature, BlsError> {
        if signatures.is_empty() {
            return Err(BlsError::AggregationFailed);
        }

        let mut aggregated = signatures[0].point;
        for sig in &signatures[1..] {
            aggregated += sig.point;
        }

        Ok(AggregateSignature { point: aggregated })
    }
}

#[cfg(feature = "bls12_381")]
impl AggregateSignature {
    /// Verify an aggregate signature against multiple public keys and messages
    #[cfg(feature = "alloc")]
    pub fn verify(&self, public_keys: &[PublicKey], messages: &[&[u8]]) -> Result<(), BlsError> {
        if public_keys.len() != messages.len() || public_keys.is_empty() {
            return Err(BlsError::VerificationFailed);
        }

        // Aggregate verification: e(P1, H(m1)) * e(P2, H(m2)) * ... = e(G, S_agg)
        let mut lhs = Gt::identity();
        for (pk, msg) in public_keys.iter().zip(messages.iter()) {
            let hash_point = G2Projective::hash_to_curve(msg, DST);
            lhs += pairing(&G1Affine::from(pk.point), &G2Affine::from(hash_point));
        }

        let rhs = pairing(&G1Affine::generator(), &G2Affine::from(self.point));

        if lhs == rhs {
            Ok(())
        } else {
            Err(BlsError::VerificationFailed)
        }
    }

    /// Verify an aggregate signature against the same message
    #[cfg(feature = "alloc")]
    pub fn verify_same_message(&self, public_keys: &[PublicKey], message: &[u8]) -> Result<(), BlsError> {
        if public_keys.is_empty() {
            return Err(BlsError::VerificationFailed);
        }

        // Aggregate the public keys first
        let aggregated_pk = PublicKey::aggregate(public_keys)?;

        // Hash the message once
        let hash_point = G2Projective::hash_to_curve(message, DST);

        // Verify: e(P_agg, H(m)) = e(G, S_agg)
        let lhs = pairing(&G1Affine::from(aggregated_pk.point), &G2Affine::from(hash_point));
        let rhs = pairing(&G1Affine::generator(), &G2Affine::from(self.point));

        if lhs == rhs {
            Ok(())
        } else {
            Err(BlsError::VerificationFailed)
        }
    }

    /// Convert to regular signature
    pub fn to_signature(&self) -> Signature {
        Signature { point: self.point }
    }
}

/// Threshold signature schemes for BLS
#[cfg(feature = "bls12_381")]
pub mod threshold {
    use super::*;

    /// A threshold signature share
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SignatureShare {
        /// The signature share
        pub signature: Signature,
        /// The signer index
        pub index: u32,
    }

    /// Threshold signature verification key
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VerificationKey {
        /// The verification key point
        pub public_key: PublicKey,
        /// The threshold value
        pub threshold: u32,
    }

    impl SignatureShare {
        /// Create a new signature share
        pub fn new(signature: Signature, index: u32) -> Self {
            Self { signature, index }
        }
    }

    /// Combine threshold signature shares using Lagrange interpolation
    #[cfg(feature = "alloc")]
    pub fn combine_signature_shares(
        shares: &[SignatureShare],
        threshold: u32,
    ) -> Result<Signature, BlsError> {
        if shares.len() < threshold as usize {
            return Err(BlsError::AggregationFailed);
        }

        // Use the first `threshold` shares
        let shares = &shares[..threshold as usize];

        let mut combined = G2Projective::identity();

        for (i, share_i) in shares.iter().enumerate() {
            // Compute Lagrange coefficient
            let mut coeff = BlsScalar::one();
            for (j, share_j) in shares.iter().enumerate() {
                if i != j {
                    let num = BlsScalar::from(share_j.index as u64);
                    let denom = BlsScalar::from(share_j.index as u64) - BlsScalar::from(share_i.index as u64);
                    coeff *= num * denom.invert().unwrap();
                }
            }

            combined += share_i.signature.point * coeff;
        }

        Ok(Signature { point: combined })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "bls12_381")]
    fn test_basic_signature() {
        let mut rng = rand::thread_rng();
        let private_key = PrivateKey::random(&mut rng);
        let public_key = private_key.public_key();

        let message = b"Hello, BLS!";
        let signature = private_key.sign(message).unwrap();

        public_key.verify(message, &signature).unwrap();
    }

    #[test]
    #[cfg(all(feature = "bls12_381", feature = "alloc"))]
    fn test_signature_aggregation() {
        let mut rng = rand::thread_rng();

        let private_key1 = PrivateKey::random(&mut rng);
        let private_key2 = PrivateKey::random(&mut rng);
        let public_key1 = private_key1.public_key();
        let public_key2 = private_key2.public_key();

        let message = b"Aggregate this!";
        let signature1 = private_key1.sign(message).unwrap();
        let signature2 = private_key2.sign(message).unwrap();

        let aggregate_sig = Signature::aggregate(&[signature1, signature2]).unwrap();
        let public_keys = [public_key1, public_key2];

        aggregate_sig.verify_same_message(&public_keys, message).unwrap();
    }

    #[test]
    #[cfg(feature = "bls12_381")]
    fn test_serialization() {
        let mut rng = rand::thread_rng();
        let private_key = PrivateKey::random(&mut rng);
        let public_key = private_key.public_key();

        // Test private key serialization
        let priv_bytes = private_key.to_bytes();
        let recovered_priv = PrivateKey::from_bytes(&priv_bytes).unwrap();
        assert_eq!(private_key.scalar, recovered_priv.scalar);

        // Test public key serialization
        let pub_bytes = public_key.to_compressed_bytes();
        let recovered_pub = PublicKey::from_compressed_bytes(&pub_bytes).unwrap();
        assert_eq!(public_key, recovered_pub);
    }
}