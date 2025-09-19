//! Schnorr Signatures Implementation
//!
//! This module implements Schnorr signatures over Ed25519, providing:
//! - Standard Schnorr signatures (EdDSA-compatible)
//! - Multi-signatures (MuSig protocol)
//! - Threshold signatures
//! - Batch verification
//! - Deterministic and non-deterministic variants

use crate::{EdwardsPoint, Scalar, FieldElement};
use crate::traits::{Compress, Decompress, Identity};

#[cfg(feature = "sha2")]
use sha2::{Digest, Sha512};

#[cfg(feature = "rand_core")]
use rand_core::{RngCore, CryptoRng};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::{String, ToString}};

/// Error types for Schnorr operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchnorrError {
    /// Invalid secret key
    InvalidSecretKey,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid signature
    InvalidSignature,
    /// Signature verification failed
    VerificationFailed,
    /// Invalid nonce
    InvalidNonce,
    /// Invalid commitment
    InvalidCommitment,
    /// Multi-signature error
    MultiSigError(String),
    /// Serialization error
    SerializationError,
    /// Hash function error
    HashError,
}

/// Schnorr secret key
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SchnorrSecretKey {
    scalar: Scalar,
}

impl SchnorrSecretKey {
    /// Generate a new random secret key
    #[cfg(feature = "rand_core")]
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let scalar = Scalar::random(rng);
        Self { scalar }
    }

    /// Create from raw bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SchnorrError> {
        let scalar = Scalar::from_bytes_mod_order(*bytes);
        Ok(Self { scalar })
    }

    /// Convert to raw bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> SchnorrPublicKey {
        let point = EdwardsPoint::mul_base(&self.scalar);
        SchnorrPublicKey { point }
    }

    /// Sign a message using deterministic nonce (RFC 6979 style)
    #[cfg(feature = "sha2")]
    pub fn sign(&self, message: &[u8]) -> Result<SchnorrSignature, SchnorrError> {
        // Generate deterministic nonce
        let nonce = self.deterministic_nonce(message)?;
        self.sign_with_nonce(message, &nonce)
    }

    /// Sign with explicit nonce (for advanced use cases)
    #[cfg(feature = "sha2")]
    pub fn sign_with_nonce(&self, message: &[u8], nonce: &Scalar) -> Result<SchnorrSignature, SchnorrError> {
        // R = k * G
        let R = EdwardsPoint::mul_base(nonce);

        // Challenge: c = H(R || P || m)
        let challenge = self.challenge_hash(&R, &self.public_key().point, message)?;

        // Response: s = k + c * x
        let response = nonce + &challenge * &self.scalar;

        Ok(SchnorrSignature {
            R: R.compress(),
            s: response,
        })
    }

    /// Generate deterministic nonce using hash of secret key and message
    #[cfg(feature = "sha2")]
    fn deterministic_nonce(&self, message: &[u8]) -> Result<Scalar, SchnorrError> {
        let mut hasher = Sha512::new();
        hasher.update(b"SchnorrNonce");
        hasher.update(&self.scalar.to_bytes());
        hasher.update(message);
        let hash = hasher.finalize();

        Ok(Scalar::from_bytes_mod_order_mod_order_wide(&hash.into()))
    }

    /// Compute challenge hash for Schnorr signature
    #[cfg(feature = "sha2")]
    fn challenge_hash(&self, R: &EdwardsPoint, P: &EdwardsPoint, message: &[u8]) -> Result<Scalar, SchnorrError> {
        let mut hasher = Sha512::new();
        hasher.update(b"SchnorrChallenge");
        hasher.update(&R.compress().to_bytes());
        hasher.update(&P.compress().to_bytes());
        hasher.update(message);
        let hash = hasher.finalize();

        Ok(Scalar::from_bytes_mod_order_mod_order_wide(&hash.into()))
    }
}

/// Schnorr public key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SchnorrPublicKey {
    point: EdwardsPoint,
}

impl SchnorrPublicKey {
    /// Create from raw bytes (32 bytes compressed)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SchnorrError> {
        let compressed = crate::edwards::CompressedEdwardsY(*bytes);
        let point = compressed.decompress()
            .ok_or(SchnorrError::InvalidPublicKey)?;
        Ok(Self { point })
    }

    /// Convert to raw bytes (32 bytes compressed)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Verify a Schnorr signature
    #[cfg(feature = "sha2")]
    pub fn verify(&self, message: &[u8], signature: &SchnorrSignature) -> Result<(), SchnorrError> {
        // Decompress R point
        let R = signature.R.decompress()
            .ok_or(SchnorrError::InvalidSignature)?;

        // Recompute challenge: c = H(R || P || m)
        let challenge = self.challenge_hash(&R, &self.point, message)?;

        // Verify: s * G == R + c * P
        let lhs = EdwardsPoint::mul_base(&signature.s);
        let rhs = &R + &(&challenge * &self.point);

        if lhs == rhs {
            Ok(())
        } else {
            Err(SchnorrError::VerificationFailed)
        }
    }

    /// Compute challenge hash (same as secret key version)
    #[cfg(feature = "sha2")]
    fn challenge_hash(&self, R: &EdwardsPoint, P: &EdwardsPoint, message: &[u8]) -> Result<Scalar, SchnorrError> {
        let mut hasher = Sha512::new();
        hasher.update(b"SchnorrChallenge");
        hasher.update(&R.compress().to_bytes());
        hasher.update(&P.compress().to_bytes());
        hasher.update(message);
        let hash = hasher.finalize();

        Ok(Scalar::from_bytes_mod_order_mod_order_wide(&hash.into()))
    }

    /// Get the underlying Edwards point
    pub fn as_point(&self) -> &EdwardsPoint {
        &self.point
    }
}

/// Schnorr signature
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SchnorrSignature {
    /// R component (commitment)
    R: crate::edwards::CompressedEdwardsY,
    /// s component (response)
    s: Scalar,
}

impl SchnorrSignature {
    /// Create from raw bytes (64 bytes: R || s)
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, SchnorrError> {
        let mut R_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        R_bytes.copy_from_slice(&bytes[0..32]);
        s_bytes.copy_from_slice(&bytes[32..64]);

        let R = crate::edwards::CompressedEdwardsY(R_bytes);
        let s = Scalar::from_bytes_mod_order(s_bytes);

        Ok(Self { R, s })
    }

    /// Convert to raw bytes (64 bytes: R || s)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.R.to_bytes());
        bytes[32..64].copy_from_slice(&self.s.to_bytes());
        bytes
    }

    /// Get R component
    pub fn R(&self) -> &crate::edwards::CompressedEdwardsY {
        &self.R
    }

    /// Get s component
    pub fn s(&self) -> &Scalar {
        &self.s
    }
}

/// MuSig (Multi-Signature) implementation
pub struct MuSig {
    /// Participating public keys
    public_keys: Vec<SchnorrPublicKey>,
    /// Aggregate public key
    aggregate_key: SchnorrPublicKey,
    /// Key aggregation coefficients
    coefficients: Vec<Scalar>,
}

impl MuSig {
    /// Create a new MuSig setup
    #[cfg(feature = "sha2")]
    pub fn new(public_keys: Vec<SchnorrPublicKey>) -> Result<Self, SchnorrError> {
        if public_keys.is_empty() {
            return Err(SchnorrError::MultiSigError("Empty public key list".to_string()));
        }

        // Compute aggregation coefficients
        let coefficients = Self::compute_coefficients(&public_keys)?;

        // Compute aggregate public key
        let mut aggregate = EdwardsPoint::identity();
        for (pk, coeff) in public_keys.iter().zip(coefficients.iter()) {
            aggregate = &aggregate + &(coeff * pk.as_point());
        }

        let aggregate_key = SchnorrPublicKey { point: aggregate };

        Ok(Self {
            public_keys,
            aggregate_key,
            coefficients,
        })
    }

    /// Get the aggregate public key
    pub fn aggregate_key(&self) -> &SchnorrPublicKey {
        &self.aggregate_key
    }

    /// Round 1: Generate nonce commitment
    #[cfg(feature = "rand_core")]
    pub fn round1_commit<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (MuSigCommitment, Scalar) {
        let nonce = Scalar::random(rng);
        let commitment = EdwardsPoint::mul_base(&nonce);
        (MuSigCommitment { R: commitment.compress() }, nonce)
    }

    /// Round 2: Generate partial signature
    #[cfg(feature = "sha2")]
    pub fn round2_sign(
        &self,
        secret_key: &SchnorrSecretKey,
        signer_index: usize,
        nonce: &Scalar,
        commitments: &[MuSigCommitment],
        message: &[u8],
    ) -> Result<MuSigPartialSignature, SchnorrError> {
        if signer_index >= self.public_keys.len() {
            return Err(SchnorrError::MultiSigError("Invalid signer index".to_string()));
        }

        // Verify that secret key matches public key
        let expected_pk = secret_key.public_key();
        if expected_pk != self.public_keys[signer_index] {
            return Err(SchnorrError::InvalidSecretKey);
        }

        // Aggregate R values
        let mut R_total = EdwardsPoint::identity();
        for commitment in commitments {
            let R_point = commitment.R.decompress()
                .ok_or(SchnorrError::InvalidCommitment)?;
            R_total = &R_total + &R_point;
        }

        // Compute challenge
        let challenge = self.musig_challenge(&R_total, message)?;

        // Compute partial signature: s_i = r_i + c * a_i * x_i
        let coeff = &self.coefficients[signer_index];
        let partial_sig = nonce + &challenge * coeff * &secret_key.scalar;

        Ok(MuSigPartialSignature {
            signer_id: signer_index as u32,
            s: partial_sig,
        })
    }

    /// Aggregate partial signatures
    pub fn aggregate_signatures(
        &self,
        partial_signatures: &[MuSigPartialSignature],
        commitments: &[MuSigCommitment],
    ) -> Result<SchnorrSignature, SchnorrError> {
        if partial_signatures.len() != commitments.len() {
            return Err(SchnorrError::MultiSigError("Mismatched signature and commitment counts".to_string()));
        }

        // Aggregate R values
        let mut R_total = EdwardsPoint::identity();
        for commitment in commitments {
            let R_point = commitment.R.decompress()
                .ok_or(SchnorrError::InvalidCommitment)?;
            R_total = &R_total + &R_point;
        }

        // Aggregate s values
        let mut s_total = Scalar::ZERO;
        for partial_sig in partial_signatures {
            s_total = &s_total + &partial_sig.s;
        }

        Ok(SchnorrSignature {
            R: R_total.compress(),
            s: s_total,
        })
    }

    /// Verify aggregate signature
    #[cfg(feature = "sha2")]
    pub fn verify(&self, message: &[u8], signature: &SchnorrSignature) -> Result<(), SchnorrError> {
        self.aggregate_key.verify(message, signature)
    }

    /// Compute key aggregation coefficients
    #[cfg(feature = "sha2")]
    fn compute_coefficients(public_keys: &[SchnorrPublicKey]) -> Result<Vec<Scalar>, SchnorrError> {
        let mut coefficients = Vec::new();

        // Compute L = H(P1 || P2 || ... || Pn)
        let mut hasher = Sha512::new();
        hasher.update(b"MuSigKeyAgg");
        for pk in public_keys {
            hasher.update(&pk.to_bytes());
        }
        let L = hasher.finalize();

        // Compute coefficient for each key: a_i = H(L || Pi)
        for pk in public_keys {
            let mut hasher = Sha512::new();
            hasher.update(b"MuSigCoeff");
            hasher.update(&L);
            hasher.update(&pk.to_bytes());
            let coeff_hash = hasher.finalize();

            let coefficient = Scalar::from_bytes_mod_order_mod_order_wide(&coeff_hash.into());
            coefficients.push(coefficient);
        }

        Ok(coefficients)
    }

    /// Compute MuSig challenge
    #[cfg(feature = "sha2")]
    fn musig_challenge(&self, R: &EdwardsPoint, message: &[u8]) -> Result<Scalar, SchnorrError> {
        let mut hasher = Sha512::new();
        hasher.update(b"MuSigChallenge");
        hasher.update(&R.compress().to_bytes());
        hasher.update(&self.aggregate_key.to_bytes());
        hasher.update(message);
        let hash = hasher.finalize();

        Ok(Scalar::from_bytes_mod_order_mod_order_wide(&hash.into()))
    }
}

/// MuSig commitment (Round 1)
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MuSigCommitment {
    /// R commitment point
    R: crate::edwards::CompressedEdwardsY,
}

impl MuSigCommitment {
    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.R.to_bytes()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            R: crate::edwards::CompressedEdwardsY(*bytes),
        }
    }
}

/// MuSig partial signature (Round 2)
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MuSigPartialSignature {
    /// Signer identifier
    signer_id: u32,
    /// Partial signature value
    s: Scalar,
}

impl MuSigPartialSignature {
    /// Get signer ID
    pub fn signer_id(&self) -> u32 {
        self.signer_id
    }

    /// Get signature value
    pub fn signature(&self) -> &Scalar {
        &self.s
    }

    /// Convert to bytes (4 bytes ID + 32 bytes signature)
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[0..4].copy_from_slice(&self.signer_id.to_le_bytes());
        bytes[4..36].copy_from_slice(&self.s.to_bytes());
        bytes
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 36]) -> Self {
        let mut id_bytes = [0u8; 4];
        let mut sig_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&bytes[0..4]);
        sig_bytes.copy_from_slice(&bytes[4..36]);

        Self {
            signer_id: u32::from_le_bytes(id_bytes),
            s: Scalar::from_bytes_mod_order(sig_bytes),
        }
    }
}

/// Batch verification for multiple Schnorr signatures
#[cfg(feature = "sha2")]
pub fn batch_verify(
    public_keys: &[SchnorrPublicKey],
    messages: &[&[u8]],
    signatures: &[SchnorrSignature],
) -> Result<(), SchnorrError> {
    if public_keys.len() != messages.len() || messages.len() != signatures.len() {
        return Err(SchnorrError::MultiSigError("Mismatched input lengths".to_string()));
    }

    if public_keys.is_empty() {
        return Err(SchnorrError::MultiSigError("Empty input".to_string()));
    }

    // TODO: Implement optimized batch verification
    // For now, verify each signature individually
    for ((pk, message), signature) in public_keys.iter().zip(messages.iter()).zip(signatures.iter()) {
        pk.verify(message, signature)?;
    }

    Ok(())
}

/// Utility functions for Schnorr operations
pub mod utils {
    use super::*;

    /// Generate a new keypair
    #[cfg(feature = "rand_core")]
    pub fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (SchnorrSecretKey, SchnorrPublicKey) {
        let secret_key = SchnorrSecretKey::generate(rng);
        let public_key = secret_key.public_key();
        (secret_key, public_key)
    }

    /// Sign a message
    #[cfg(feature = "sha2")]
    pub fn sign(secret_key: &SchnorrSecretKey, message: &[u8]) -> Result<SchnorrSignature, SchnorrError> {
        secret_key.sign(message)
    }

    /// Verify a signature
    #[cfg(feature = "sha2")]
    pub fn verify(
        public_key: &SchnorrPublicKey,
        message: &[u8],
        signature: &SchnorrSignature,
    ) -> bool {
        public_key.verify(message, signature).is_ok()
    }

    /// Create a MuSig setup
    #[cfg(feature = "sha2")]
    pub fn create_musig(public_keys: Vec<SchnorrPublicKey>) -> Result<MuSig, SchnorrError> {
        MuSig::new(public_keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "rand_core", feature = "sha2"))]
    fn test_schnorr_signature() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let secret_key = SchnorrSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();

        let message = b"Hello, Schnorr!";
        let signature = secret_key.sign(message).unwrap();

        // Verify signature
        public_key.verify(message, &signature).unwrap();

        // Test serialization
        let sk_bytes = secret_key.to_bytes();
        let pk_bytes = public_key.to_bytes();
        let sig_bytes = signature.to_bytes();

        let recovered_sk = SchnorrSecretKey::from_bytes(&sk_bytes).unwrap();
        let recovered_pk = SchnorrPublicKey::from_bytes(&pk_bytes).unwrap();
        let recovered_sig = SchnorrSignature::from_bytes(&sig_bytes).unwrap();

        assert_eq!(public_key, recovered_pk);
        assert_eq!(signature, recovered_sig);
        recovered_pk.verify(message, &recovered_sig).unwrap();
    }

    #[test]
    #[cfg(all(feature = "rand_core", feature = "sha2"))]
    fn test_musig() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        // Generate keypairs for 3 signers
        let keypairs: Vec<_> = (0..3)
            .map(|_| {
                let sk = SchnorrSecretKey::generate(&mut rng);
                let pk = sk.public_key();
                (sk, pk)
            })
            .collect();

        let public_keys: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
        let musig = MuSig::new(public_keys).unwrap();

        let message = b"MuSig test message";

        // Round 1: Generate commitments
        let mut commitments = Vec::new();
        let mut nonces = Vec::new();

        for _ in &keypairs {
            let (commitment, nonce) = musig.round1_commit(&mut rng);
            commitments.push(commitment);
            nonces.push(nonce);
        }

        // Round 2: Generate partial signatures
        let mut partial_signatures = Vec::new();
        for (i, (sk, _)) in keypairs.iter().enumerate() {
            let partial_sig = musig.round2_sign(sk, i, &nonces[i], &commitments, message).unwrap();
            partial_signatures.push(partial_sig);
        }

        // Aggregate signatures
        let aggregate_signature = musig.aggregate_signatures(&partial_signatures, &commitments).unwrap();

        // Verify aggregate signature
        musig.verify(message, &aggregate_signature).unwrap();
    }

    #[test]
    #[cfg(all(feature = "rand_core", feature = "sha2"))]
    fn test_batch_verification() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        // Generate multiple keypairs and signatures
        let count = 5;
        let mut public_keys = Vec::new();
        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        for i in 0..count {
            let secret_key = SchnorrSecretKey::generate(&mut rng);
            let public_key = secret_key.public_key();
            let message = format!("Message {}", i);
            let signature = secret_key.sign(message.as_bytes()).unwrap();

            public_keys.push(public_key);
            messages.push(message);
            signatures.push(signature);
        }

        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_bytes()).collect();

        // Batch verify
        batch_verify(&public_keys, &message_refs, &signatures).unwrap();
    }
}