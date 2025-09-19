//! BLS (Boneh-Lynn-Shacham) Signatures
//!
//! This module implements BLS signatures over the BLS12-381 pairing-friendly curve.
//! BLS signatures provide:
//! - Signature aggregation (multiple signatures -> single signature)
//! - Public key aggregation
//! - Batch verification
//! - Deterministic signatures
//! - Short signatures (96 bytes for G2, 48 bytes for G1)

#[cfg(feature = "bls12_381")]
use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar as BlsScalar,
    pairing, multi_miller_loop, MillerLoopResult,
};

#[cfg(feature = "sha2")]
use sha2::{Digest, Sha256};

#[cfg(feature = "rand_core")]
use rand_core::{RngCore, CryptoRng};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String};

/// Error types for BLS operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlsError {
    /// Invalid secret key
    InvalidSecretKey,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid signature
    InvalidSignature,
    /// Signature verification failed
    VerificationFailed,
    /// Invalid aggregation (empty input)
    InvalidAggregation,
    /// Serialization error
    SerializationError,
    /// Hash-to-curve error
    HashToCurveError,
    /// BLS library error
    BlsLibraryError(String),
}

/// BLS signature schemes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlsScheme {
    /// Basic scheme: public keys in G1, signatures in G2
    Basic,
    /// Message augmentation scheme: prevents rogue key attacks
    MessageAugmentation,
    /// Proof of possession scheme: requires PoP for aggregation
    ProofOfPossession,
}

/// BLS secret key
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlsSecretKey {
    #[cfg(feature = "bls12_381")]
    scalar: BlsScalar,
    #[cfg(not(feature = "bls12_381"))]
    _phantom: (),
}

impl BlsSecretKey {
    /// Generate a new random secret key
    #[cfg(all(feature = "bls12_381", feature = "rand_core"))]
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let scalar = BlsScalar::from_bytes_wide(&[bytes, [0u8; 32]].concat().try_into().unwrap());
        Self { scalar }
    }

    /// Create from raw bytes (32 bytes)
    #[cfg(feature = "bls12_381")]
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BlsError> {
        let scalar = BlsScalar::from_bytes(bytes)
            .map(|s| s.ok_or(BlsError::InvalidSecretKey))??;
        Ok(Self { scalar })
    }

    /// Convert to raw bytes
    #[cfg(feature = "bls12_381")]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Get the corresponding public key
    #[cfg(feature = "bls12_381")]
    pub fn public_key(&self) -> BlsPublicKey {
        let point = G1Projective::generator() * self.scalar;
        BlsPublicKey { point: point.into() }
    }

    /// Sign a message
    #[cfg(all(feature = "bls12_381", feature = "sha2"))]
    pub fn sign(&self, message: &[u8], scheme: BlsScheme) -> Result<BlsSignature, BlsError> {
        let hash_point = match scheme {
            BlsScheme::Basic => self.hash_to_g2(message)?,
            BlsScheme::MessageAugmentation => {
                let augmented = [self.public_key().to_bytes().as_slice(), message].concat();
                self.hash_to_g2(&augmented)?
            },
            BlsScheme::ProofOfPossession => self.hash_to_g2(message)?,
        };

        let signature_point = hash_point * self.scalar;
        Ok(BlsSignature { point: signature_point.into() })
    }

    /// Create a proof of possession (PoP)
    #[cfg(all(feature = "bls12_381", feature = "sha2"))]
    pub fn proof_of_possession(&self) -> Result<BlsSignature, BlsError> {
        let pk_bytes = self.public_key().to_bytes();
        self.sign(&pk_bytes, BlsScheme::Basic)
    }

    /// Hash message to G2 point
    #[cfg(all(feature = "bls12_381", feature = "sha2"))]
    fn hash_to_g2(&self, message: &[u8]) -> Result<G2Projective, BlsError> {
        // Simplified hash-to-curve (real implementation would use proper hash-to-curve)
        let mut hasher = Sha256::new();
        hasher.update(b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_");
        hasher.update(message);
        let hash = hasher.finalize();

        // This is a simplified version - production code should use proper hash-to-curve
        let scalar = BlsScalar::from_bytes_wide(&[hash.as_slice().try_into().unwrap(), [0u8; 32]].concat().try_into().unwrap());
        Ok(G2Projective::generator() * scalar)
    }
}

/// BLS public key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlsPublicKey {
    #[cfg(feature = "bls12_381")]
    point: G1Affine,
    #[cfg(not(feature = "bls12_381"))]
    _phantom: (),
}

impl BlsPublicKey {
    /// Create from raw bytes (48 bytes compressed)
    #[cfg(feature = "bls12_381")]
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, BlsError> {
        let point = G1Affine::from_compressed(bytes)
            .map(|p| p.ok_or(BlsError::InvalidPublicKey))??;
        Ok(Self { point })
    }

    /// Convert to raw bytes (48 bytes compressed)
    #[cfg(feature = "bls12_381")]
    pub fn to_bytes(&self) -> [u8; 48] {
        self.point.to_compressed()
    }

    /// Verify a signature
    #[cfg(all(feature = "bls12_381", feature = "sha2"))]
    pub fn verify(&self, message: &[u8], signature: &BlsSignature, scheme: BlsScheme) -> Result<(), BlsError> {
        let hash_point = match scheme {
            BlsScheme::Basic => Self::hash_to_g2(message)?,
            BlsScheme::MessageAugmentation => {
                let augmented = [self.to_bytes().as_slice(), message].concat();
                Self::hash_to_g2(&augmented)?
            },
            BlsScheme::ProofOfPossession => Self::hash_to_g2(message)?,
        };

        // Verify: e(pk, H(m)) = e(g1, sig)
        let lhs = pairing(&self.point, &hash_point.into());
        let rhs = pairing(&G1Affine::generator(), &signature.point);

        if lhs == rhs {
            Ok(())
        } else {
            Err(BlsError::VerificationFailed)
        }
    }

    /// Verify a proof of possession
    #[cfg(all(feature = "bls12_381", feature = "sha2"))]
    pub fn verify_proof_of_possession(&self, pop: &BlsSignature) -> Result<(), BlsError> {
        let pk_bytes = self.to_bytes();
        self.verify(&pk_bytes, pop, BlsScheme::Basic)
    }

    /// Aggregate multiple public keys
    #[cfg(feature = "bls12_381")]
    pub fn aggregate(public_keys: &[BlsPublicKey]) -> Result<Self, BlsError> {
        if public_keys.is_empty() {
            return Err(BlsError::InvalidAggregation);
        }

        let mut sum = G1Projective::identity();
        for pk in public_keys {
            sum += pk.point;
        }

        Ok(Self { point: sum.into() })
    }

    /// Hash message to G2 point (static version)
    #[cfg(all(feature = "bls12_381", feature = "sha2"))]
    fn hash_to_g2(message: &[u8]) -> Result<G2Projective, BlsError> {
        let mut hasher = Sha256::new();
        hasher.update(b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_");
        hasher.update(message);
        let hash = hasher.finalize();

        let scalar = BlsScalar::from_bytes_wide(&[hash.as_slice().try_into().unwrap(), [0u8; 32]].concat().try_into().unwrap());
        Ok(G2Projective::generator() * scalar)
    }
}

/// BLS signature
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlsSignature {
    #[cfg(feature = "bls12_381")]
    point: G2Affine,
    #[cfg(not(feature = "bls12_381"))]
    _phantom: (),
}

impl BlsSignature {
    /// Create from raw bytes (96 bytes compressed)
    #[cfg(feature = "bls12_381")]
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, BlsError> {
        let point = G2Affine::from_compressed(bytes)
            .map(|p| p.ok_or(BlsError::InvalidSignature))??;
        Ok(Self { point })
    }

    /// Convert to raw bytes (96 bytes compressed)
    #[cfg(feature = "bls12_381")]
    pub fn to_bytes(&self) -> [u8; 96] {
        self.point.to_compressed()
    }

    /// Aggregate multiple signatures
    #[cfg(feature = "bls12_381")]
    pub fn aggregate(signatures: &[BlsSignature]) -> Result<Self, BlsError> {
        if signatures.is_empty() {
            return Err(BlsError::InvalidAggregation);
        }

        let mut sum = G2Projective::identity();
        for sig in signatures {
            sum += sig.point;
        }

        Ok(Self { point: sum.into() })
    }
}

/// Batch verification for multiple signatures
#[cfg(all(feature = "bls12_381", feature = "sha2"))]
pub fn batch_verify(
    public_keys: &[BlsPublicKey],
    messages: &[&[u8]],
    signatures: &[BlsSignature],
    scheme: BlsScheme,
) -> Result<(), BlsError> {
    if public_keys.len() != messages.len() || messages.len() != signatures.len() {
        return Err(BlsError::InvalidAggregation);
    }

    if public_keys.is_empty() {
        return Err(BlsError::InvalidAggregation);
    }

    // Prepare Miller loop inputs
    let mut miller_inputs = Vec::new();

    for (i, (pk, message)) in public_keys.iter().zip(messages.iter()).enumerate() {
        let hash_point = match scheme {
            BlsScheme::Basic => BlsPublicKey::hash_to_g2(message)?,
            BlsScheme::MessageAugmentation => {
                let augmented = [pk.to_bytes().as_slice(), message].concat();
                BlsPublicKey::hash_to_g2(&augmented)?
            },
            BlsScheme::ProofOfPossession => BlsPublicKey::hash_to_g2(message)?,
        };

        miller_inputs.push((&pk.point, &hash_point.into()));
        miller_inputs.push((&(-G1Affine::generator()), &signatures[i].point));
    }

    // Batch verification using multi-Miller loop
    let result = multi_miller_loop(&miller_inputs).final_exponentiation();

    if result == Gt::identity() {
        Ok(())
    } else {
        Err(BlsError::VerificationFailed)
    }
}

/// Multi-signature scheme using BLS
pub struct BlsMultiSig {
    /// Participating public keys
    pub public_keys: Vec<BlsPublicKey>,
    /// Aggregate public key
    pub aggregate_key: BlsPublicKey,
    /// Signature scheme
    pub scheme: BlsScheme,
}

impl BlsMultiSig {
    /// Create a new multi-signature setup
    #[cfg(feature = "bls12_381")]
    pub fn new(public_keys: Vec<BlsPublicKey>, scheme: BlsScheme) -> Result<Self, BlsError> {
        let aggregate_key = BlsPublicKey::aggregate(&public_keys)?;
        Ok(Self {
            public_keys,
            aggregate_key,
            scheme,
        })
    }

    /// Sign a message (partial signature)
    #[cfg(all(feature = "bls12_381", feature = "sha2"))]
    pub fn partial_sign(&self, secret_key: &BlsSecretKey, message: &[u8]) -> Result<BlsSignature, BlsError> {
        // Verify that the secret key corresponds to one of the public keys
        let expected_pk = secret_key.public_key();
        if !self.public_keys.contains(&expected_pk) {
            return Err(BlsError::InvalidSecretKey);
        }

        secret_key.sign(message, self.scheme)
    }

    /// Aggregate partial signatures
    #[cfg(feature = "bls12_381")]
    pub fn aggregate_signatures(&self, signatures: &[BlsSignature]) -> Result<BlsSignature, BlsError> {
        BlsSignature::aggregate(signatures)
    }

    /// Verify the aggregate signature
    #[cfg(all(feature = "bls12_381", feature = "sha2"))]
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> Result<(), BlsError> {
        self.aggregate_key.verify(message, signature, self.scheme)
    }
}

/// Utility functions for BLS operations
pub mod utils {
    use super::*;

    /// Generate a new keypair
    #[cfg(all(feature = "bls12_381", feature = "rand_core"))]
    pub fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (BlsSecretKey, BlsPublicKey) {
        let secret_key = BlsSecretKey::generate(rng);
        let public_key = secret_key.public_key();
        (secret_key, public_key)
    }

    /// Sign a message with the given scheme
    #[cfg(all(feature = "bls12_381", feature = "sha2"))]
    pub fn sign(secret_key: &BlsSecretKey, message: &[u8], scheme: BlsScheme) -> Result<BlsSignature, BlsError> {
        secret_key.sign(message, scheme)
    }

    /// Verify a signature
    #[cfg(all(feature = "bls12_381", feature = "sha2"))]
    pub fn verify(
        public_key: &BlsPublicKey,
        message: &[u8],
        signature: &BlsSignature,
        scheme: BlsScheme,
    ) -> bool {
        public_key.verify(message, signature, scheme).is_ok()
    }

    /// Aggregate public keys
    #[cfg(feature = "bls12_381")]
    pub fn aggregate_public_keys(keys: &[BlsPublicKey]) -> Result<BlsPublicKey, BlsError> {
        BlsPublicKey::aggregate(keys)
    }

    /// Aggregate signatures
    #[cfg(feature = "bls12_381")]
    pub fn aggregate_signatures(signatures: &[BlsSignature]) -> Result<BlsSignature, BlsError> {
        BlsSignature::aggregate(signatures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "bls12_381", feature = "rand_core", feature = "sha2"))]
    fn test_bls_basic_signature() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let secret_key = BlsSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();

        let message = b"Hello, BLS!";
        let signature = secret_key.sign(message, BlsScheme::Basic).unwrap();

        // Verify signature
        public_key.verify(message, &signature, BlsScheme::Basic).unwrap();

        // Test serialization
        let sk_bytes = secret_key.to_bytes();
        let pk_bytes = public_key.to_bytes();
        let sig_bytes = signature.to_bytes();

        let recovered_sk = BlsSecretKey::from_bytes(&sk_bytes).unwrap();
        let recovered_pk = BlsPublicKey::from_bytes(&pk_bytes).unwrap();
        let recovered_sig = BlsSignature::from_bytes(&sig_bytes).unwrap();

        assert_eq!(public_key, recovered_pk);
        assert_eq!(signature, recovered_sig);
        recovered_pk.verify(message, &recovered_sig, BlsScheme::Basic).unwrap();
    }

    #[test]
    #[cfg(all(feature = "bls12_381", feature = "rand_core", feature = "sha2"))]
    fn test_bls_aggregation() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        // Generate multiple keypairs
        let keypairs: Vec<_> = (0..3)
            .map(|_| {
                let sk = BlsSecretKey::generate(&mut rng);
                let pk = sk.public_key();
                (sk, pk)
            })
            .collect();

        let message = b"Aggregate this!";

        // Each party signs the message
        let signatures: Vec<_> = keypairs
            .iter()
            .map(|(sk, _)| sk.sign(message, BlsScheme::Basic).unwrap())
            .collect();

        // Aggregate signatures and public keys
        let aggregate_signature = BlsSignature::aggregate(&signatures).unwrap();
        let public_keys: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
        let aggregate_public_key = BlsPublicKey::aggregate(&public_keys).unwrap();

        // Verify aggregate signature
        aggregate_public_key.verify(message, &aggregate_signature, BlsScheme::Basic).unwrap();
    }

    #[test]
    #[cfg(all(feature = "bls12_381", feature = "rand_core", feature = "sha2"))]
    fn test_bls_multisig() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        // Generate keypairs for participants
        let keypairs: Vec<_> = (0..4)
            .map(|_| {
                let sk = BlsSecretKey::generate(&mut rng);
                let pk = sk.public_key();
                (sk, pk)
            })
            .collect();

        let public_keys: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
        let multisig = BlsMultiSig::new(public_keys, BlsScheme::ProofOfPossession).unwrap();

        let message = b"Multi-signature test";

        // Each participant creates a partial signature
        let partial_signatures: Vec<_> = keypairs
            .iter()
            .map(|(sk, _)| multisig.partial_sign(sk, message).unwrap())
            .collect();

        // Aggregate the partial signatures
        let aggregate_signature = multisig.aggregate_signatures(&partial_signatures).unwrap();

        // Verify the aggregate signature
        multisig.verify(message, &aggregate_signature).unwrap();
    }

    #[test]
    #[cfg(all(feature = "bls12_381", feature = "rand_core", feature = "sha2"))]
    fn test_proof_of_possession() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        let secret_key = BlsSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();

        // Generate proof of possession
        let pop = secret_key.proof_of_possession().unwrap();

        // Verify proof of possession
        public_key.verify_proof_of_possession(&pop).unwrap();
    }
}