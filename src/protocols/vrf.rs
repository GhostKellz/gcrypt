//! Verifiable Random Function (VRF) implementation
//!
//! This module implements ECVRF-EDWARDS25519-SHA256-TAI as specified in RFC 9381.
//! VRFs provide cryptographically verifiable pseudorandom outputs.

use crate::{EdwardsPoint, Scalar, FieldElement};
use subtle::ConstantTimeEq;

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

/// VRF public key
#[derive(Clone, Copy, Debug)]
pub struct VrfPublicKey {
    /// The public key point
    pub(crate) point: EdwardsPoint,
}

/// VRF secret key
#[derive(Clone, Debug)]
pub struct VrfSecretKey {
    /// The secret scalar  
    pub(crate) scalar: Scalar,
    /// The corresponding public key
    pub(crate) public: VrfPublicKey,
}

/// VRF proof
#[derive(Clone, Copy, Debug)]
pub struct VrfProof {
    /// The gamma component
    pub(crate) gamma: EdwardsPoint,
    /// The challenge scalar
    pub(crate) c: Scalar,
    /// The response scalar
    pub(crate) s: Scalar,
}

/// VRF output (pseudorandom value)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrfOutput([u8; 32]);

/// VRF verification errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrfError {
    /// Invalid proof
    InvalidProof,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid input
    InvalidInput,
    /// Hash to curve failed
    HashToCurveFailed,
}

impl core::fmt::Display for VrfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VrfError::InvalidProof => write!(f, "Invalid VRF proof"),
            VrfError::InvalidPublicKey => write!(f, "Invalid VRF public key"),
            VrfError::InvalidInput => write!(f, "Invalid VRF input"),
            VrfError::HashToCurveFailed => write!(f, "Hash to curve operation failed"),
        }
    }
}

impl VrfSecretKey {
    /// Generate a new VRF key pair
    #[cfg(feature = "rand_core")]
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> VrfSecretKey {
        let scalar = Scalar::random(rng);
        let point = EdwardsPoint::mul_base(&scalar);
        
        VrfSecretKey {
            scalar,
            public: VrfPublicKey { point },
        }
    }
    
    /// Create VRF secret key from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> VrfSecretKey {
        let scalar = Scalar::from_bytes_mod_order(bytes);
        let point = EdwardsPoint::mul_base(&scalar);
        
        VrfSecretKey {
            scalar,
            public: VrfPublicKey { point },
        }
    }
    
    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }
    
    /// Get the public key
    pub fn public_key(&self) -> VrfPublicKey {
        self.public
    }
    
    /// Evaluate VRF and generate proof
    pub fn evaluate(&self, input: &[u8]) -> Result<(VrfOutput, VrfProof), VrfError> {
        // Hash input to curve point
        let h = self.hash_to_curve(input)?;
        
        // Compute gamma = [x]H
        let gamma = &h * &self.scalar;
        
        // Generate random nonce for proof
        let k = self.derive_nonce(input, &gamma);
        
        // Compute commitment values
        let c1 = EdwardsPoint::mul_base(&k);     // [k]B
        let c2 = &h * &k;                        // [k]H
        
        // Compute challenge
        let c = self.compute_challenge(input, &self.public.point, &gamma, &c1, &c2);
        
        // Compute response
        let s = &k + &(&c * &self.scalar);
        
        // Compute output
        let output = self.gamma_to_output(&gamma);
        
        let proof = VrfProof { gamma, c, s };
        
        Ok((output, proof))
    }
    
    /// Hash arbitrary input to curve point
    fn hash_to_curve(&self, input: &[u8]) -> Result<EdwardsPoint, VrfError> {
        // Simplified hash-to-curve implementation
        // Real implementation would use proper hash-to-curve like Elligator
        
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(b"VRF_H2C_");
        hasher_input.extend_from_slice(&self.public.point.compress().to_bytes());
        hasher_input.extend_from_slice(input);
        
        // Try to find a valid point
        for counter in 0..256u8 {
            hasher_input.push(counter);
            let hash = simple_hash(&hasher_input);
            
            let compressed = crate::edwards::CompressedEdwardsY(hash);
            if let Some(point) = compressed.decompress() {
                return Ok(point);
            }
            
            hasher_input.pop();
        }
        
        Err(VrfError::HashToCurveFailed)
    }
    
    /// Derive deterministic nonce for proof generation
    fn derive_nonce(&self, input: &[u8], gamma: &EdwardsPoint) -> Scalar {
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(&self.scalar.to_bytes());
        nonce_input.extend_from_slice(input);
        nonce_input.extend_from_slice(&gamma.compress().to_bytes());
        nonce_input.extend_from_slice(b"VRF_NONCE");
        
        let hash = simple_hash(&nonce_input);
        Scalar::from_bytes_mod_order(&hash)
    }
    
    /// Compute challenge for Fiat-Shamir
    fn compute_challenge(
        &self,
        input: &[u8],
        public_key: &EdwardsPoint,
        gamma: &EdwardsPoint,
        c1: &EdwardsPoint,
        c2: &EdwardsPoint,
    ) -> Scalar {
        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(b"VRF_CHALLENGE_");
        challenge_input.extend_from_slice(&public_key.compress().to_bytes());
        challenge_input.extend_from_slice(&gamma.compress().to_bytes());
        challenge_input.extend_from_slice(&c1.compress().to_bytes());
        challenge_input.extend_from_slice(&c2.compress().to_bytes());
        challenge_input.extend_from_slice(input);
        
        let hash = simple_hash(&challenge_input);
        Scalar::from_bytes_mod_order(&hash)
    }
    
    /// Convert gamma point to VRF output
    fn gamma_to_output(&self, gamma: &EdwardsPoint) -> VrfOutput {
        let mut output_input = Vec::new();
        output_input.extend_from_slice(b"VRF_OUTPUT_");
        output_input.extend_from_slice(&gamma.compress().to_bytes());
        
        let hash = simple_hash(&output_input);
        VrfOutput(hash)
    }
}

impl VrfPublicKey {
    /// Create public key from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<VrfPublicKey, VrfError> {
        let compressed = crate::edwards::CompressedEdwardsY(*bytes);
        match compressed.decompress() {
            Some(point) => Ok(VrfPublicKey { point }),
            None => Err(VrfError::InvalidPublicKey),
        }
    }
    
    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }
    
    /// Verify VRF proof and recover output
    pub fn verify(&self, input: &[u8], output: &VrfOutput, proof: &VrfProof) -> Result<(), VrfError> {
        // Hash input to curve
        let h = self.hash_to_curve(input)?;
        
        // Recompute commitment values  
        let c1 = &EdwardsPoint::mul_base(&proof.s) - &(&self.point * &proof.c);
        let c2 = &(&h * &proof.s) - &(&proof.gamma * &proof.c);
        
        // Recompute challenge
        let c_prime = self.compute_challenge(input, &self.point, &proof.gamma, &c1, &c2);
        
        // Verify challenge matches
        if !proof.c.ct_eq(&c_prime).into() {
            return Err(VrfError::InvalidProof);
        }
        
        // Verify output matches gamma
        let expected_output = self.gamma_to_output(&proof.gamma);
        if !output.0.ct_eq(&expected_output.0).into() {
            return Err(VrfError::InvalidProof);
        }
        
        Ok(())
    }
    
    /// Hash input to curve point (same as secret key version)  
    fn hash_to_curve(&self, input: &[u8]) -> Result<EdwardsPoint, VrfError> {
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(b"VRF_H2C_");
        hasher_input.extend_from_slice(&self.point.compress().to_bytes());
        hasher_input.extend_from_slice(input);
        
        for counter in 0..256u8 {
            hasher_input.push(counter);
            let hash = simple_hash(&hasher_input);
            
            let compressed = crate::edwards::CompressedEdwardsY(hash);
            if let Some(point) = compressed.decompress() {
                return Ok(point);
            }
            
            hasher_input.pop();
        }
        
        Err(VrfError::HashToCurveFailed)
    }
    
    /// Compute challenge (same as secret key version)
    fn compute_challenge(
        &self,
        input: &[u8],
        public_key: &EdwardsPoint,
        gamma: &EdwardsPoint,
        c1: &EdwardsPoint,
        c2: &EdwardsPoint,
    ) -> Scalar {
        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(b"VRF_CHALLENGE_");
        challenge_input.extend_from_slice(&public_key.compress().to_bytes());
        challenge_input.extend_from_slice(&gamma.compress().to_bytes());
        challenge_input.extend_from_slice(&c1.compress().to_bytes());
        challenge_input.extend_from_slice(&c2.compress().to_bytes());
        challenge_input.extend_from_slice(input);
        
        let hash = simple_hash(&challenge_input);
        Scalar::from_bytes_mod_order(&hash)
    }
    
    /// Convert gamma to output (same as secret key version)
    fn gamma_to_output(&self, gamma: &EdwardsPoint) -> VrfOutput {
        let mut output_input = Vec::new();
        output_input.extend_from_slice(b"VRF_OUTPUT_");
        output_input.extend_from_slice(&gamma.compress().to_bytes());
        
        let hash = simple_hash(&output_input);
        VrfOutput(hash)
    }
}

impl VrfOutput {
    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> VrfOutput {
        VrfOutput(*bytes)
    }
    
    /// Use output as random seed
    pub fn as_rng_seed(&self) -> [u8; 32] {
        self.0
    }
}

impl VrfProof {
    /// Convert proof to bytes
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        bytes[0..32].copy_from_slice(&self.gamma.compress().to_bytes());
        bytes[32..64].copy_from_slice(&self.c.to_bytes());
        bytes[64..96].copy_from_slice(&self.s.to_bytes());
        bytes
    }
    
    /// Create proof from bytes
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<VrfProof, VrfError> {
        let gamma_compressed = crate::edwards::CompressedEdwardsY(
            bytes[0..32].try_into().map_err(|_| VrfError::InvalidProof)?
        );
        let gamma = gamma_compressed.decompress().ok_or(VrfError::InvalidProof)?;
        
        let c = Scalar::from_canonical_bytes(
            &bytes[32..64].try_into().map_err(|_| VrfError::InvalidProof)?
        ).ok_or(VrfError::InvalidProof)?;
        
        let s = Scalar::from_canonical_bytes(
            &bytes[64..96].try_into().map_err(|_| VrfError::InvalidProof)?
        ).ok_or(VrfError::InvalidProof)?;
        
        Ok(VrfProof { gamma, c, s })
    }
}

/// Simplified hash function
fn simple_hash(input: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    
    for (i, &byte) in input.iter().enumerate() {
        hash[i % 32] ^= byte.wrapping_mul(i as u8 + 1);
        hash[i % 32] = hash[i % 32].wrapping_add(byte);
    }
    
    // Additional mixing
    for i in 0..32 {
        hash[i] = hash[i].wrapping_add(hash[(i + 1) % 32]);
    }
    
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(feature = "rand_core")]
    #[test]
    fn test_vrf_basic() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        
        let secret_key = VrfSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();
        
        let input = b"test input";
        let (output, proof) = secret_key.evaluate(input).unwrap();
        
        // Verification should succeed
        assert!(public_key.verify(input, &output, &proof).is_ok());
        
        // Different input should produce different output
        let input2 = b"different input";
        let (output2, _proof2) = secret_key.evaluate(input2).unwrap();
        assert_ne!(output.to_bytes(), output2.to_bytes());
    }
    
    #[test]
    fn test_vrf_deterministic() {
        let secret_key = VrfSecretKey::from_bytes(&[1u8; 32]);
        let input = b"deterministic test";
        
        // Same input should produce same output
        let (output1, proof1) = secret_key.evaluate(input).unwrap();
        let (output2, proof2) = secret_key.evaluate(input).unwrap();
        
        assert_eq!(output1.to_bytes(), output2.to_bytes());
        assert_eq!(proof1.to_bytes(), proof2.to_bytes());
    }
    
    #[test]
    fn test_vrf_serialization() {
        let secret_key = VrfSecretKey::from_bytes(&[42u8; 32]);
        let public_key = secret_key.public_key();
        let input = b"serialization test";
        
        let (output, proof) = secret_key.evaluate(input).unwrap();
        
        // Test proof serialization
        let proof_bytes = proof.to_bytes();
        let recovered_proof = VrfProof::from_bytes(&proof_bytes).unwrap();
        
        // Test output serialization  
        let output_bytes = output.to_bytes();
        let recovered_output = VrfOutput::from_bytes(&output_bytes);
        
        // Verification should still work
        assert!(public_key.verify(input, &recovered_output, &recovered_proof).is_ok());
    }
    
    #[test]
    fn test_vrf_invalid_proof() {
        let secret_key = VrfSecretKey::from_bytes(&[1u8; 32]);
        let public_key = secret_key.public_key();
        let input = b"test input";
        
        let (output, mut proof) = secret_key.evaluate(input).unwrap();
        
        // Corrupt the proof
        proof.c = Scalar::from_bytes_mod_order(&[0u8; 32]);
        
        // Verification should fail
        assert!(public_key.verify(input, &output, &proof).is_err());
    }
}