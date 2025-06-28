//! Threshold cryptography implementations
//!
//! This module provides threshold signature schemes where multiple parties
//! must cooperate to create a valid signature.
//!
//! This module requires the `alloc` feature to be enabled.

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

use crate::{EdwardsPoint, Scalar};
use crate::traits::Compress;
use subtle::ConstantTimeEq;
use core::ops::Neg;

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

/// A threshold signature participant
#[derive(Clone, Debug)]
pub struct ThresholdParticipant {
    /// Participant ID
    pub id: u32,
    /// Secret share
    pub secret_share: Scalar,
    /// Public key share
    pub public_share: EdwardsPoint,
}

/// Threshold signature scheme configuration
#[derive(Clone, Debug)]
pub struct ThresholdConfig {
    /// Number of participants required to sign (threshold)
    pub threshold: usize,
    /// Total number of participants
    pub participants: usize,
}

/// A partial signature from a threshold participant
#[derive(Clone, Copy, Debug)]
pub struct PartialSignature {
    /// Participant ID
    pub participant_id: u32,
    /// Partial signature value
    pub signature: Scalar,
    /// Commitment point
    pub commitment: EdwardsPoint,
}

/// Complete threshold signature
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct ThresholdSignature {
    /// The final signature
    pub signature: Scalar,
    /// The combined commitment
    pub commitment: EdwardsPoint,
    /// List of participating signers
    pub signers: Vec<u32>,
}

/// Threshold cryptography errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdError {
    /// Invalid threshold configuration
    InvalidThreshold,
    /// Insufficient participants
    InsufficientParticipants,
    /// Invalid participant ID
    InvalidParticipant,
    /// Invalid partial signature
    InvalidPartialSignature,
    /// Signature aggregation failed
    AggregationFailed,
    /// Verification failed
    VerificationFailed,
}

impl core::fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ThresholdError::InvalidThreshold => write!(f, "Invalid threshold configuration"),
            ThresholdError::InsufficientParticipants => write!(f, "Insufficient participants"),
            ThresholdError::InvalidParticipant => write!(f, "Invalid participant ID"),
            ThresholdError::InvalidPartialSignature => write!(f, "Invalid partial signature"),
            ThresholdError::AggregationFailed => write!(f, "Signature aggregation failed"),
            ThresholdError::VerificationFailed => write!(f, "Verification failed"),
        }
    }
}

/// Threshold signature coordinator
#[cfg(feature = "alloc")]
pub struct ThresholdCoordinator {
    /// Threshold configuration
    config: ThresholdConfig,
    /// Master public key
    public_key: EdwardsPoint,
    /// Participant public shares
    participant_keys: Vec<(u32, EdwardsPoint)>,
}

impl ThresholdConfig {
    /// Create a new threshold configuration
    pub fn new(threshold: usize, participants: usize) -> Result<Self, ThresholdError> {
        if threshold == 0 || threshold > participants || participants == 0 {
            return Err(ThresholdError::InvalidThreshold);
        }
        
        Ok(ThresholdConfig {
            threshold,
            participants,
        })
    }
    
    /// Generate threshold key shares using Shamir's Secret Sharing
    #[cfg(feature = "rand_core")]
    pub fn generate_shares<R: CryptoRng + RngCore>(
        &self, 
        rng: &mut R
    ) -> Result<(EdwardsPoint, Vec<ThresholdParticipant>), ThresholdError> {
        // Generate master secret key
        let master_secret = Scalar::random(rng);
        let master_public = EdwardsPoint::mul_base(&master_secret);
        
        // Generate polynomial coefficients for Shamir's secret sharing
        let mut coefficients = vec![master_secret];
        for _ in 1..self.threshold {
            coefficients.push(Scalar::random(rng));
        }
        
        // Evaluate polynomial at each participant's ID to generate shares
        let mut participants = Vec::new();
        for i in 1..=self.participants {
            let participant_id = i as u32;
            let secret_share = self.evaluate_polynomial(&coefficients, participant_id);
            let public_share = EdwardsPoint::mul_base(&secret_share);
            
            participants.push(ThresholdParticipant {
                id: participant_id,
                secret_share,
                public_share,
            });
        }
        
        Ok((master_public, participants))
    }
    
    /// Evaluate polynomial at given x value for Shamir's secret sharing
    fn evaluate_polynomial(&self, coefficients: &[Scalar], x: u32) -> Scalar {
        let mut result = Scalar::ZERO;
        let mut x_bytes = [0u8; 32];
        x_bytes[0..8].copy_from_slice(&(x as u64).to_le_bytes());
        let x_scalar = Scalar::from_bytes_mod_order(x_bytes);
        
        for (i, &coeff) in coefficients.iter().enumerate() {
            // Compute coeff * x^i
            let mut term = coeff;
            for _ in 0..i {
                term = &term * &x_scalar;
            }
            result = &result + &term;
        }
        
        result
    }
}

impl ThresholdParticipant {
    /// Create a partial signature for a message
    #[cfg(feature = "rand_core")]
    pub fn sign_partial<R: CryptoRng + RngCore>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> PartialSignature {
        // Generate random nonce
        let nonce = Scalar::random(rng);
        let commitment = EdwardsPoint::mul_base(&nonce);
        
        // Compute challenge
        let challenge = self.compute_challenge(message, &commitment);
        
        // Compute partial signature: s = k + c * x_i
        let signature = &nonce + &(&challenge * &self.secret_share);
        
        PartialSignature {
            participant_id: self.id,
            signature,
            commitment,
        }
    }
    
    /// Create deterministic partial signature
    pub fn sign_partial_deterministic(&self, message: &[u8]) -> PartialSignature {
        // Derive deterministic nonce
        let nonce = self.derive_nonce(message);
        let commitment = EdwardsPoint::mul_base(&nonce);
        
        // Compute challenge
        let challenge = self.compute_challenge(message, &commitment);
        
        // Compute partial signature
        let signature = &nonce + &(&challenge * &self.secret_share);
        
        PartialSignature {
            participant_id: self.id,
            signature,
            commitment,
        }
    }
    
    /// Compute challenge for signature
    fn compute_challenge(&self, message: &[u8], commitment: &EdwardsPoint) -> Scalar {
        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(message);
        challenge_input.extend_from_slice(&self.public_share.compress().to_bytes());
        challenge_input.extend_from_slice(&commitment.compress().to_bytes());
        challenge_input.extend_from_slice(&self.id.to_le_bytes());
        
        let hash = simple_hash(&challenge_input);
        Scalar::from_bytes_mod_order(hash)
    }
    
    /// Derive deterministic nonce
    fn derive_nonce(&self, message: &[u8]) -> Scalar {
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(&self.secret_share.to_bytes());
        nonce_input.extend_from_slice(message);
        nonce_input.extend_from_slice(&self.id.to_le_bytes());
        nonce_input.extend_from_slice(b"THRESHOLD_NONCE");
        
        let hash = simple_hash(&nonce_input);
        Scalar::from_bytes_mod_order(hash)
    }
}

#[cfg(feature = "alloc")]
impl ThresholdCoordinator {
    /// Create a new threshold coordinator
    pub fn new(
        config: ThresholdConfig,
        public_key: EdwardsPoint,
        participant_keys: Vec<(u32, EdwardsPoint)>,
    ) -> Result<Self, ThresholdError> {
        if participant_keys.len() != config.participants {
            return Err(ThresholdError::InvalidThreshold);
        }
        
        Ok(ThresholdCoordinator {
            config,
            public_key,
            participant_keys,
        })
    }
    
    /// Aggregate partial signatures into a complete threshold signature
    pub fn aggregate_signatures(
        &self,
        message: &[u8],
        partial_signatures: Vec<PartialSignature>,
    ) -> Result<ThresholdSignature, ThresholdError> {
        if partial_signatures.len() < self.config.threshold {
            return Err(ThresholdError::InsufficientParticipants);
        }
        
        // Take only the required number of signatures
        let signatures: Vec<_> = partial_signatures.into_iter().take(self.config.threshold).collect();
        
        // Compute Lagrange coefficients for interpolation
        let lagrange_coeffs = self.compute_lagrange_coefficients(&signatures)?;
        
        // Aggregate signatures using Lagrange interpolation
        let mut aggregated_signature = Scalar::ZERO;
        let mut aggregated_commitment = EdwardsPoint::IDENTITY;
        
        for (partial_sig, coeff) in signatures.iter().zip(lagrange_coeffs.iter()) {
            // Verify partial signature first
            self.verify_partial_signature(message, partial_sig)?;
            
            // Aggregate: s = sum(L_i * s_i)
            aggregated_signature = &aggregated_signature + &(coeff * &partial_sig.signature);
            
            // Aggregate commitments: R = sum(L_i * R_i)
            let weighted_commitment = &partial_sig.commitment * coeff;
            aggregated_commitment = &aggregated_commitment + &weighted_commitment;
        }
        
        let signers: Vec<u32> = signatures.iter().map(|s| s.participant_id).collect();
        
        Ok(ThresholdSignature {
            signature: aggregated_signature,
            commitment: aggregated_commitment,
            signers,
        })
    }
    
    /// Compute Lagrange interpolation coefficients
    fn compute_lagrange_coefficients(
        &self,
        signatures: &[PartialSignature],
    ) -> Result<Vec<Scalar>, ThresholdError> {
        let mut coefficients = Vec::new();
        
        for i in 0..signatures.len() {
            let x_i = signatures[i].participant_id;
            let mut numerator = Scalar::ONE;
            let mut denominator = Scalar::ONE;
            
            for j in 0..signatures.len() {
                if i != j {
                    let x_j = signatures[j].participant_id;
                    
                    // numerator *= (0 - x_j) = -x_j
                    let mut x_j_bytes = [0u8; 32];
                    x_j_bytes[0..8].copy_from_slice(&(x_j as u64).to_le_bytes());
                    numerator = &numerator * &Scalar::from_bytes_mod_order(x_j_bytes).neg();
                    
                    // denominator *= (x_i - x_j)
                    let mut x_i_bytes = [0u8; 32];
                    x_i_bytes[0..8].copy_from_slice(&(x_i as u64).to_le_bytes());
                    let mut x_j_bytes = [0u8; 32];
                    x_j_bytes[0..8].copy_from_slice(&(x_j as u64).to_le_bytes());
                    let diff = Scalar::from_bytes_mod_order(x_i_bytes) - Scalar::from_bytes_mod_order(x_j_bytes);
                    denominator = &denominator * &diff;
                }
            }
            
            // Compute coefficient as numerator / denominator
            let coeff = &numerator * &denominator.invert().unwrap_or(Scalar::ONE);
            coefficients.push(coeff);
        }
        
        Ok(coefficients)
    }
    
    /// Verify a partial signature
    fn verify_partial_signature(
        &self,
        message: &[u8],
        partial_sig: &PartialSignature,
    ) -> Result<(), ThresholdError> {
        // Find the participant's public key
        let public_share = self.participant_keys
            .iter()
            .find(|(id, _)| *id == partial_sig.participant_id)
            .map(|(_, key)| *key)
            .ok_or(ThresholdError::InvalidParticipant)?;
        
        // Compute expected challenge
        let challenge = self.compute_partial_challenge(
            message,
            &partial_sig.commitment,
            &public_share,
            partial_sig.participant_id,
        );
        
        // Verify: [s]G = R + [c]P_i
        let left_side = EdwardsPoint::mul_base(&partial_sig.signature);
        let right_side = &partial_sig.commitment + &(&public_share * &challenge);
        
        if left_side.ct_eq(&right_side).into() {
            Ok(())
        } else {
            Err(ThresholdError::InvalidPartialSignature)
        }
    }
    
    /// Compute challenge for partial signature verification
    fn compute_partial_challenge(
        &self,
        message: &[u8],
        commitment: &EdwardsPoint,
        public_share: &EdwardsPoint,
        participant_id: u32,
    ) -> Scalar {
        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(message);
        challenge_input.extend_from_slice(&public_share.compress().to_bytes());
        challenge_input.extend_from_slice(&commitment.compress().to_bytes());
        challenge_input.extend_from_slice(&participant_id.to_le_bytes());
        
        let hash = simple_hash(&challenge_input);
        Scalar::from_bytes_mod_order(hash)
    }
    
    /// Verify a complete threshold signature
    pub fn verify_threshold_signature(
        &self,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<(), ThresholdError> {
        if signature.signers.len() < self.config.threshold {
            return Err(ThresholdError::InsufficientParticipants);
        }
        
        // Compute challenge for the complete signature
        let challenge = self.compute_threshold_challenge(message, &signature.commitment);
        
        // Verify: [s]G = R + [c]PK
        let left_side = EdwardsPoint::mul_base(&signature.signature);
        let right_side = &signature.commitment + &(&self.public_key * &challenge);
        
        if left_side.ct_eq(&right_side).into() {
            Ok(())
        } else {
            Err(ThresholdError::VerificationFailed)
        }
    }
    
    /// Compute challenge for threshold signature
    fn compute_threshold_challenge(&self, message: &[u8], commitment: &EdwardsPoint) -> Scalar {
        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(message);
        challenge_input.extend_from_slice(&self.public_key.compress().to_bytes());
        challenge_input.extend_from_slice(&commitment.compress().to_bytes());
        challenge_input.extend_from_slice(b"THRESHOLD");
        
        let hash = simple_hash(&challenge_input);
        Scalar::from_bytes_mod_order(hash)
    }
}

/// Simplified hash function
fn simple_hash(input: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    
    for (i, &byte) in input.iter().enumerate() {
        hash[i % 32] ^= byte.wrapping_mul((i as u8).wrapping_add(1));
        hash[i % 32] = hash[i % 32].wrapping_add(byte);
    }
    
    // Additional mixing
    for round in 0..4 {
        for i in 0..32 {
            hash[i] = hash[i].wrapping_add(hash[(i + round + 1) % 32]);
        }
    }
    
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(feature = "rand_core")]
    #[test]
    fn test_threshold_signature_basic() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        
        // Create 3-of-5 threshold scheme
        let config = ThresholdConfig::new(3, 5).unwrap();
        let (master_public, participants) = config.generate_shares(&mut rng).unwrap();
        
        // Create participant key list
        let participant_keys: Vec<_> = participants.iter()
            .map(|p| (p.id, p.public_share))
            .collect();
        
        let coordinator = ThresholdCoordinator::new(config, master_public, participant_keys).unwrap();
        
        // Have 3 participants sign a message
        let message = b"Threshold signature test";
        let mut partial_signatures = Vec::new();
        
        for i in 0..3 {
            let partial_sig = participants[i].sign_partial(message, &mut rng);
            partial_signatures.push(partial_sig);
        }
        
        // Aggregate the signatures
        let threshold_sig = coordinator.aggregate_signatures(message, partial_signatures).unwrap();
        
        // Verify the threshold signature
        assert!(coordinator.verify_threshold_signature(message, &threshold_sig).is_ok());
        
        // Wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(coordinator.verify_threshold_signature(wrong_message, &threshold_sig).is_err());
    }
    
    #[cfg(feature = "rand_core")]
    #[test]
    fn test_insufficient_participants() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        
        // Create 3-of-5 threshold scheme
        let config = ThresholdConfig::new(3, 5).unwrap();
        let (master_public, participants) = config.generate_shares(&mut rng).unwrap();
        
        let participant_keys: Vec<_> = participants.iter()
            .map(|p| (p.id, p.public_share))
            .collect();
        
        let coordinator = ThresholdCoordinator::new(config, master_public, participant_keys).unwrap();
        
        // Try with only 2 participants (should fail)
        let message = b"Test message";
        let mut partial_signatures = Vec::new();
        
        for i in 0..2 {
            let partial_sig = participants[i].sign_partial(message, &mut rng);
            partial_signatures.push(partial_sig);
        }
        
        // Should fail due to insufficient participants
        assert!(coordinator.aggregate_signatures(message, partial_signatures).is_err());
    }
    
    #[test]
    fn test_deterministic_threshold() {
        // Create simple 2-of-3 setup for testing
        let config = ThresholdConfig::new(2, 3).unwrap();
        
        let participant1 = ThresholdParticipant {
            id: 1,
            secret_share: Scalar::from_bytes_mod_order(&[1u8; 32]),
            public_share: EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(&[1u8; 32])),
        };
        
        let message = b"Deterministic test";
        
        // Same participant should produce same partial signature
        let sig1 = participant1.sign_partial_deterministic(message);
        let sig2 = participant1.sign_partial_deterministic(message);
        
        assert_eq!(sig1.participant_id, sig2.participant_id);
        assert!(sig1.signature.ct_eq(&sig2.signature).into());
        assert!(sig1.commitment.ct_eq(&sig2.commitment).into());
    }
}