//! MiMC Hash Function
//!
//! MiMC is a family of hash functions designed for use in SNARKs and STARKs.
//! It uses a very simple round function with minimal multiplicative complexity.

use crate::{field::FieldElement, traits::Field};
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// MiMC hash function errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimcError {
    /// Invalid input length
    InvalidInputLength,
    /// Invalid parameters
    InvalidParameters,
    /// Hash computation failed
    ComputationFailed,
}

impl fmt::Display for MimcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MimcError::InvalidInputLength => write!(f, "Invalid MiMC input length"),
            MimcError::InvalidParameters => write!(f, "Invalid MiMC parameters"),
            MimcError::ComputationFailed => write!(f, "MiMC computation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MimcError {}

/// MiMC parameters for different configurations
#[derive(Debug, Clone)]
pub struct MimcParameters {
    /// Number of rounds
    pub rounds: usize,
    /// Exponent (typically 3, 5, or 7)
    pub exponent: u64,
    /// Round constants
    #[cfg(feature = "alloc")]
    pub round_constants: Vec<FieldElement>,
}

impl MimcParameters {
    /// Create MiMC parameters for BN254 field with exponent 7
    #[cfg(feature = "alloc")]
    pub fn bn254_exponent_7() -> Self {
        Self {
            rounds: 91, // Standard rounds for BN254 with exponent 7
            exponent: 7,
            round_constants: Self::bn254_round_constants_exp_7(),
        }
    }

    /// Create MiMC parameters for BN254 field with exponent 5
    #[cfg(feature = "alloc")]
    pub fn bn254_exponent_5() -> Self {
        Self {
            rounds: 110, // More rounds needed for smaller exponent
            exponent: 5,
            round_constants: Self::bn254_round_constants_exp_5(),
        }
    }

    /// Create MiMC parameters for BN254 field with exponent 3
    #[cfg(feature = "alloc")]
    pub fn bn254_exponent_3() -> Self {
        Self {
            rounds: 322, // Many more rounds needed for exponent 3
            exponent: 3,
            round_constants: Self::bn254_round_constants_exp_3(),
        }
    }

    /// BN254 round constants for exponent 7 (simplified)
    #[cfg(feature = "alloc")]
    fn bn254_round_constants_exp_7() -> Vec<FieldElement> {
        // In practice, these should be generated using a cryptographically secure method
        let mut constants = Vec::with_capacity(91);
        for i in 0..91 {
            // Simple deterministic generation for demonstration
            let value = (i as u64).wrapping_mul(0x1234567890abcdefu64);
            constants.push(FieldElement::from_u64(value));
        }
        constants
    }

    /// BN254 round constants for exponent 5
    #[cfg(feature = "alloc")]
    fn bn254_round_constants_exp_5() -> Vec<FieldElement> {
        let mut constants = Vec::with_capacity(110);
        for i in 0..110 {
            let value = (i as u64).wrapping_mul(0x9876543210fedcbau64);
            constants.push(FieldElement::from_u64(value));
        }
        constants
    }

    /// BN254 round constants for exponent 3
    #[cfg(feature = "alloc")]
    fn bn254_round_constants_exp_3() -> Vec<FieldElement> {
        let mut constants = Vec::with_capacity(322);
        for i in 0..322 {
            let value = (i as u64).wrapping_mul(0xfedcba0987654321u64);
            constants.push(FieldElement::from_u64(value));
        }
        constants
    }
}

/// MiMC hash function implementation
pub struct MimcHasher {
    params: MimcParameters,
}

impl MimcHasher {
    /// Create a new MiMC hasher with given parameters
    pub fn new(params: MimcParameters) -> Self {
        Self { params }
    }

    /// Create a MiMC hasher for BN254 with exponent 7
    #[cfg(feature = "alloc")]
    pub fn bn254_exponent_7() -> Self {
        Self::new(MimcParameters::bn254_exponent_7())
    }

    /// Create a MiMC hasher for BN254 with exponent 5
    #[cfg(feature = "alloc")]
    pub fn bn254_exponent_5() -> Self {
        Self::new(MimcParameters::bn254_exponent_5())
    }

    /// Hash two field elements using MiMC
    #[cfg(feature = "alloc")]
    pub fn hash_two(&self, left: &FieldElement, right: &FieldElement) -> Result<FieldElement, MimcError> {
        // MiMC two-input hash: E_k(left) + right + k where k = right
        let encrypted_left = self.mimc_encrypt(left, right)?;
        Ok(encrypted_left + *right + *right)
    }

    /// Hash multiple field elements using Davies-Meyer construction
    #[cfg(feature = "alloc")]
    pub fn hash_many(&self, inputs: &[FieldElement]) -> Result<FieldElement, MimcError> {
        if inputs.is_empty() {
            return Ok(FieldElement::zero());
        }

        let mut result = inputs[0];

        for &input in &inputs[1..] {
            result = self.hash_two(&result, &input)?;
        }

        Ok(result)
    }

    /// MiMC sponge construction for variable-length output
    #[cfg(feature = "alloc")]
    pub fn sponge(&self, inputs: &[FieldElement], output_len: usize) -> Result<Vec<FieldElement>, MimcError> {
        // Simple sponge: repeatedly hash accumulated state with new inputs
        let mut state = FieldElement::zero();

        // Absorb phase
        for &input in inputs {
            state = self.hash_two(&state, &input)?;
        }

        // Squeeze phase
        let mut output = Vec::with_capacity(output_len);
        for i in 0..output_len {
            let index_element = FieldElement::from_u64(i as u64);
            let next_output = self.hash_two(&state, &index_element)?;
            output.push(next_output);
            state = next_output;
        }

        Ok(output)
    }

    /// MiMC encryption function: E_k(x) = F(x + k) where F is the MiMC permutation
    #[cfg(feature = "alloc")]
    fn mimc_encrypt(&self, plaintext: &FieldElement, key: &FieldElement) -> Result<FieldElement, MimcError> {
        if self.params.round_constants.len() != self.params.rounds {
            return Err(MimcError::InvalidParameters);
        }

        let mut state = *plaintext + *key;

        for i in 0..self.params.rounds {
            // Add round constant
            state = state + self.params.round_constants[i];

            // Apply S-box (x^exponent)
            state = state.pow(self.params.exponent);
        }

        // Final key addition
        Ok(state + *key)
    }

    /// MiMC permutation without key (for other constructions)
    #[cfg(feature = "alloc")]
    pub fn mimc_permutation(&self, input: &FieldElement) -> Result<FieldElement, MimcError> {
        // Use zero key for permutation
        let zero_key = FieldElement::zero();
        let encrypted = self.mimc_encrypt(input, &zero_key)?;
        Ok(encrypted - zero_key) // Remove final key addition
    }

    /// MiMC Feistel construction for larger inputs
    #[cfg(feature = "alloc")]
    pub fn mimc_feistel(&self, left: &FieldElement, right: &FieldElement, rounds: usize) -> Result<(FieldElement, FieldElement), MimcError> {
        let mut l = *left;
        let mut r = *right;

        for i in 0..rounds {
            let round_key = FieldElement::from_u64(i as u64);
            let f_output = self.mimc_encrypt(&r, &round_key)?;
            let new_l = r;
            let new_r = l + f_output;
            l = new_l;
            r = new_r;
        }

        Ok((l, r))
    }
}

/// Convenience functions for common MiMC operations
#[cfg(feature = "alloc")]
pub mod mimc {
    use super::*;

    /// Hash two field elements using MiMC
    pub fn hash_two(left: &FieldElement, right: &FieldElement) -> Result<FieldElement, MimcError> {
        let hasher = MimcHasher::bn254_exponent_7();
        hasher.hash_two(left, right)
    }

    /// Hash multiple field elements using MiMC
    pub fn hash_many(inputs: &[FieldElement]) -> Result<FieldElement, MimcError> {
        let hasher = MimcHasher::bn254_exponent_7();
        hasher.hash_many(inputs)
    }

    /// MiMC sponge with variable output length
    pub fn sponge(inputs: &[FieldElement], output_len: usize) -> Result<Vec<FieldElement>, MimcError> {
        let hasher = MimcHasher::bn254_exponent_7();
        hasher.sponge(inputs, output_len)
    }

    /// MiMC permutation
    pub fn permutation(input: &FieldElement) -> Result<FieldElement, MimcError> {
        let hasher = MimcHasher::bn254_exponent_7();
        hasher.mimc_permutation(input)
    }

    /// MiMC encryption
    pub fn encrypt(plaintext: &FieldElement, key: &FieldElement) -> Result<FieldElement, MimcError> {
        let hasher = MimcHasher::bn254_exponent_7();
        hasher.mimc_encrypt(plaintext, key)
    }

    /// MiMC Feistel construction
    pub fn feistel(left: &FieldElement, right: &FieldElement, rounds: usize) -> Result<(FieldElement, FieldElement), MimcError> {
        let hasher = MimcHasher::bn254_exponent_7();
        hasher.mimc_feistel(left, right, rounds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mimc_parameters() {
        let params = MimcParameters::bn254_exponent_7();
        assert_eq!(params.rounds, 91);
        assert_eq!(params.exponent, 7);
        assert_eq!(params.round_constants.len(), 91);

        let params5 = MimcParameters::bn254_exponent_5();
        assert_eq!(params5.exponent, 5);
        assert_eq!(params5.rounds, 110);

        let params3 = MimcParameters::bn254_exponent_3();
        assert_eq!(params3.exponent, 3);
        assert_eq!(params3.rounds, 322);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_mimc_encryption() {
        let hasher = MimcHasher::bn254_exponent_7();
        let plaintext = FieldElement::from_u64(42);
        let key = FieldElement::from_u64(84);

        let ciphertext = hasher.mimc_encrypt(&plaintext, &key).unwrap();

        // Same input should produce same output
        let ciphertext2 = hasher.mimc_encrypt(&plaintext, &key).unwrap();
        assert_eq!(ciphertext, ciphertext2);

        // Different key should produce different output
        let key2 = FieldElement::from_u64(85);
        let ciphertext3 = hasher.mimc_encrypt(&plaintext, &key2).unwrap();
        assert_ne!(ciphertext, ciphertext3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_mimc_hash_two() {
        let hasher = MimcHasher::bn254_exponent_7();
        let left = FieldElement::from_u64(42);
        let right = FieldElement::from_u64(84);

        let result = hasher.hash_two(&left, &right).unwrap();
        let result2 = hasher.hash_two(&left, &right).unwrap();
        assert_eq!(result, result2);

        // Order should matter
        let result3 = hasher.hash_two(&right, &left).unwrap();
        assert_ne!(result, result3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_mimc_hash_many() {
        let hasher = MimcHasher::bn254_exponent_7();
        let inputs = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
            FieldElement::from_u64(4),
        ];

        let result = hasher.hash_many(&inputs).unwrap();
        let result2 = hasher.hash_many(&inputs).unwrap();
        assert_eq!(result, result2);

        // Different inputs should produce different results
        let inputs2 = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
            FieldElement::from_u64(5), // Changed last element
        ];
        let result3 = hasher.hash_many(&inputs2).unwrap();
        assert_ne!(result, result3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_mimc_permutation() {
        let hasher = MimcHasher::bn254_exponent_7();
        let input = FieldElement::from_u64(42);

        let output = hasher.mimc_permutation(&input).unwrap();
        let output2 = hasher.mimc_permutation(&input).unwrap();
        assert_eq!(output, output2);

        // Different inputs should produce different outputs
        let input2 = FieldElement::from_u64(43);
        let output3 = hasher.mimc_permutation(&input2).unwrap();
        assert_ne!(output, output3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_mimc_feistel() {
        let hasher = MimcHasher::bn254_exponent_7();
        let left = FieldElement::from_u64(42);
        let right = FieldElement::from_u64(84);

        let (new_left, new_right) = hasher.mimc_feistel(&left, &right, 8).unwrap();

        // Same inputs should produce same outputs
        let (new_left2, new_right2) = hasher.mimc_feistel(&left, &right, 8).unwrap();
        assert_eq!(new_left, new_left2);
        assert_eq!(new_right, new_right2);

        // Different number of rounds should produce different results
        let (new_left3, new_right3) = hasher.mimc_feistel(&left, &right, 10).unwrap();
        assert!(new_left != new_left3 || new_right != new_right3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_convenience_functions() {
        let left = FieldElement::from_u64(42);
        let right = FieldElement::from_u64(84);

        let result1 = mimc::hash_two(&left, &right).unwrap();
        let result2 = mimc::hash_two(&left, &right).unwrap();
        assert_eq!(result1, result2);

        let inputs = vec![left, right];
        let result3 = mimc::hash_many(&inputs).unwrap();

        let perm_result = mimc::permutation(&left).unwrap();
        let enc_result = mimc::encrypt(&left, &right).unwrap();

        // All should be different (generally)
        assert_ne!(result1, perm_result);
        assert_ne!(result1, enc_result);
        assert_ne!(perm_result, enc_result);
    }
}