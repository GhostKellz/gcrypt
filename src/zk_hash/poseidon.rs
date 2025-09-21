//! Poseidon Hash Function
//!
//! Poseidon is a family of hash functions designed to be very efficient
//! as a constraint in SNARKs, STARKs, and other arithmetic circuits.
//! It uses a sponge construction with a substitution-permutation network.

use crate::{field::FieldElement, traits::Field};
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Poseidon hash function errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoseidonError {
    /// Invalid input length
    InvalidInputLength,
    /// Invalid parameters
    InvalidParameters,
    /// Hash computation failed
    ComputationFailed,
}

impl fmt::Display for PoseidonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoseidonError::InvalidInputLength => write!(f, "Invalid Poseidon input length"),
            PoseidonError::InvalidParameters => write!(f, "Invalid Poseidon parameters"),
            PoseidonError::ComputationFailed => write!(f, "Poseidon computation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PoseidonError {}

/// Poseidon parameters for different field types and widths
#[derive(Debug, Clone)]
pub struct PoseidonParameters {
    /// Width of the permutation (t)
    pub width: usize,
    /// Number of full rounds
    pub full_rounds: usize,
    /// Number of partial rounds
    pub partial_rounds: usize,
    /// Round constants
    #[cfg(feature = "alloc")]
    pub round_constants: Vec<FieldElement>,
    /// MDS matrix elements (flattened)
    #[cfg(feature = "alloc")]
    pub mds_matrix: Vec<FieldElement>,
    /// Alpha (S-box exponent)
    pub alpha: u64,
}

impl PoseidonParameters {
    /// Create Poseidon parameters for width 3 (BN254 field)
    #[cfg(feature = "alloc")]
    pub fn width_3_bn254() -> Self {
        Self {
            width: 3,
            full_rounds: 8,
            partial_rounds: 57,
            round_constants: Self::bn254_round_constants_width_3(),
            mds_matrix: Self::bn254_mds_matrix_width_3(),
            alpha: 5,
        }
    }

    /// Create Poseidon parameters for width 5 (BN254 field)
    #[cfg(feature = "alloc")]
    pub fn width_5_bn254() -> Self {
        Self {
            width: 5,
            full_rounds: 8,
            partial_rounds: 60,
            round_constants: Self::bn254_round_constants_width_5(),
            mds_matrix: Self::bn254_mds_matrix_width_5(),
            alpha: 5,
        }
    }

    /// BN254 round constants for width 3
    #[cfg(feature = "alloc")]
    fn bn254_round_constants_width_3() -> Vec<FieldElement> {
        // Simplified constants for demonstration
        // In production, these should be generated using the official Poseidon algorithm
        vec![
            FieldElement::from_u64(0x109b7f411ba0e4c9),
            FieldElement::from_u64(0x16ed41e13bb9c0c6),
            FieldElement::from_u64(0x2b90bba00fca0589),
            FieldElement::from_u64(0x0101c8acd45ad15),
            FieldElement::from_u64(0x27fb79f9a3ce5b66),
            FieldElement::from_u64(0x108511ae3d60ba70),
            FieldElement::from_u64(0x2969f27eed31a480),
            FieldElement::from_u64(0xe50d606a0d9a0c0),
            // Add more constants as needed...
        ]
    }

    /// BN254 round constants for width 5
    #[cfg(feature = "alloc")]
    fn bn254_round_constants_width_5() -> Vec<FieldElement> {
        // Simplified constants for demonstration
        vec![
            FieldElement::from_u64(0x185aaeee45a6f5d),
            FieldElement::from_u64(0x6b1a1e2ce28c580),
            FieldElement::from_u64(0x2f08e374dd9bc4e),
            FieldElement::from_u64(0x2a20d47d4d59e7b),
            FieldElement::from_u64(0x19b7ad79b38fcc0),
            // Add more constants as needed...
        ]
    }

    /// BN254 MDS matrix for width 3
    #[cfg(feature = "alloc")]
    fn bn254_mds_matrix_width_3() -> Vec<FieldElement> {
        vec![
            FieldElement::from_u64(1), FieldElement::from_u64(1), FieldElement::from_u64(1),
            FieldElement::from_u64(1), FieldElement::from_u64(2), FieldElement::from_u64(3),
            FieldElement::from_u64(1), FieldElement::from_u64(3), FieldElement::from_u64(6),
        ]
    }

    /// BN254 MDS matrix for width 5
    #[cfg(feature = "alloc")]
    fn bn254_mds_matrix_width_5() -> Vec<FieldElement> {
        vec![
            FieldElement::from_u64(1), FieldElement::from_u64(1), FieldElement::from_u64(1), FieldElement::from_u64(1), FieldElement::from_u64(1),
            FieldElement::from_u64(1), FieldElement::from_u64(2), FieldElement::from_u64(3), FieldElement::from_u64(4), FieldElement::from_u64(5),
            FieldElement::from_u64(1), FieldElement::from_u64(3), FieldElement::from_u64(6), FieldElement::from_u64(10), FieldElement::from_u64(15),
            FieldElement::from_u64(1), FieldElement::from_u64(4), FieldElement::from_u64(10), FieldElement::from_u64(20), FieldElement::from_u64(35),
            FieldElement::from_u64(1), FieldElement::from_u64(5), FieldElement::from_u64(15), FieldElement::from_u64(35), FieldElement::from_u64(70),
        ]
    }
}

/// Poseidon hash function implementation
pub struct PoseidonHasher {
    params: PoseidonParameters,
}

impl PoseidonHasher {
    /// Create a new Poseidon hasher with given parameters
    pub fn new(params: PoseidonParameters) -> Self {
        Self { params }
    }

    /// Create a Poseidon hasher for width 3 (BN254)
    #[cfg(feature = "alloc")]
    pub fn width_3_bn254() -> Self {
        Self::new(PoseidonParameters::width_3_bn254())
    }

    /// Create a Poseidon hasher for width 5 (BN254)
    #[cfg(feature = "alloc")]
    pub fn width_5_bn254() -> Self {
        Self::new(PoseidonParameters::width_5_bn254())
    }

    /// Hash a single field element
    pub fn hash_single(&self, input: &FieldElement) -> Result<FieldElement, PoseidonError> {
        let mut state = vec![FieldElement::zero(); self.params.width];
        state[0] = *input;
        self.permute(&mut state)?;
        Ok(state[0])
    }

    /// Hash two field elements
    #[cfg(feature = "alloc")]
    pub fn hash_two(&self, left: &FieldElement, right: &FieldElement) -> Result<FieldElement, PoseidonError> {
        if self.params.width < 3 {
            return Err(PoseidonError::InvalidParameters);
        }

        let mut state = vec![FieldElement::zero(); self.params.width];
        state[0] = *left;
        state[1] = *right;
        self.permute(&mut state)?;
        Ok(state[0])
    }

    /// Hash multiple field elements
    #[cfg(feature = "alloc")]
    pub fn hash_many(&self, inputs: &[FieldElement]) -> Result<FieldElement, PoseidonError> {
        let rate = self.params.width - 1; // Capacity is 1
        let mut state = vec![FieldElement::zero(); self.params.width];

        // Absorb phase
        for chunk in inputs.chunks(rate) {
            for (i, input) in chunk.iter().enumerate() {
                state[i] = state[i] + *input;
            }
            self.permute(&mut state)?;
        }

        // Squeeze phase (single output)
        Ok(state[0])
    }

    /// Poseidon sponge for variable-length output
    #[cfg(feature = "alloc")]
    pub fn sponge(&self, inputs: &[FieldElement], output_len: usize) -> Result<Vec<FieldElement>, PoseidonError> {
        let rate = self.params.width - 1;
        let mut state = vec![FieldElement::zero(); self.params.width];

        // Absorb phase
        for chunk in inputs.chunks(rate) {
            for (i, input) in chunk.iter().enumerate() {
                state[i] = state[i] + *input;
            }
            self.permute(&mut state)?;
        }

        // Squeeze phase
        let mut output = Vec::with_capacity(output_len);
        let mut remaining = output_len;

        while remaining > 0 {
            let to_squeeze = core::cmp::min(remaining, rate);
            output.extend_from_slice(&state[..to_squeeze]);
            remaining -= to_squeeze;

            if remaining > 0 {
                self.permute(&mut state)?;
            }
        }

        Ok(output)
    }

    /// Perform the Poseidon permutation on the state
    #[cfg(feature = "alloc")]
    fn permute(&self, state: &mut [FieldElement]) -> Result<(), PoseidonError> {
        if state.len() != self.params.width {
            return Err(PoseidonError::InvalidParameters);
        }

        let half_full_rounds = self.params.full_rounds / 2;
        let mut round_const_offset = 0;

        // First half of full rounds
        for _ in 0..half_full_rounds {
            self.add_round_constants(state, round_const_offset)?;
            self.s_box_full(state);
            self.linear_layer(state)?;
            round_const_offset += self.params.width;
        }

        // Partial rounds
        for _ in 0..self.params.partial_rounds {
            self.add_round_constants(state, round_const_offset)?;
            self.s_box_partial(state);
            self.linear_layer(state)?;
            round_const_offset += self.params.width;
        }

        // Second half of full rounds
        for _ in 0..half_full_rounds {
            self.add_round_constants(state, round_const_offset)?;
            self.s_box_full(state);
            self.linear_layer(state)?;
            round_const_offset += self.params.width;
        }

        Ok(())
    }

    /// Add round constants to the state
    #[cfg(feature = "alloc")]
    fn add_round_constants(&self, state: &mut [FieldElement], offset: usize) -> Result<(), PoseidonError> {
        if offset + self.params.width > self.params.round_constants.len() {
            return Err(PoseidonError::InvalidParameters);
        }

        for i in 0..self.params.width {
            state[i] = state[i] + self.params.round_constants[offset + i];
        }

        Ok(())
    }

    /// Apply S-box to all state elements (full round)
    fn s_box_full(&self, state: &mut [FieldElement]) {
        for element in state.iter_mut() {
            *element = element.pow(self.params.alpha);
        }
    }

    /// Apply S-box to first state element only (partial round)
    fn s_box_partial(&self, state: &mut [FieldElement]) {
        state[0] = state[0].pow(self.params.alpha);
    }

    /// Apply linear layer (MDS matrix multiplication)
    #[cfg(feature = "alloc")]
    fn linear_layer(&self, state: &mut [FieldElement]) -> Result<(), PoseidonError> {
        let width = self.params.width;
        if self.params.mds_matrix.len() != width * width {
            return Err(PoseidonError::InvalidParameters);
        }

        let mut new_state = vec![FieldElement::zero(); width];

        for i in 0..width {
            for j in 0..width {
                let matrix_element = self.params.mds_matrix[i * width + j];
                new_state[i] = new_state[i] + (matrix_element * state[j]);
            }
        }

        state.copy_from_slice(&new_state);
        Ok(())
    }
}

/// Convenience functions for common Poseidon operations
#[cfg(feature = "alloc")]
pub mod poseidon {
    use super::*;

    /// Hash two field elements using Poseidon
    pub fn hash_two(left: &FieldElement, right: &FieldElement) -> Result<FieldElement, PoseidonError> {
        let hasher = PoseidonHasher::width_3_bn254();
        hasher.hash_two(left, right)
    }

    /// Hash multiple field elements using Poseidon
    pub fn hash_many(inputs: &[FieldElement]) -> Result<FieldElement, PoseidonError> {
        let hasher = PoseidonHasher::width_5_bn254();
        hasher.hash_many(inputs)
    }

    /// Poseidon sponge with variable output length
    pub fn sponge(inputs: &[FieldElement], output_len: usize) -> Result<Vec<FieldElement>, PoseidonError> {
        let hasher = PoseidonHasher::width_5_bn254();
        hasher.sponge(inputs, output_len)
    }

    /// Hash a single field element
    pub fn hash_single(input: &FieldElement) -> Result<FieldElement, PoseidonError> {
        let hasher = PoseidonHasher::width_3_bn254();
        hasher.hash_single(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_parameters() {
        let params = PoseidonParameters::width_3_bn254();
        assert_eq!(params.width, 3);
        assert_eq!(params.full_rounds, 8);
        assert_eq!(params.alpha, 5);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_poseidon_hash_single() {
        let hasher = PoseidonHasher::width_3_bn254();
        let input = FieldElement::from_u64(42);
        let result = hasher.hash_single(&input).unwrap();

        // Hash should be deterministic
        let result2 = hasher.hash_single(&input).unwrap();
        assert_eq!(result, result2);

        // Different inputs should produce different hashes
        let input2 = FieldElement::from_u64(43);
        let result3 = hasher.hash_single(&input2).unwrap();
        assert_ne!(result, result3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_poseidon_hash_two() {
        let hasher = PoseidonHasher::width_3_bn254();
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
    fn test_poseidon_hash_many() {
        let hasher = PoseidonHasher::width_5_bn254();
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
    fn test_poseidon_sponge() {
        let hasher = PoseidonHasher::width_5_bn254();
        let inputs = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
        ];

        let output = hasher.sponge(&inputs, 3).unwrap();
        assert_eq!(output.len(), 3);

        // Same inputs should produce same output
        let output2 = hasher.sponge(&inputs, 3).unwrap();
        assert_eq!(output, output2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_convenience_functions() {
        let left = FieldElement::from_u64(42);
        let right = FieldElement::from_u64(84);

        let result1 = poseidon::hash_two(&left, &right).unwrap();
        let result2 = poseidon::hash_two(&left, &right).unwrap();
        assert_eq!(result1, result2);

        let inputs = vec![left, right];
        let result3 = poseidon::hash_many(&inputs).unwrap();

        // Different hash functions should generally produce different results
        // (though this isn't guaranteed due to the simplified implementation)
        let single_result = poseidon::hash_single(&left).unwrap();
        assert_ne!(single_result, result1); // Usually different
    }
}