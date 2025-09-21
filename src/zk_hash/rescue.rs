//! Rescue Hash Function
//!
//! Rescue is a hash function designed for use in zero-knowledge proofs.
//! It uses an SPN (substitution-permutation network) construction with
//! inverse operations to improve algebraic properties.

use crate::{field::FieldElement, traits::Field};
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Rescue hash function errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RescueError {
    /// Invalid input length
    InvalidInputLength,
    /// Invalid parameters
    InvalidParameters,
    /// Hash computation failed
    ComputationFailed,
}

impl fmt::Display for RescueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RescueError::InvalidInputLength => write!(f, "Invalid Rescue input length"),
            RescueError::InvalidParameters => write!(f, "Invalid Rescue parameters"),
            RescueError::ComputationFailed => write!(f, "Rescue computation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RescueError {}

/// Rescue parameters for different field types and rates
#[derive(Debug, Clone)]
pub struct RescueParameters {
    /// Rate (number of field elements absorbed per permutation)
    pub rate: usize,
    /// Capacity (security parameter)
    pub capacity: usize,
    /// Number of rounds
    pub rounds: usize,
    /// Alpha (forward S-box exponent)
    pub alpha: u64,
    /// Alpha inverse (backward S-box exponent)
    pub alpha_inv: u64,
    /// Round constants for forward direction
    #[cfg(feature = "alloc")]
    pub round_constants: Vec<FieldElement>,
    /// Round constants for inverse direction
    #[cfg(feature = "alloc")]
    pub round_constants_inv: Vec<FieldElement>,
    /// MDS matrix elements
    #[cfg(feature = "alloc")]
    pub mds_matrix: Vec<FieldElement>,
}

impl RescueParameters {
    /// Create Rescue parameters for rate 2, capacity 1 (BN254 field)
    #[cfg(feature = "alloc")]
    pub fn rate_2_capacity_1_bn254() -> Self {
        Self {
            rate: 2,
            capacity: 1,
            rounds: 12,
            alpha: 5,
            alpha_inv: Self::compute_alpha_inv(5),
            round_constants: Self::bn254_round_constants_forward(),
            round_constants_inv: Self::bn254_round_constants_inverse(),
            mds_matrix: Self::bn254_mds_matrix_3x3(),
        }
    }

    /// Create Rescue parameters for rate 4, capacity 1 (BN254 field)
    #[cfg(feature = "alloc")]
    pub fn rate_4_capacity_1_bn254() -> Self {
        Self {
            rate: 4,
            capacity: 1,
            rounds: 14,
            alpha: 5,
            alpha_inv: Self::compute_alpha_inv(5),
            round_constants: Self::bn254_round_constants_forward_5x5(),
            round_constants_inv: Self::bn254_round_constants_inverse_5x5(),
            mds_matrix: Self::bn254_mds_matrix_5x5(),
        }
    }

    /// Compute alpha inverse for BN254 field
    /// For BN254, alpha_inv of 5 is computed as the modular inverse
    fn compute_alpha_inv(alpha: u64) -> u64 {
        // Simplified computation - in practice, use proper modular inverse
        // For alpha = 5 in BN254 field, alpha_inv is a specific value
        match alpha {
            5 => 14119173304915053161u64, // Simplified placeholder
            _ => 1,
        }
    }

    /// BN254 forward round constants for 3x3 (rate 2, capacity 1)
    #[cfg(feature = "alloc")]
    fn bn254_round_constants_forward() -> Vec<FieldElement> {
        vec![
            FieldElement::from_u64(0x1c5d8f1b1b6d7a48),
            FieldElement::from_u64(0x2a3d2b5f2e4c8a67),
            FieldElement::from_u64(0x15e6c4f8a9b3d52e),
            FieldElement::from_u64(0x3f1a6e2d8c4b9e71),
            FieldElement::from_u64(0x2d7f9b1e5a8c6f42),
            FieldElement::from_u64(0x1a8e5d3f7b2c9461),
            FieldElement::from_u64(0x39c7f2e1d6a8b503),
            FieldElement::from_u64(0x2e4f8a6b9c1d5e37),
            FieldElement::from_u64(0x1d6b9e4f2a7c8531),
            FieldElement::from_u64(0x3b8f1c5e9d2a6471),
            FieldElement::from_u64(0x2f7a3e1b8c5d9260),
            FieldElement::from_u64(0x1e9c6f4a3b7d8504),
        ]
    }

    /// BN254 inverse round constants for 3x3
    #[cfg(feature = "alloc")]
    fn bn254_round_constants_inverse() -> Vec<FieldElement> {
        vec![
            FieldElement::from_u64(0x2a1f8e3d5b7c9406),
            FieldElement::from_u64(0x3c6b2f4e8a1d5973),
            FieldElement::from_u64(0x1f4d7a9e2c5b8631),
            FieldElement::from_u64(0x375e9c1f4a6d8b20),
            FieldElement::from_u64(0x2b8f5e3a1c7d9604),
            FieldElement::from_u64(0x1d5c8f2e4a7b9360),
            FieldElement::from_u64(0x3a7c1f5e8d2b6490),
            FieldElement::from_u64(0x2e1d6a9f3c5b8704),
            FieldElement::from_u64(0x1f8b5e2d7a3c9461),
            FieldElement::from_u64(0x39f2c6e1d5a8b047),
            FieldElement::from_u64(0x2d7e1a5f8c3b9620),
            FieldElement::from_u64(0x1c9f6e4a2d7b8503),
        ]
    }

    /// BN254 forward round constants for 5x5 (rate 4, capacity 1)
    #[cfg(feature = "alloc")]
    fn bn254_round_constants_forward_5x5() -> Vec<FieldElement> {
        vec![
            FieldElement::from_u64(0x1a2b3c4d5e6f7a80),
            FieldElement::from_u64(0x2b3c4d5e6f7a8091),
            FieldElement::from_u64(0x3c4d5e6f7a8091a2),
            FieldElement::from_u64(0x4d5e6f7a8091a2b3),
            FieldElement::from_u64(0x5e6f7a8091a2b3c4),
            // Add more constants for 14 rounds * 5 elements...
        ]
    }

    /// BN254 inverse round constants for 5x5
    #[cfg(feature = "alloc")]
    fn bn254_round_constants_inverse_5x5() -> Vec<FieldElement> {
        vec![
            FieldElement::from_u64(0x5e6f7a8091a2b3c4),
            FieldElement::from_u64(0x4d5e6f7a8091a2b3),
            FieldElement::from_u64(0x3c4d5e6f7a8091a2),
            FieldElement::from_u64(0x2b3c4d5e6f7a8091),
            FieldElement::from_u64(0x1a2b3c4d5e6f7a80),
            // Add more constants...
        ]
    }

    /// BN254 MDS matrix for 3x3
    #[cfg(feature = "alloc")]
    fn bn254_mds_matrix_3x3() -> Vec<FieldElement> {
        vec![
            FieldElement::from_u64(7), FieldElement::from_u64(23), FieldElement::from_u64(8),
            FieldElement::from_u64(47), FieldElement::from_u64(6), FieldElement::from_u64(58),
            FieldElement::from_u64(16), FieldElement::from_u64(39), FieldElement::from_u64(1),
        ]
    }

    /// BN254 MDS matrix for 5x5
    #[cfg(feature = "alloc")]
    fn bn254_mds_matrix_5x5() -> Vec<FieldElement> {
        vec![
            FieldElement::from_u64(7), FieldElement::from_u64(23), FieldElement::from_u64(8), FieldElement::from_u64(26), FieldElement::from_u64(13),
            FieldElement::from_u64(47), FieldElement::from_u64(6), FieldElement::from_u64(58), FieldElement::from_u64(21), FieldElement::from_u64(44),
            FieldElement::from_u64(16), FieldElement::from_u64(39), FieldElement::from_u64(1), FieldElement::from_u64(25), FieldElement::from_u64(42),
            FieldElement::from_u64(9), FieldElement::from_u64(27), FieldElement::from_u64(14), FieldElement::from_u64(31), FieldElement::from_u64(48),
            FieldElement::from_u64(33), FieldElement::from_u64(18), FieldElement::from_u64(35), FieldElement::from_u64(12), FieldElement::from_u64(29),
        ]
    }

    /// Get state width (rate + capacity)
    pub fn state_width(&self) -> usize {
        self.rate + self.capacity
    }
}

/// Rescue hash function implementation
pub struct RescueHasher {
    params: RescueParameters,
}

impl RescueHasher {
    /// Create a new Rescue hasher with given parameters
    pub fn new(params: RescueParameters) -> Self {
        Self { params }
    }

    /// Create a Rescue hasher for rate 2, capacity 1 (BN254)
    #[cfg(feature = "alloc")]
    pub fn rate_2_capacity_1_bn254() -> Self {
        Self::new(RescueParameters::rate_2_capacity_1_bn254())
    }

    /// Create a Rescue hasher for rate 4, capacity 1 (BN254)
    #[cfg(feature = "alloc")]
    pub fn rate_4_capacity_1_bn254() -> Self {
        Self::new(RescueParameters::rate_4_capacity_1_bn254())
    }

    /// Hash two field elements
    #[cfg(feature = "alloc")]
    pub fn hash_two(&self, left: &FieldElement, right: &FieldElement) -> Result<FieldElement, RescueError> {
        if self.params.rate < 2 {
            return Err(RescueError::InvalidParameters);
        }

        let mut state = vec![FieldElement::zero(); self.params.state_width()];
        state[0] = *left;
        state[1] = *right;

        self.rescue_permutation(&mut state)?;
        Ok(state[0])
    }

    /// Hash multiple field elements using sponge construction
    #[cfg(feature = "alloc")]
    pub fn hash_many(&self, inputs: &[FieldElement]) -> Result<FieldElement, RescueError> {
        let mut state = vec![FieldElement::zero(); self.params.state_width()];

        // Absorb phase
        for chunk in inputs.chunks(self.params.rate) {
            for (i, input) in chunk.iter().enumerate() {
                state[i] = state[i] + *input;
            }
            self.rescue_permutation(&mut state)?;
        }

        // Squeeze phase
        Ok(state[0])
    }

    /// Rescue sponge for variable-length output
    #[cfg(feature = "alloc")]
    pub fn sponge(&self, inputs: &[FieldElement], output_len: usize) -> Result<Vec<FieldElement>, RescueError> {
        let mut state = vec![FieldElement::zero(); self.params.state_width()];

        // Absorb phase
        for chunk in inputs.chunks(self.params.rate) {
            for (i, input) in chunk.iter().enumerate() {
                state[i] = state[i] + *input;
            }
            self.rescue_permutation(&mut state)?;
        }

        // Squeeze phase
        let mut output = Vec::with_capacity(output_len);
        let mut remaining = output_len;

        while remaining > 0 {
            let to_squeeze = core::cmp::min(remaining, self.params.rate);
            output.extend_from_slice(&state[..to_squeeze]);
            remaining -= to_squeeze;

            if remaining > 0 {
                self.rescue_permutation(&mut state)?;
            }
        }

        Ok(output)
    }

    /// Perform the Rescue permutation
    #[cfg(feature = "alloc")]
    fn rescue_permutation(&self, state: &mut [FieldElement]) -> Result<(), RescueError> {
        if state.len() != self.params.state_width() {
            return Err(RescueError::InvalidParameters);
        }

        let state_width = self.params.state_width();

        for round in 0..self.params.rounds {
            let round_const_offset = round * state_width * 2; // 2 for forward and inverse

            // Forward half-round
            self.add_round_constants(state, &self.params.round_constants, round_const_offset)?;
            self.forward_s_box(state);
            self.linear_layer(state)?;

            // Backward half-round
            self.add_round_constants(state, &self.params.round_constants_inv, round_const_offset + state_width)?;
            self.inverse_s_box(state);
            self.linear_layer(state)?;
        }

        Ok(())
    }

    /// Add round constants to state
    #[cfg(feature = "alloc")]
    fn add_round_constants(
        &self,
        state: &mut [FieldElement],
        constants: &[FieldElement],
        offset: usize,
    ) -> Result<(), RescueError> {
        let state_width = state.len();
        if offset + state_width > constants.len() {
            return Err(RescueError::InvalidParameters);
        }

        for i in 0..state_width {
            state[i] = state[i] + constants[offset + i];
        }

        Ok(())
    }

    /// Apply forward S-box (x^alpha)
    fn forward_s_box(&self, state: &mut [FieldElement]) {
        for element in state.iter_mut() {
            *element = element.pow(self.params.alpha);
        }
    }

    /// Apply inverse S-box (x^alpha_inv)
    fn inverse_s_box(&self, state: &mut [FieldElement]) {
        for element in state.iter_mut() {
            *element = element.pow(self.params.alpha_inv);
        }
    }

    /// Apply linear layer (MDS matrix multiplication)
    #[cfg(feature = "alloc")]
    fn linear_layer(&self, state: &mut [FieldElement]) -> Result<(), RescueError> {
        let width = self.params.state_width();
        if self.params.mds_matrix.len() != width * width {
            return Err(RescueError::InvalidParameters);
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

/// Convenience functions for common Rescue operations
#[cfg(feature = "alloc")]
pub mod rescue {
    use super::*;

    /// Hash two field elements using Rescue
    pub fn hash_two(left: &FieldElement, right: &FieldElement) -> Result<FieldElement, RescueError> {
        let hasher = RescueHasher::rate_2_capacity_1_bn254();
        hasher.hash_two(left, right)
    }

    /// Hash multiple field elements using Rescue
    pub fn hash_many(inputs: &[FieldElement]) -> Result<FieldElement, RescueError> {
        let hasher = RescueHasher::rate_4_capacity_1_bn254();
        hasher.hash_many(inputs)
    }

    /// Rescue sponge with variable output length
    pub fn sponge(inputs: &[FieldElement], output_len: usize) -> Result<Vec<FieldElement>, RescueError> {
        let hasher = RescueHasher::rate_4_capacity_1_bn254();
        hasher.sponge(inputs, output_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rescue_parameters() {
        let params = RescueParameters::rate_2_capacity_1_bn254();
        assert_eq!(params.rate, 2);
        assert_eq!(params.capacity, 1);
        assert_eq!(params.state_width(), 3);
        assert_eq!(params.alpha, 5);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_rescue_hash_two() {
        let hasher = RescueHasher::rate_2_capacity_1_bn254();
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
    fn test_rescue_hash_many() {
        let hasher = RescueHasher::rate_4_capacity_1_bn254();
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
    fn test_rescue_sponge() {
        let hasher = RescueHasher::rate_4_capacity_1_bn254();
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

        let result1 = rescue::hash_two(&left, &right).unwrap();
        let result2 = rescue::hash_two(&left, &right).unwrap();
        assert_eq!(result1, result2);

        let inputs = vec![left, right];
        let result3 = rescue::hash_many(&inputs).unwrap();

        // Different hash functions should generally produce different results
        assert_ne!(result1, result3);
    }
}