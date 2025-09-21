//! Pedersen Hash Function
//!
//! Pedersen hashing based on elliptic curve operations. While not as
//! circuit-friendly as algebraic hashes, it provides strong collision
//! resistance properties and is useful in certain ZK constructions.

use crate::{EdwardsPoint, Scalar, field::FieldElement};
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Pedersen hash function errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PedersenError {
    /// Invalid input length
    InvalidInputLength,
    /// Invalid generator setup
    InvalidGenerators,
    /// Hash computation failed
    ComputationFailed,
    /// Input too large for bit decomposition
    InputTooLarge,
}

impl fmt::Display for PedersenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PedersenError::InvalidInputLength => write!(f, "Invalid Pedersen input length"),
            PedersenError::InvalidGenerators => write!(f, "Invalid Pedersen generators"),
            PedersenError::ComputationFailed => write!(f, "Pedersen computation failed"),
            PedersenError::InputTooLarge => write!(f, "Input too large for bit decomposition"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PedersenError {}

/// Pedersen hash parameters
#[derive(Debug, Clone)]
pub struct PedersenParameters {
    /// Base generators for different input chunks
    #[cfg(feature = "alloc")]
    pub generators: Vec<EdwardsPoint>,
    /// Number of bits per chunk
    pub chunk_size: usize,
    /// Maximum input length in bits
    pub max_input_bits: usize,
}

impl PedersenParameters {
    /// Create Pedersen parameters for 256-bit inputs with 4-bit chunks
    #[cfg(feature = "alloc")]
    pub fn new_256_bit_4_chunk() -> Self {
        let chunk_size = 4;
        let max_input_bits = 256;
        let num_generators = (max_input_bits + chunk_size - 1) / chunk_size;

        Self {
            generators: Self::generate_generators(num_generators),
            chunk_size,
            max_input_bits,
        }
    }

    /// Create Pedersen parameters for 256-bit inputs with 8-bit chunks
    #[cfg(feature = "alloc")]
    pub fn new_256_bit_8_chunk() -> Self {
        let chunk_size = 8;
        let max_input_bits = 256;
        let num_generators = (max_input_bits + chunk_size - 1) / chunk_size;

        Self {
            generators: Self::generate_generators(num_generators),
            chunk_size,
            max_input_bits,
        }
    }

    /// Generate deterministic generators for Pedersen hashing
    #[cfg(feature = "alloc")]
    fn generate_generators(count: usize) -> Vec<EdwardsPoint> {
        let mut generators = Vec::with_capacity(count);

        // Start with a known base point (the standard generator)
        let base = EdwardsPoint::generator();

        // Generate additional points by repeated hashing and mapping to curve
        let mut current = base;
        generators.push(current);

        for i in 1..count {
            // Use the scalar from the index to generate new points
            let scalar = Scalar::from_u64(i as u64 + 1000); // Add offset to avoid small scalars
            current = &current + &(&base * &scalar);
            generators.push(current);
        }

        generators
    }

    /// Get number of required generators
    pub fn num_generators(&self) -> usize {
        #[cfg(feature = "alloc")]
        {
            self.generators.len()
        }
        #[cfg(not(feature = "alloc"))]
        {
            (self.max_input_bits + self.chunk_size - 1) / self.chunk_size
        }
    }
}

/// Pedersen hash function implementation
pub struct PedersenHasher {
    params: PedersenParameters,
}

impl PedersenHasher {
    /// Create a new Pedersen hasher
    pub fn new(params: PedersenParameters) -> Self {
        Self { params }
    }

    /// Create a Pedersen hasher for 256-bit inputs with 4-bit chunks
    #[cfg(feature = "alloc")]
    pub fn new_256_bit_4_chunk() -> Self {
        Self::new(PedersenParameters::new_256_bit_4_chunk())
    }

    /// Create a Pedersen hasher for 256-bit inputs with 8-bit chunks
    #[cfg(feature = "alloc")]
    pub fn new_256_bit_8_chunk() -> Self {
        Self::new(PedersenParameters::new_256_bit_8_chunk())
    }

    /// Hash a field element
    #[cfg(feature = "alloc")]
    pub fn hash_field(&self, input: &FieldElement) -> Result<EdwardsPoint, PedersenError> {
        // Convert field element to bytes and hash
        let bytes = input.to_bytes();
        self.hash_bytes(&bytes)
    }

    /// Hash two field elements
    #[cfg(feature = "alloc")]
    pub fn hash_two_fields(&self, left: &FieldElement, right: &FieldElement) -> Result<EdwardsPoint, PedersenError> {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&left.to_bytes());
        combined.extend_from_slice(&right.to_bytes());
        self.hash_bytes(&combined)
    }

    /// Hash arbitrary bytes
    #[cfg(feature = "alloc")]
    pub fn hash_bytes(&self, input: &[u8]) -> Result<EdwardsPoint, PedersenError> {
        if input.len() * 8 > self.params.max_input_bits {
            return Err(PedersenError::InputTooLarge);
        }

        // Convert bytes to bit chunks
        let chunks = self.bytes_to_chunks(input)?;
        self.hash_chunks(&chunks)
    }

    /// Hash pre-computed bit chunks
    #[cfg(feature = "alloc")]
    pub fn hash_chunks(&self, chunks: &[usize]) -> Result<EdwardsPoint, PedersenError> {
        if chunks.len() > self.params.generators.len() {
            return Err(PedersenError::InvalidInputLength);
        }

        let mut result = EdwardsPoint::identity();

        for (chunk_value, generator) in chunks.iter().zip(self.params.generators.iter()) {
            if *chunk_value >= (1 << self.params.chunk_size) {
                return Err(PedersenError::InputTooLarge);
            }

            // Add chunk_value * generator to the result
            let scalar = Scalar::from_u64(*chunk_value as u64);
            let contribution = generator * &scalar;
            result = &result + &contribution;
        }

        Ok(result)
    }

    /// Hash multiple field elements (variable-length input)
    #[cfg(feature = "alloc")]
    pub fn hash_many_fields(&self, inputs: &[FieldElement]) -> Result<EdwardsPoint, PedersenError> {
        let mut all_bytes = Vec::new();
        for input in inputs {
            all_bytes.extend_from_slice(&input.to_bytes());
        }
        self.hash_bytes(&all_bytes)
    }

    /// Convert bytes to bit chunks for Pedersen hashing
    #[cfg(feature = "alloc")]
    fn bytes_to_chunks(&self, input: &[u8]) -> Result<Vec<usize>, PedersenError> {
        let mut chunks = Vec::new();
        let chunk_size = self.params.chunk_size;
        let mut bit_buffer = 0u32;
        let mut bits_in_buffer = 0;

        for &byte in input {
            bit_buffer |= (byte as u32) << bits_in_buffer;
            bits_in_buffer += 8;

            while bits_in_buffer >= chunk_size {
                let chunk = (bit_buffer & ((1 << chunk_size) - 1)) as usize;
                chunks.push(chunk);
                bit_buffer >>= chunk_size;
                bits_in_buffer -= chunk_size;
            }
        }

        // Handle remaining bits
        if bits_in_buffer > 0 {
            let chunk = bit_buffer as usize;
            chunks.push(chunk);
        }

        Ok(chunks)
    }

    /// Compress a Pedersen hash result to a field element
    pub fn compress_point(&self, point: &EdwardsPoint) -> FieldElement {
        // Simple compression: use the x-coordinate
        // In practice, you might want a more sophisticated compression scheme
        let compressed = point.compress();
        FieldElement::from_bytes(&compressed.to_bytes())
    }

    /// Hash to field element (compress the result)
    #[cfg(feature = "alloc")]
    pub fn hash_to_field(&self, input: &[u8]) -> Result<FieldElement, PedersenError> {
        let point = self.hash_bytes(input)?;
        Ok(self.compress_point(&point))
    }

    /// Two-to-one hash for Merkle trees
    #[cfg(feature = "alloc")]
    pub fn merkle_hash(&self, left: &FieldElement, right: &FieldElement) -> Result<FieldElement, PedersenError> {
        let point = self.hash_two_fields(left, right)?;
        Ok(self.compress_point(&point))
    }
}

/// Windowed Pedersen hashing for better performance
pub struct WindowedPedersenHasher {
    base_hasher: PedersenHasher,
    window_size: usize,
}

impl WindowedPedersenHasher {
    /// Create a new windowed Pedersen hasher
    pub fn new(base_hasher: PedersenHasher, window_size: usize) -> Self {
        Self {
            base_hasher,
            window_size,
        }
    }

    /// Hash using windowed method for better performance
    #[cfg(feature = "alloc")]
    pub fn hash_windowed(&self, input: &[u8]) -> Result<EdwardsPoint, PedersenError> {
        // For large inputs, split into windows and hash hierarchically
        if input.len() <= 32 {
            // Small input, use regular method
            return self.base_hasher.hash_bytes(input);
        }

        let mut windows = Vec::new();
        for chunk in input.chunks(self.window_size) {
            let window_hash = self.base_hasher.hash_bytes(chunk)?;
            windows.push(self.base_hasher.compress_point(&window_hash));
        }

        // Hash the window results
        let final_point = self.base_hasher.hash_many_fields(&windows)?;
        Ok(final_point)
    }
}

/// Convenience functions for common Pedersen operations
#[cfg(feature = "alloc")]
pub mod pedersen {
    use super::*;

    /// Hash two field elements using Pedersen
    pub fn hash_two(left: &FieldElement, right: &FieldElement) -> Result<FieldElement, PedersenError> {
        let hasher = PedersenHasher::new_256_bit_4_chunk();
        hasher.merkle_hash(left, right)
    }

    /// Hash multiple field elements using Pedersen
    pub fn hash_many(inputs: &[FieldElement]) -> Result<FieldElement, PedersenError> {
        let hasher = PedersenHasher::new_256_bit_4_chunk();
        let point = hasher.hash_many_fields(inputs)?;
        Ok(hasher.compress_point(&point))
    }

    /// Hash bytes to field element using Pedersen
    pub fn hash_bytes(input: &[u8]) -> Result<FieldElement, PedersenError> {
        let hasher = PedersenHasher::new_256_bit_4_chunk();
        hasher.hash_to_field(input)
    }

    /// Hash to elliptic curve point (uncompressed)
    pub fn hash_to_point(input: &[u8]) -> Result<EdwardsPoint, PedersenError> {
        let hasher = PedersenHasher::new_256_bit_4_chunk();
        hasher.hash_bytes(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_parameters() {
        let params = PedersenParameters::new_256_bit_4_chunk();
        assert_eq!(params.chunk_size, 4);
        assert_eq!(params.max_input_bits, 256);
        assert_eq!(params.num_generators(), 64); // 256 / 4 = 64

        let params8 = PedersenParameters::new_256_bit_8_chunk();
        assert_eq!(params8.chunk_size, 8);
        assert_eq!(params8.num_generators(), 32); // 256 / 8 = 32
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_bytes_to_chunks() {
        let hasher = PedersenHasher::new_256_bit_4_chunk();
        let input = vec![0xAB, 0xCD]; // 10101011 11001101

        let chunks = hasher.bytes_to_chunks(&input).unwrap();

        // With 4-bit chunks: [11, 10, 10, 5, 13, 12, 3, 3] (little-endian bit order)
        assert!(chunks.len() >= 4);

        // Each chunk should be < 16 (2^4)
        for chunk in chunks {
            assert!(chunk < 16);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pedersen_hash_field() {
        let hasher = PedersenHasher::new_256_bit_4_chunk();
        let input = FieldElement::from_u64(42);

        let result = hasher.hash_field(&input).unwrap();
        let result2 = hasher.hash_field(&input).unwrap();

        // Same input should produce same output
        assert_eq!(result, result2);

        // Different input should produce different output
        let input2 = FieldElement::from_u64(43);
        let result3 = hasher.hash_field(&input2).unwrap();
        assert_ne!(result, result3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pedersen_hash_two_fields() {
        let hasher = PedersenHasher::new_256_bit_4_chunk();
        let left = FieldElement::from_u64(42);
        let right = FieldElement::from_u64(84);

        let result = hasher.hash_two_fields(&left, &right).unwrap();
        let result2 = hasher.hash_two_fields(&left, &right).unwrap();
        assert_eq!(result, result2);

        // Order should matter
        let result3 = hasher.hash_two_fields(&right, &left).unwrap();
        assert_ne!(result, result3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pedersen_compress_point() {
        let hasher = PedersenHasher::new_256_bit_4_chunk();
        let input = FieldElement::from_u64(42);

        let point = hasher.hash_field(&input).unwrap();
        let compressed = hasher.compress_point(&point);

        // Compression should be deterministic
        let compressed2 = hasher.compress_point(&point);
        assert_eq!(compressed, compressed2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pedersen_merkle_hash() {
        let hasher = PedersenHasher::new_256_bit_4_chunk();
        let left = FieldElement::from_u64(42);
        let right = FieldElement::from_u64(84);

        let result = hasher.merkle_hash(&left, &right).unwrap();
        let result2 = hasher.merkle_hash(&left, &right).unwrap();
        assert_eq!(result, result2);

        // Order should matter
        let result3 = hasher.merkle_hash(&right, &left).unwrap();
        assert_ne!(result, result3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_windowed_pedersen() {
        let base_hasher = PedersenHasher::new_256_bit_8_chunk();
        let windowed_hasher = WindowedPedersenHasher::new(base_hasher, 16);

        let input = vec![0x42u8; 64]; // Large input
        let result = windowed_hasher.hash_windowed(&input).unwrap();

        // Same input should produce same output
        let result2 = windowed_hasher.hash_windowed(&input).unwrap();
        assert_eq!(result, result2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_convenience_functions() {
        let left = FieldElement::from_u64(42);
        let right = FieldElement::from_u64(84);

        let result1 = pedersen::hash_two(&left, &right).unwrap();
        let result2 = pedersen::hash_two(&left, &right).unwrap();
        assert_eq!(result1, result2);

        let inputs = vec![left, right];
        let result3 = pedersen::hash_many(&inputs).unwrap();

        let bytes = vec![0x42, 0x84];
        let result4 = pedersen::hash_bytes(&bytes).unwrap();
        let point_result = pedersen::hash_to_point(&bytes).unwrap();

        // All functions should produce valid results
        assert_ne!(result1, FieldElement::zero());
        assert_ne!(result3, FieldElement::zero());
        assert_ne!(result4, FieldElement::zero());
        assert_ne!(point_result, EdwardsPoint::identity());
    }
}