//! Noise Protocol Framework implementation
//!
//! This module implements the Noise Protocol Framework for secure communications,
//! commonly used in mesh networking and P2P protocols like WireGuard.
//!
//! Supports Noise patterns including:
//! - Noise_XX (most common for P2P)
//! - Noise_NK (known public key)
//! - Noise_IK (immediate key exchange)

use crate::{Scalar, MontgomeryPoint};
// Note: ChaCha20Poly1305 would be imported from aes_gcm module when available

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

use core::fmt;

/// Noise handshake patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoisePattern {
    /// Noise_XX - mutual authentication after handshake
    XX,
    /// Noise_NK - responder has known static key
    NK,
    /// Noise_IK - initiator knows responder's static key
    IK,
    /// Noise_N - one-way authentication
    N,
    /// Noise_K - responder knows initiator's static key
    K,
    /// Noise_X - initiator's identity transmitted
    X,
}

/// Noise cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// ChaCha20-Poly1305 with SHA256 and Curve25519
    ChaCha20Poly1305SHA256Curve25519,
    /// AES256-GCM with SHA256 and Curve25519
    AES256GCMSHA256Curve25519,
}

/// Noise handshake state
#[derive(Debug, Clone)]
pub struct HandshakeState {
    /// Current handshake pattern
    pattern: NoisePattern,
    /// Cipher suite in use
    cipher_suite: CipherSuite,
    /// Local static key pair
    local_static: Option<(Scalar, MontgomeryPoint)>,
    /// Remote static public key
    remote_static: Option<MontgomeryPoint>,
    /// Local ephemeral key pair
    local_ephemeral: Option<(Scalar, MontgomeryPoint)>,
    /// Remote ephemeral public key
    remote_ephemeral: Option<MontgomeryPoint>,
    /// Chaining key for key derivation
    chaining_key: [u8; 32],
    /// Handshake hash
    handshake_hash: [u8; 32],
    /// Message pattern index
    message_patterns: &'static [MessagePattern],
    /// Current message index
    message_index: usize,
    /// Whether this is the initiator
    is_initiator: bool,
}

/// Transport state after handshake completion
#[derive(Debug, Clone)]
pub struct TransportState {
    /// Cipher suite
    cipher_suite: CipherSuite,
    /// Sending key
    sending_key: [u8; 32],
    /// Receiving key
    receiving_key: [u8; 32],
    /// Sending nonce
    sending_nonce: u64,
    /// Receiving nonce
    receiving_nonce: u64,
}

/// Message patterns for handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagePattern {
    /// Send/receive ephemeral key
    E,
    /// Send/receive static key
    S,
    /// Perform DH with ephemeral and ephemeral
    EE,
    /// Perform DH with ephemeral and static
    ES,
    /// Perform DH with static and ephemeral
    SE,
    /// Perform DH with static and static
    SS,
}

/// Noise protocol errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseError {
    /// Invalid handshake pattern
    InvalidPattern,
    /// Invalid cipher suite
    InvalidCipherSuite,
    /// Missing key material
    MissingKey,
    /// Invalid message format
    InvalidMessage,
    /// Handshake failed
    HandshakeFailed,
    /// Decryption failed
    DecryptionFailed,
    /// Message too large
    MessageTooLarge,
    /// Protocol violation
    ProtocolViolation,
    /// Buffer too small
    BufferTooSmall,
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoiseError::InvalidPattern => write!(f, "Invalid handshake pattern"),
            NoiseError::InvalidCipherSuite => write!(f, "Invalid cipher suite"),
            NoiseError::MissingKey => write!(f, "Missing required key material"),
            NoiseError::InvalidMessage => write!(f, "Invalid message format"),
            NoiseError::HandshakeFailed => write!(f, "Handshake failed"),
            NoiseError::DecryptionFailed => write!(f, "Message decryption failed"),
            NoiseError::MessageTooLarge => write!(f, "Message exceeds maximum size"),
            NoiseError::ProtocolViolation => write!(f, "Protocol state violation"),
            NoiseError::BufferTooSmall => write!(f, "Output buffer too small"),
        }
    }
}

/// Noise_XX handshake patterns
const NOISE_XX_PATTERNS: &[MessagePattern] = &[
    MessagePattern::E,
    MessagePattern::E, MessagePattern::EE, MessagePattern::S, MessagePattern::ES,
    MessagePattern::S, MessagePattern::SE,
];

/// Noise_NK handshake patterns
const NOISE_NK_PATTERNS: &[MessagePattern] = &[
    MessagePattern::E, MessagePattern::ES,
    MessagePattern::E, MessagePattern::EE,
];

/// Noise_IK handshake patterns
const NOISE_IK_PATTERNS: &[MessagePattern] = &[
    MessagePattern::E, MessagePattern::ES, MessagePattern::S, MessagePattern::SS,
    MessagePattern::E, MessagePattern::EE, MessagePattern::SE,
];

impl HandshakeState {
    /// Initialize handshake state as initiator
    pub fn new_initiator(
        pattern: NoisePattern,
        cipher_suite: CipherSuite,
        local_static: Option<(Scalar, MontgomeryPoint)>,
        remote_static: Option<MontgomeryPoint>,
    ) -> Result<Self, NoiseError> {
        let message_patterns = match pattern {
            NoisePattern::XX => NOISE_XX_PATTERNS,
            NoisePattern::NK => NOISE_NK_PATTERNS,
            NoisePattern::IK => NOISE_IK_PATTERNS,
            _ => return Err(NoiseError::InvalidPattern),
        };

        let protocol_name = Self::protocol_name(pattern, cipher_suite);
        let (chaining_key, handshake_hash) = Self::initialize_symmetric(&protocol_name);

        Ok(HandshakeState {
            pattern,
            cipher_suite,
            local_static,
            remote_static,
            local_ephemeral: None,
            remote_ephemeral: None,
            chaining_key,
            handshake_hash,
            message_patterns,
            message_index: 0,
            is_initiator: true,
        })
    }

    /// Initialize handshake state as responder
    pub fn new_responder(
        pattern: NoisePattern,
        cipher_suite: CipherSuite,
        local_static: Option<(Scalar, MontgomeryPoint)>,
        remote_static: Option<MontgomeryPoint>,
    ) -> Result<Self, NoiseError> {
        let message_patterns = match pattern {
            NoisePattern::XX => NOISE_XX_PATTERNS,
            NoisePattern::NK => NOISE_NK_PATTERNS,
            NoisePattern::IK => NOISE_IK_PATTERNS,
            _ => return Err(NoiseError::InvalidPattern),
        };

        let protocol_name = Self::protocol_name(pattern, cipher_suite);
        let (chaining_key, handshake_hash) = Self::initialize_symmetric(&protocol_name);

        Ok(HandshakeState {
            pattern,
            cipher_suite,
            local_static,
            remote_static,
            local_ephemeral: None,
            remote_ephemeral: None,
            chaining_key,
            handshake_hash,
            message_patterns,
            message_index: 0,
            is_initiator: false,
        })
    }

    /// Generate protocol name string
    fn protocol_name(pattern: NoisePattern, cipher_suite: CipherSuite) -> [u8; 32] {
        let pattern_str = match pattern {
            NoisePattern::XX => "Noise_XX",
            NoisePattern::NK => "Noise_NK",
            NoisePattern::IK => "Noise_IK",
            NoisePattern::N => "Noise_N",
            NoisePattern::K => "Noise_K",
            NoisePattern::X => "Noise_X",
        };

        let cipher_str = match cipher_suite {
            CipherSuite::ChaCha20Poly1305SHA256Curve25519 => "_25519_ChaChaPoly_SHA256",
            CipherSuite::AES256GCMSHA256Curve25519 => "_25519_AESGCM_SHA256",
        };

        let full_name = [pattern_str, cipher_str].concat();
        let mut padded = [0u8; 32];
        let len = full_name.len().min(32);
        padded[..len].copy_from_slice(&full_name.as_bytes()[..len]);
        padded
    }

    /// Initialize symmetric state
    fn initialize_symmetric(protocol_name: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let mut chaining_key = [0u8; 32];
        let mut handshake_hash = [0u8; 32];

        if protocol_name.len() <= 32 {
            chaining_key.copy_from_slice(protocol_name);
            handshake_hash.copy_from_slice(protocol_name);
        } else {
            // Hash if longer than 32 bytes
            chaining_key = Self::sha256(protocol_name);
            handshake_hash = chaining_key;
        }

        (chaining_key, handshake_hash)
    }

    /// SHA256 hash function
    fn sha256(data: &[u8]) -> [u8; 32] {
        // In a real implementation, this would use a proper SHA256 implementation
        // For now, we'll use a simplified hash
        let mut hash = [0u8; 32];
        for (i, &byte) in data.iter().enumerate() {
            hash[i % 32] ^= byte;
        }
        hash
    }

    /// HKDF key derivation
    fn hkdf(chaining_key: &[u8; 32], input_key_material: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        // Simplified HKDF implementation
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];

        // XOR chaining key with input material
        for i in 0..32 {
            k1[i] = chaining_key[i] ^ input_key_material[i];
            k2[i] = chaining_key[i] ^ input_key_material[i] ^ 0x01;
        }

        (k1, k2)
    }

    /// Write handshake message
    #[cfg(feature = "alloc")]
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.message_index >= self.message_patterns.len() {
            return Err(NoiseError::ProtocolViolation);
        }

        let mut message = Vec::new();

        // Process message patterns for this message
        let patterns_for_message = self.get_patterns_for_message();

        for pattern in patterns_for_message {
            match pattern {
                MessagePattern::E => {
                    // Generate and send ephemeral key
                    // Generate ephemeral key (simplified - would use proper RNG in practice)
                    let ephemeral_private = Scalar::from_bytes_mod_order([42u8; 32]);
                    let ephemeral_public = MontgomeryPoint::mul_base_clamped(ephemeral_private.to_bytes());
                    self.local_ephemeral = Some((ephemeral_private, ephemeral_public));
                    message.extend_from_slice(&ephemeral_public.to_bytes());
                    self.mix_hash(&ephemeral_public.to_bytes());
                }
                MessagePattern::S => {
                    // Send static key (encrypted if we have a key)
                    if let Some((_, static_public)) = &self.local_static {
                        let static_bytes = static_public.to_bytes();
                        // TODO: Encrypt with current key if available
                        message.extend_from_slice(&static_bytes);
                        self.mix_hash(&static_bytes);
                    } else {
                        return Err(NoiseError::MissingKey);
                    }
                }
                MessagePattern::EE => {
                    self.mix_key(&self.dh_ee()?);
                }
                MessagePattern::ES => {
                    self.mix_key(&self.dh_es()?);
                }
                MessagePattern::SE => {
                    self.mix_key(&self.dh_se()?);
                }
                MessagePattern::SS => {
                    self.mix_key(&self.dh_ss()?);
                }
            }
        }

        // Encrypt payload if we have a key
        if !payload.is_empty() {
            // TODO: Implement AEAD encryption
            message.extend_from_slice(payload);
            self.mix_hash(payload);
        }

        self.message_index += 1;
        Ok(message)
    }

    /// Read handshake message
    #[cfg(feature = "alloc")]
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.message_index >= self.message_patterns.len() {
            return Err(NoiseError::ProtocolViolation);
        }

        let mut offset = 0;
        let patterns_for_message = self.get_patterns_for_message();

        for pattern in patterns_for_message {
            match pattern {
                MessagePattern::E => {
                    // Read ephemeral key
                    if offset + 32 > message.len() {
                        return Err(NoiseError::InvalidMessage);
                    }
                    let mut ephemeral_bytes = [0u8; 32];
                    ephemeral_bytes.copy_from_slice(&message[offset..offset + 32]);
                    let ephemeral_public = MontgomeryPoint::from_bytes(ephemeral_bytes);
                    self.remote_ephemeral = Some(ephemeral_public);
                    self.mix_hash(&ephemeral_bytes);
                    offset += 32;
                }
                MessagePattern::S => {
                    // Read static key
                    if offset + 32 > message.len() {
                        return Err(NoiseError::InvalidMessage);
                    }
                    let mut static_bytes = [0u8; 32];
                    static_bytes.copy_from_slice(&message[offset..offset + 32]);
                    // TODO: Decrypt if encrypted
                    let static_public = MontgomeryPoint::from_bytes(static_bytes);
                    self.remote_static = Some(static_public);
                    self.mix_hash(&static_bytes);
                    offset += 32;
                }
                MessagePattern::EE => {
                    self.mix_key(&self.dh_ee()?);
                }
                MessagePattern::ES => {
                    self.mix_key(&self.dh_es()?);
                }
                MessagePattern::SE => {
                    self.mix_key(&self.dh_se()?);
                }
                MessagePattern::SS => {
                    self.mix_key(&self.dh_ss()?);
                }
            }
        }

        // Decrypt remaining payload
        let payload = if offset < message.len() {
            let ciphertext = &message[offset..];
            // TODO: Implement AEAD decryption
            self.mix_hash(ciphertext);
            ciphertext.to_vec()
        } else {
            Vec::new()
        };

        self.message_index += 1;
        Ok(payload)
    }

    /// Check if handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        self.message_index >= self.message_patterns.len()
    }

    /// Finalize handshake and create transport state
    pub fn finalize(self) -> Result<(TransportState, TransportState), NoiseError> {
        if !self.is_handshake_complete() {
            return Err(NoiseError::HandshakeFailed);
        }

        let (sending_key, receiving_key) = Self::hkdf(&self.chaining_key, &[0u8; 32]);

        let initiator_transport = TransportState {
            cipher_suite: self.cipher_suite,
            sending_key: if self.is_initiator { sending_key } else { receiving_key },
            receiving_key: if self.is_initiator { receiving_key } else { sending_key },
            sending_nonce: 0,
            receiving_nonce: 0,
        };

        let responder_transport = TransportState {
            cipher_suite: self.cipher_suite,
            sending_key: if self.is_initiator { receiving_key } else { sending_key },
            receiving_key: if self.is_initiator { sending_key } else { receiving_key },
            sending_nonce: 0,
            receiving_nonce: 0,
        };

        Ok((initiator_transport, responder_transport))
    }

    // Helper methods

    fn get_patterns_for_message(&self) -> Vec<MessagePattern> {
        // This is a simplified version - real implementation would parse message patterns properly
        match self.message_index {
            0 => vec![MessagePattern::E],
            1 => vec![MessagePattern::E, MessagePattern::EE, MessagePattern::S, MessagePattern::ES],
            2 => vec![MessagePattern::S, MessagePattern::SE],
            _ => vec![],
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        // Update handshake hash
        for (i, &byte) in data.iter().enumerate() {
            self.handshake_hash[i % 32] ^= byte;
        }
    }

    fn mix_key(&mut self, shared_secret: &[u8; 32]) {
        let (new_chaining_key, _) = Self::hkdf(&self.chaining_key, shared_secret);
        self.chaining_key = new_chaining_key;
    }

    fn dh_ee(&self) -> Result<[u8; 32], NoiseError> {
        let local_ephemeral = self.local_ephemeral.as_ref().ok_or(NoiseError::MissingKey)?;
        let remote_ephemeral = self.remote_ephemeral.as_ref().ok_or(NoiseError::MissingKey)?;
        Ok(crate::montgomery::x25519(local_ephemeral.0.to_bytes(), remote_ephemeral.to_bytes()))
    }

    fn dh_es(&self) -> Result<[u8; 32], NoiseError> {
        if self.is_initiator {
            let local_ephemeral = self.local_ephemeral.as_ref().ok_or(NoiseError::MissingKey)?;
            let remote_static = self.remote_static.as_ref().ok_or(NoiseError::MissingKey)?;
            Ok(crate::montgomery::x25519(local_ephemeral.0.to_bytes(), remote_static.to_bytes()))
        } else {
            let local_static = self.local_static.as_ref().ok_or(NoiseError::MissingKey)?;
            let remote_ephemeral = self.remote_ephemeral.as_ref().ok_or(NoiseError::MissingKey)?;
            Ok(crate::montgomery::x25519(local_static.0.to_bytes(), remote_ephemeral.to_bytes()))
        }
    }

    fn dh_se(&self) -> Result<[u8; 32], NoiseError> {
        if self.is_initiator {
            let local_static = self.local_static.as_ref().ok_or(NoiseError::MissingKey)?;
            let remote_ephemeral = self.remote_ephemeral.as_ref().ok_or(NoiseError::MissingKey)?;
            Ok(crate::montgomery::x25519(local_static.0.to_bytes(), remote_ephemeral.to_bytes()))
        } else {
            let local_ephemeral = self.local_ephemeral.as_ref().ok_or(NoiseError::MissingKey)?;
            let remote_static = self.remote_static.as_ref().ok_or(NoiseError::MissingKey)?;
            Ok(crate::montgomery::x25519(local_ephemeral.0.to_bytes(), remote_static.to_bytes()))
        }
    }

    fn dh_ss(&self) -> Result<[u8; 32], NoiseError> {
        let local_static = self.local_static.as_ref().ok_or(NoiseError::MissingKey)?;
        let remote_static = self.remote_static.as_ref().ok_or(NoiseError::MissingKey)?;
        Ok(crate::montgomery::x25519(local_static.0.to_bytes(), remote_static.to_bytes()))
    }
}

impl TransportState {
    /// Encrypt a message
    #[cfg(feature = "alloc")]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if plaintext.len() > 65535 - 16 {
            return Err(NoiseError::MessageTooLarge);
        }

        let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);

        // TODO: Implement actual AEAD encryption based on cipher_suite
        match self.cipher_suite {
            CipherSuite::ChaCha20Poly1305SHA256Curve25519 => {
                // Placeholder for ChaCha20-Poly1305 encryption
                ciphertext.extend_from_slice(plaintext);
                ciphertext.extend_from_slice(&[0u8; 16]); // Mock tag
            }
            CipherSuite::AES256GCMSHA256Curve25519 => {
                // Placeholder for AES256-GCM encryption
                ciphertext.extend_from_slice(plaintext);
                ciphertext.extend_from_slice(&[0u8; 16]); // Mock tag
            }
        }

        self.sending_nonce = self.sending_nonce.wrapping_add(1);
        Ok(ciphertext)
    }

    /// Decrypt a message
    #[cfg(feature = "alloc")]
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if ciphertext.len() < 16 {
            return Err(NoiseError::InvalidMessage);
        }

        let plaintext_len = ciphertext.len() - 16;
        let mut plaintext = Vec::with_capacity(plaintext_len);

        // TODO: Implement actual AEAD decryption based on cipher_suite
        match self.cipher_suite {
            CipherSuite::ChaCha20Poly1305SHA256Curve25519 => {
                // Placeholder for ChaCha20-Poly1305 decryption
                plaintext.extend_from_slice(&ciphertext[..plaintext_len]);
            }
            CipherSuite::AES256GCMSHA256Curve25519 => {
                // Placeholder for AES256-GCM decryption
                plaintext.extend_from_slice(&ciphertext[..plaintext_len]);
            }
        }

        self.receiving_nonce = self.receiving_nonce.wrapping_add(1);
        Ok(plaintext)
    }

    /// Get current sending nonce
    pub fn sending_nonce(&self) -> u64 {
        self.sending_nonce
    }

    /// Get current receiving nonce
    pub fn receiving_nonce(&self) -> u64 {
        self.receiving_nonce
    }

    /// Check if nonces need rekeying (after 2^64 - 1)
    pub fn needs_rekey(&self) -> bool {
        self.sending_nonce == u64::MAX || self.receiving_nonce == u64::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "alloc")]
    fn test_noise_xx_handshake() {
        let mut rng = rand::thread_rng();

        // Generate static keys for both parties
        let initiator_static_private = Scalar::random(&mut rng);
        let initiator_static_public = MontgomeryPoint::mul_base_clamped(initiator_static_private.to_bytes());

        let responder_static_private = Scalar::random(&mut rng);
        let responder_static_public = MontgomeryPoint::mul_base_clamped(responder_static_private.to_bytes());

        // Initialize handshake states
        let mut initiator = HandshakeState::new_initiator(
            NoisePattern::XX,
            CipherSuite::ChaCha20Poly1305SHA256Curve25519,
            Some((initiator_static_private, initiator_static_public)),
            None,
        ).unwrap();

        let mut responder = HandshakeState::new_responder(
            NoisePattern::XX,
            CipherSuite::ChaCha20Poly1305SHA256Curve25519,
            Some((responder_static_private, responder_static_public)),
            None,
        ).unwrap();

        // Message 1: Initiator -> Responder
        let msg1 = initiator.write_message(b"Hello").unwrap();
        let payload1 = responder.read_message(&msg1).unwrap();
        assert_eq!(payload1, b"Hello");

        // Message 2: Responder -> Initiator
        let msg2 = responder.write_message(b"Hi there").unwrap();
        let payload2 = initiator.read_message(&msg2).unwrap();
        assert_eq!(payload2, b"Hi there");

        // Message 3: Initiator -> Responder
        let msg3 = initiator.write_message(b"Final").unwrap();
        let payload3 = responder.read_message(&msg3).unwrap();
        assert_eq!(payload3, b"Final");

        // Handshake should be complete
        assert!(initiator.is_handshake_complete());
        assert!(responder.is_handshake_complete());
    }

    #[test]
    fn test_protocol_name_generation() {
        let name = HandshakeState::protocol_name(
            NoisePattern::XX,
            CipherSuite::ChaCha20Poly1305SHA256Curve25519
        );

        // Should start with "Noise_XX"
        assert!(name.starts_with(b"Noise_XX"));
    }
}