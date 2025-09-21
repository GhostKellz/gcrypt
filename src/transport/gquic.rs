//! GQUIC Transport Integration for Ghostchain Ecosystem
//!
//! This module provides hardware-accelerated cryptographic operations
//! specifically optimized for GQUIC transport protocol used by Etherlink
//! and other Ghostchain networking components.

use crate::{
    EdwardsPoint, MontgomeryPoint, Scalar,
    hash::blake3_hash,
    aead::{ChaCha20Poly1305, Aead, Key, Nonce},
};
use core::fmt;
use subtle::{Choice, ConstantTimeEq};

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, boxed::Box};

/// Errors that can occur during GQUIC transport operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GquicError {
    /// Invalid packet format
    InvalidPacket,
    /// Authentication failure
    AuthenticationFailed,
    /// Invalid session key
    InvalidSessionKey,
    /// Encryption failure
    EncryptionFailed,
    /// Decryption failure
    DecryptionFailed,
    /// Key derivation failure
    KeyDerivationFailed,
    /// Invalid connection ID
    InvalidConnectionId,
}

impl fmt::Display for GquicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GquicError::InvalidPacket => write!(f, "Invalid GQUIC packet format"),
            GquicError::AuthenticationFailed => write!(f, "GQUIC authentication failed"),
            GquicError::InvalidSessionKey => write!(f, "Invalid GQUIC session key"),
            GquicError::EncryptionFailed => write!(f, "GQUIC encryption failed"),
            GquicError::DecryptionFailed => write!(f, "GQUIC decryption failed"),
            GquicError::KeyDerivationFailed => write!(f, "GQUIC key derivation failed"),
            GquicError::InvalidConnectionId => write!(f, "Invalid GQUIC connection ID"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GquicError {}

/// GQUIC connection identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId([u8; 16]);

impl ConnectionId {
    /// Create a new connection ID from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the connection ID as bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Generate a random connection ID
    #[cfg(feature = "rand_core")]
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// GQUIC session key for symmetric encryption
#[derive(Clone)]
pub struct SessionKey {
    key: Key<ChaCha20Poly1305>,
    connection_id: ConnectionId,
    sequence: u64,
}

impl SessionKey {
    /// Create a new session key from raw bytes
    pub fn from_bytes(key_bytes: &[u8; 32], connection_id: ConnectionId) -> Self {
        Self {
            key: Key::from(*key_bytes),
            connection_id,
            sequence: 0,
        }
    }

    /// Derive a session key from X25519 shared secret
    pub fn derive_from_shared_secret(
        shared_secret: &[u8; 32],
        connection_id: ConnectionId,
        context: &[u8],
    ) -> Result<Self, GquicError> {
        // Use BLAKE3 for key derivation
        let mut key_material = [0u8; 32];
        let mut hasher = blake3::Hasher::new();
        hasher.update(shared_secret);
        hasher.update(connection_id.as_bytes());
        hasher.update(context);
        hasher.update(b"GQUIC-SESSION-KEY");

        let hash = hasher.finalize();
        key_material.copy_from_slice(&hash.as_bytes()[..32]);

        Ok(Self::from_bytes(&key_material, connection_id))
    }

    /// Get the next packet nonce
    fn next_nonce(&mut self) -> Nonce<ChaCha20Poly1305> {
        let mut nonce_bytes = [0u8; 12];

        // Connection ID (first 8 bytes of nonce)
        nonce_bytes[..8].copy_from_slice(&self.connection_id.as_bytes()[..8]);

        // Sequence number (last 4 bytes)
        nonce_bytes[8..].copy_from_slice(&self.sequence.to_le_bytes()[..4]);

        self.sequence = self.sequence.wrapping_add(1);

        Nonce::from(nonce_bytes)
    }

    /// Get connection ID
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKey")
            .field("connection_id", &self.connection_id)
            .field("sequence", &self.sequence)
            .finish()
    }
}

/// High-performance GQUIC transport for packet encryption/decryption
pub struct GquicTransport {
    cipher: ChaCha20Poly1305,
}

impl GquicTransport {
    /// Create a new GQUIC transport instance
    pub fn new() -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(),
        }
    }

    /// Encrypt a single GQUIC packet
    pub fn encrypt_packet(
        &self,
        session: &mut SessionKey,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, GquicError> {
        let nonce = session.next_nonce();

        self.cipher
            .encrypt(&session.key, &nonce, plaintext, additional_data)
            .map_err(|_| GquicError::EncryptionFailed)
    }

    /// Decrypt a single GQUIC packet
    pub fn decrypt_packet(
        &self,
        session: &mut SessionKey,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, GquicError> {
        let nonce = session.next_nonce();

        self.cipher
            .decrypt(&session.key, &nonce, ciphertext, additional_data)
            .map_err(|_| GquicError::DecryptionFailed)
    }

    /// High-performance batch packet encryption
    /// Encrypts multiple packets in parallel when possible
    #[cfg(feature = "alloc")]
    pub fn batch_encrypt_packets(
        &self,
        sessions: &mut [SessionKey],
        packets: &[&[u8]],
        additional_data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, GquicError> {
        if sessions.len() != packets.len() || packets.len() != additional_data.len() {
            return Err(GquicError::InvalidPacket);
        }

        let mut encrypted_packets = Vec::with_capacity(packets.len());

        for ((session, packet), ad) in sessions.iter_mut().zip(packets.iter()).zip(additional_data.iter()) {
            let encrypted = self.encrypt_packet(session, packet, ad)?;
            encrypted_packets.push(encrypted);
        }

        Ok(encrypted_packets)
    }

    /// High-performance batch packet decryption
    #[cfg(feature = "alloc")]
    pub fn batch_decrypt_packets(
        &self,
        sessions: &mut [SessionKey],
        packets: &[&[u8]],
        additional_data: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, GquicError> {
        if sessions.len() != packets.len() || packets.len() != additional_data.len() {
            return Err(GquicError::InvalidPacket);
        }

        let mut decrypted_packets = Vec::with_capacity(packets.len());

        for ((session, packet), ad) in sessions.iter_mut().zip(packets.iter()).zip(additional_data.iter()) {
            let decrypted = self.decrypt_packet(session, packet, ad)?;
            decrypted_packets.push(decrypted);
        }

        Ok(decrypted_packets)
    }
}

impl Default for GquicTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// GQUIC connection manager for multiple concurrent connections
#[cfg(feature = "std")]
pub struct GquicConnectionManager {
    sessions: HashMap<ConnectionId, SessionKey>,
    transport: GquicTransport,
}

#[cfg(feature = "std")]
impl GquicConnectionManager {
    /// Create a new connection manager
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            transport: GquicTransport::new(),
        }
    }

    /// Add a new session
    pub fn add_session(&mut self, session: SessionKey) {
        let connection_id = session.connection_id();
        self.sessions.insert(connection_id, session);
    }

    /// Remove a session
    pub fn remove_session(&mut self, connection_id: &ConnectionId) -> Option<SessionKey> {
        self.sessions.remove(connection_id)
    }

    /// Encrypt packet for a specific connection
    pub fn encrypt_for_connection(
        &mut self,
        connection_id: &ConnectionId,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, GquicError> {
        let session = self.sessions
            .get_mut(connection_id)
            .ok_or(GquicError::InvalidConnectionId)?;

        self.transport.encrypt_packet(session, plaintext, additional_data)
    }

    /// Decrypt packet for a specific connection
    pub fn decrypt_for_connection(
        &mut self,
        connection_id: &ConnectionId,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, GquicError> {
        let session = self.sessions
            .get_mut(connection_id)
            .ok_or(GquicError::InvalidConnectionId)?;

        self.transport.decrypt_packet(session, ciphertext, additional_data)
    }

    /// Get number of active connections
    pub fn connection_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(feature = "std")]
impl Default for GquicConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// GQUIC key exchange using X25519
pub struct GquicKeyExchange;

impl GquicKeyExchange {
    /// Perform X25519 key exchange and derive GQUIC session key
    pub fn derive_session_key(
        local_secret: &Scalar,
        remote_public: &MontgomeryPoint,
        connection_id: ConnectionId,
        context: &[u8],
    ) -> Result<SessionKey, GquicError> {
        // Perform X25519 key exchange
        let shared_point = remote_public * local_secret;
        let shared_secret = shared_point.to_bytes();

        // Derive session key from shared secret
        SessionKey::derive_from_shared_secret(&shared_secret, connection_id, context)
    }

    /// Generate a local key pair for GQUIC
    #[cfg(feature = "rand_core")]
    pub fn generate_keypair<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
    ) -> (Scalar, MontgomeryPoint) {
        let secret = Scalar::random(rng);
        let public = MontgomeryPoint::mul_base(&secret);
        (secret, public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_creation() {
        let bytes = [1u8; 16];
        let conn_id = ConnectionId::from_bytes(bytes);
        assert_eq!(conn_id.as_bytes(), &bytes);
    }

    #[test]
    fn test_session_key_derivation() {
        let shared_secret = [0x42u8; 32];
        let connection_id = ConnectionId::from_bytes([0x01u8; 16]);
        let context = b"test-context";

        let session_key = SessionKey::derive_from_shared_secret(
            &shared_secret,
            connection_id,
            context
        ).unwrap();

        assert_eq!(session_key.connection_id(), connection_id);
    }

    #[test]
    fn test_packet_encryption_decryption() {
        let session_key = SessionKey::from_bytes(
            &[0x42u8; 32],
            ConnectionId::from_bytes([0x01u8; 16])
        );
        let mut encrypt_session = session_key.clone();
        let mut decrypt_session = session_key;

        let transport = GquicTransport::new();
        let plaintext = b"Hello, GQUIC!";
        let additional_data = b"packet-header";

        let ciphertext = transport.encrypt_packet(
            &mut encrypt_session,
            plaintext,
            additional_data
        ).unwrap();

        let decrypted = transport.decrypt_packet(
            &mut decrypt_session,
            &ciphertext,
            additional_data
        ).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_operations() {
        let mut sessions = vec![
            SessionKey::from_bytes(&[0x42u8; 32], ConnectionId::from_bytes([0x01u8; 16])),
            SessionKey::from_bytes(&[0x43u8; 32], ConnectionId::from_bytes([0x02u8; 16])),
        ];

        let packets = vec![b"packet1".as_slice(), b"packet2".as_slice()];
        let additional_data = vec![b"header1".as_slice(), b"header2".as_slice()];

        let transport = GquicTransport::new();

        let encrypted = transport.batch_encrypt_packets(
            &mut sessions,
            &packets,
            &additional_data
        ).unwrap();

        assert_eq!(encrypted.len(), 2);
    }

    #[cfg(all(feature = "std", feature = "rand_core"))]
    #[test]
    fn test_connection_manager() {
        let mut rng = rand::thread_rng();
        let connection_id = ConnectionId::random(&mut rng);
        let session_key = SessionKey::from_bytes(&[0x42u8; 32], connection_id);

        let mut manager = GquicConnectionManager::new();
        manager.add_session(session_key);

        assert_eq!(manager.connection_count(), 1);

        let plaintext = b"test message";
        let additional_data = b"test header";

        let encrypted = manager.encrypt_for_connection(
            &connection_id,
            plaintext,
            additional_data
        ).unwrap();

        let decrypted = manager.decrypt_for_connection(
            &connection_id,
            &encrypted,
            additional_data
        ).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}