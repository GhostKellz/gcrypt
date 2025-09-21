//! Session management for secure transport protocols
//!
//! This module provides session management capabilities for maintaining
//! secure communication channels across the Ghostchain ecosystem.

use crate::{EdwardsPoint, Scalar, hash::blake3_hash};
use core::fmt;
use subtle::{Choice, ConstantTimeEq};

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String};

/// Session management errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Session has expired
    Expired,
    /// Invalid session token
    InvalidToken,
    /// Session not found
    NotFound,
    /// Insufficient permissions
    InsufficientPermissions,
    /// Session creation failed
    CreationFailed,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Expired => write!(f, "Session has expired"),
            SessionError::InvalidToken => write!(f, "Invalid session token"),
            SessionError::NotFound => write!(f, "Session not found"),
            SessionError::InsufficientPermissions => write!(f, "Insufficient permissions for operation"),
            SessionError::CreationFailed => write!(f, "Failed to create session"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SessionError {}

/// Session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// Create a session ID from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get session ID as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generate a random session ID
    #[cfg(feature = "rand_core")]
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derive session ID from key material
    pub fn derive_from_key(public_key: &EdwardsPoint, timestamp: u64, context: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&public_key.compress().to_bytes());
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(context);
        hasher.update(b"SESSION-ID");

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Self(bytes)
    }
}

/// Transport session for maintaining secure communication state
#[derive(Debug, Clone)]
pub struct TransportSession {
    /// Unique session identifier
    pub id: SessionId,
    /// Remote public key for authentication
    pub remote_public_key: EdwardsPoint,
    /// Session creation timestamp
    pub created_at: u64,
    /// Session expiration timestamp
    pub expires_at: u64,
    /// Additional session metadata
    #[cfg(feature = "alloc")]
    pub metadata: Vec<u8>,
}

impl TransportSession {
    /// Create a new transport session
    #[cfg(feature = "std")]
    pub fn new(
        remote_public_key: EdwardsPoint,
        duration_secs: u64,
        context: &[u8],
    ) -> Result<Self, SessionError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SessionError::CreationFailed)?
            .as_secs();

        let id = SessionId::derive_from_key(&remote_public_key, now, context);

        Ok(Self {
            id,
            remote_public_key,
            created_at: now,
            expires_at: now + duration_secs,
            #[cfg(feature = "alloc")]
            metadata: Vec::new(),
        })
    }

    /// Create a session with explicit timestamps
    pub fn with_timestamps(
        remote_public_key: EdwardsPoint,
        created_at: u64,
        expires_at: u64,
        context: &[u8],
    ) -> Self {
        let id = SessionId::derive_from_key(&remote_public_key, created_at, context);

        Self {
            id,
            remote_public_key,
            created_at,
            expires_at,
            #[cfg(feature = "alloc")]
            metadata: Vec::new(),
        }
    }

    /// Check if session is valid at given timestamp
    pub fn is_valid_at(&self, timestamp: u64) -> bool {
        timestamp >= self.created_at && timestamp < self.expires_at
    }

    /// Check if session is currently valid
    #[cfg(feature = "std")]
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.is_valid_at(now)
    }

    /// Get remaining session lifetime in seconds
    #[cfg(feature = "std")]
    pub fn remaining_lifetime(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now >= self.expires_at {
            0
        } else {
            self.expires_at - now
        }
    }

    /// Extend session expiration
    pub fn extend(&mut self, additional_secs: u64) {
        self.expires_at = self.expires_at.saturating_add(additional_secs);
    }

    /// Add metadata to session
    #[cfg(feature = "alloc")]
    pub fn add_metadata(&mut self, data: Vec<u8>) {
        self.metadata = data;
    }

    /// Get session metadata
    #[cfg(feature = "alloc")]
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
}

/// Session pool for managing multiple concurrent sessions
#[cfg(feature = "std")]
pub struct SessionPool {
    sessions: std::collections::HashMap<SessionId, TransportSession>,
    max_sessions: usize,
}

#[cfg(feature = "std")]
impl SessionPool {
    /// Create a new session pool
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            max_sessions,
        }
    }

    /// Add a session to the pool
    pub fn add_session(&mut self, session: TransportSession) -> Result<(), SessionError> {
        if self.sessions.len() >= self.max_sessions {
            // Remove expired sessions first
            self.cleanup_expired();

            // If still at capacity, reject new session
            if self.sessions.len() >= self.max_sessions {
                return Err(SessionError::CreationFailed);
            }
        }

        self.sessions.insert(session.id, session);
        Ok(())
    }

    /// Get a session by ID
    pub fn get_session(&self, id: &SessionId) -> Option<&TransportSession> {
        self.sessions.get(id)
    }

    /// Get a mutable session by ID
    pub fn get_session_mut(&mut self, id: &SessionId) -> Option<&mut TransportSession> {
        self.sessions.get_mut(id)
    }

    /// Remove a session
    pub fn remove_session(&mut self, id: &SessionId) -> Option<TransportSession> {
        self.sessions.remove(id)
    }

    /// Remove all expired sessions
    pub fn cleanup_expired(&mut self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let initial_count = self.sessions.len();
        self.sessions.retain(|_, session| session.is_valid_at(now));
        initial_count - self.sessions.len()
    }

    /// Get number of active sessions
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Check if pool is at capacity
    pub fn is_full(&self) -> bool {
        self.sessions.len() >= self.max_sessions
    }

    /// Get all session IDs
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.sessions.keys().copied().collect()
    }

    /// Validate and get session
    pub fn validate_session(&self, id: &SessionId) -> Result<&TransportSession, SessionError> {
        let session = self.get_session(id).ok_or(SessionError::NotFound)?;

        if !session.is_valid() {
            return Err(SessionError::Expired);
        }

        Ok(session)
    }

    /// Extend session if it exists and is valid
    pub fn extend_session(&mut self, id: &SessionId, additional_secs: u64) -> Result<(), SessionError> {
        let session = self.get_session_mut(id).ok_or(SessionError::NotFound)?;

        if !session.is_valid() {
            return Err(SessionError::Expired);
        }

        session.extend(additional_secs);
        Ok(())
    }
}

#[cfg(feature = "std")]
impl Default for SessionPool {
    fn default() -> Self {
        Self::new(1000) // Default to 1000 max sessions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scalar;

    #[test]
    fn test_session_id_derivation() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let public_key = EdwardsPoint::mul_base(&secret);
        let timestamp = 1234567890u64;
        let context = b"test-context";

        let id1 = SessionId::derive_from_key(&public_key, timestamp, context);
        let id2 = SessionId::derive_from_key(&public_key, timestamp, context);

        // Same inputs should produce same ID
        assert_eq!(id1, id2);

        // Different timestamp should produce different ID
        let id3 = SessionId::derive_from_key(&public_key, timestamp + 1, context);
        assert_ne!(id1, id3);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_session_validity() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let public_key = EdwardsPoint::mul_base(&secret);

        let session = TransportSession::new(public_key, 3600, b"test").unwrap();
        assert!(session.is_valid());
        assert!(session.remaining_lifetime() > 0);
    }

    #[test]
    fn test_session_with_timestamps() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let public_key = EdwardsPoint::mul_base(&secret);

        let now = 1000u64;
        let session = TransportSession::with_timestamps(
            public_key,
            now,
            now + 3600,
            b"test"
        );

        assert!(session.is_valid_at(now + 1800)); // Middle of validity period
        assert!(!session.is_valid_at(now + 7200)); // After expiration
        assert!(!session.is_valid_at(now - 1)); // Before creation
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_session_pool() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let public_key = EdwardsPoint::mul_base(&secret);

        let mut pool = SessionPool::new(2);

        let session1 = TransportSession::new(public_key, 3600, b"test1").unwrap();
        let session2 = TransportSession::new(public_key, 3600, b"test2").unwrap();

        let id1 = session1.id;
        let id2 = session2.id;

        assert!(pool.add_session(session1).is_ok());
        assert!(pool.add_session(session2).is_ok());
        assert_eq!(pool.active_sessions(), 2);

        // Pool should be full
        assert!(pool.is_full());

        // Should be able to retrieve sessions
        assert!(pool.get_session(&id1).is_some());
        assert!(pool.get_session(&id2).is_some());

        // Remove a session
        assert!(pool.remove_session(&id1).is_some());
        assert_eq!(pool.active_sessions(), 1);
        assert!(!pool.is_full());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_session_extension() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let public_key = EdwardsPoint::mul_base(&secret);

        let mut pool = SessionPool::new(10);
        let session = TransportSession::new(public_key, 1, b"test").unwrap(); // 1 second duration
        let id = session.id;

        pool.add_session(session).unwrap();

        // Extend the session
        assert!(pool.extend_session(&id, 3600).is_ok());

        let extended_session = pool.get_session(&id).unwrap();
        assert!(extended_session.remaining_lifetime() > 1);
    }
}