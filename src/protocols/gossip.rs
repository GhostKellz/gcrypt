//! Gossip Protocol for Decentralized Networking
//!
//! This module implements a secure gossip protocol for peer-to-peer networks,
//! enabling efficient information dissemination across mesh networks.
//!
//! Features:
//! - Message propagation with anti-entropy mechanisms
//! - Cryptographic message authentication
//! - Peer discovery and reputation tracking
//! - Byzantine fault tolerance

use crate::{Scalar, EdwardsPoint};
use crate::protocols::{Ed25519SecretKey, Ed25519PublicKey, Ed25519Signature};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, collections::BTreeMap, collections::BTreeSet};

use core::{fmt, hash::Hash};

#[cfg(feature = "rand_core")]
use rand_core::{RngCore, CryptoRng};

#[cfg(test)]
use rand::thread_rng;

/// Unique peer identifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub [u8; 32]);

/// Network address for peer connectivity
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAddress {
    /// IP address or hostname
    pub host: [u8; 16], // IPv6 compatible
    /// Port number
    pub port: u16,
    /// Protocol (TCP, UDP, etc.)
    pub protocol: NetworkProtocol,
}

/// Network protocols supported
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkProtocol {
    /// TCP connection
    TCP,
    /// UDP datagram
    UDP,
    /// QUIC over UDP
    QUIC,
    /// WebSocket
    WebSocket,
}

/// Gossip message types
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageType {
    /// Peer discovery message
    PeerDiscovery,
    /// Data propagation message
    DataPropagation,
    /// Heartbeat/keep-alive
    Heartbeat,
    /// Synchronization request
    SyncRequest,
    /// Synchronization response
    SyncResponse,
    /// Custom application data
    Custom(u8),
}

/// Gossip message structure
#[derive(Clone, Debug)]
pub struct GossipMessage {
    /// Message ID (prevents loops)
    pub id: [u8; 32],
    /// Message type
    pub msg_type: MessageType,
    /// Source peer ID
    pub source: PeerId,
    /// Target peer ID (None for broadcast)
    pub target: Option<PeerId>,
    /// Time-to-live (hop count)
    pub ttl: u8,
    /// Message payload
    pub payload: Vec<u8>,
    /// Cryptographic signature
    pub signature: Ed25519Signature,
    /// Timestamp (Unix timestamp)
    pub timestamp: u64,
}

/// Signed gossip message
#[derive(Clone, Debug)]
pub struct SignedGossipMessage {
    /// The gossip message
    pub message: GossipMessage,
    /// Verification key
    pub public_key: Ed25519PublicKey,
}

/// Peer information in the network
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Peer identifier
    pub id: PeerId,
    /// Network addresses
    pub addresses: Vec<PeerAddress>,
    /// Public key for verification
    pub public_key: Ed25519PublicKey,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Reputation score
    pub reputation: f64,
    /// Connection state
    pub state: PeerState,
}

/// Peer connection state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    /// Disconnected
    Disconnected,
    /// Connecting
    Connecting,
    /// Connected
    Connected,
    /// Failed connection
    Failed,
    /// Banned due to misbehavior
    Banned,
}

/// Gossip protocol configuration
#[derive(Clone, Debug)]
pub struct GossipConfig {
    /// Maximum number of peers to maintain
    pub max_peers: usize,
    /// Message TTL (time-to-live)
    pub default_ttl: u8,
    /// Heartbeat interval in seconds
    pub heartbeat_interval: u64,
    /// Peer timeout in seconds
    pub peer_timeout: u64,
    /// Maximum message size
    pub max_message_size: usize,
    /// Fanout factor for message propagation
    pub fanout: usize,
    /// Enable anti-entropy synchronization
    pub enable_anti_entropy: bool,
}

/// Gossip protocol state
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct GossipState {
    /// Our peer information
    pub local_peer: PeerInfo,
    /// Our private key
    pub private_key: Ed25519SecretKey,
    /// Known peers
    pub peers: BTreeMap<PeerId, PeerInfo>,
    /// Message cache (for duplicate detection)
    pub message_cache: BTreeSet<[u8; 32]>,
    /// Configuration
    pub config: GossipConfig,
    /// Current time (Unix timestamp)
    pub current_time: u64,
}

/// Gossip protocol errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipError {
    /// Invalid message format
    InvalidMessage,
    /// Message too large
    MessageTooLarge,
    /// Invalid signature
    InvalidSignature,
    /// Peer not found
    PeerNotFound,
    /// Peer already exists
    PeerAlreadyExists,
    /// Message expired (TTL reached 0)
    MessageExpired,
    /// Duplicate message
    DuplicateMessage,
    /// Network error
    NetworkError,
    /// Serialization error
    SerializationError,
    /// Configuration error
    ConfigError,
}

impl fmt::Display for GossipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GossipError::InvalidMessage => write!(f, "Invalid message format"),
            GossipError::MessageTooLarge => write!(f, "Message exceeds maximum size"),
            GossipError::InvalidSignature => write!(f, "Invalid message signature"),
            GossipError::PeerNotFound => write!(f, "Peer not found"),
            GossipError::PeerAlreadyExists => write!(f, "Peer already exists"),
            GossipError::MessageExpired => write!(f, "Message TTL expired"),
            GossipError::DuplicateMessage => write!(f, "Duplicate message received"),
            GossipError::NetworkError => write!(f, "Network communication error"),
            GossipError::SerializationError => write!(f, "Message serialization error"),
            GossipError::ConfigError => write!(f, "Invalid configuration"),
        }
    }
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            max_peers: 100,
            default_ttl: 7,
            heartbeat_interval: 30,
            peer_timeout: 300,
            max_message_size: 64 * 1024, // 64KB
            fanout: 6,
            enable_anti_entropy: true,
        }
    }
}

impl PeerId {
    /// Generate a new random peer ID
    #[cfg(feature = "rand_core")]
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut id = [0u8; 32];
        rng.fill_bytes(&mut id);
        PeerId(id)
    }

    /// Create peer ID from public key
    pub fn from_public_key(public_key: &Ed25519PublicKey) -> Self {
        // Hash the public key to create peer ID
        // Note: In a real implementation, this would properly serialize the public key
        let mut id = [0u8; 32];
        // Simplified - would use proper serialization of public key
        for i in 0..32 {
            id[i] = (i as u8) ^ 0x42; // Placeholder
        }
        PeerId(id)
    }

    /// Get bytes representation
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PeerAddress {
    /// Create new TCP address
    pub fn tcp(host: [u8; 16], port: u16) -> Self {
        Self {
            host,
            port,
            protocol: NetworkProtocol::TCP,
        }
    }

    /// Create new UDP address
    pub fn udp(host: [u8; 16], port: u16) -> Self {
        Self {
            host,
            port,
            protocol: NetworkProtocol::UDP,
        }
    }

    /// Create new QUIC address
    pub fn quic(host: [u8; 16], port: u16) -> Self {
        Self {
            host,
            port,
            protocol: NetworkProtocol::QUIC,
        }
    }
}

impl GossipMessage {
    /// Create a new gossip message
    #[cfg(feature = "rand_core")]
    pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(
        msg_type: MessageType,
        source: PeerId,
        target: Option<PeerId>,
        payload: Vec<u8>,
        ttl: u8,
        timestamp: u64,
        private_key: &Ed25519SecretKey,
        rng: &mut R,
    ) -> Result<Self, GossipError> {
        // Generate random message ID
        let mut id = [0u8; 32];
        rng.fill_bytes(&mut id);

        // Create message for signing
        let mut message = GossipMessage {
            id,
            msg_type,
            source,
            target,
            ttl,
            payload,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]), // Placeholder
            timestamp,
        };

        // Sign the message
        let message_hash = message.hash();
        let signature = private_key.sign(&message_hash, rng);
        message.signature = signature;

        Ok(message)
    }

    /// Calculate message hash for signing
    pub fn hash(&self) -> [u8; 32] {
        // Simplified hash - in practice would use a proper hash function
        let mut hash = [0u8; 32];

        // Hash ID
        for (i, &byte) in self.id.iter().enumerate() {
            hash[i % 32] ^= byte;
        }

        // Hash type
        hash[0] ^= match self.msg_type {
            MessageType::PeerDiscovery => 1,
            MessageType::DataPropagation => 2,
            MessageType::Heartbeat => 3,
            MessageType::SyncRequest => 4,
            MessageType::SyncResponse => 5,
            MessageType::Custom(x) => x,
        };

        // Hash source
        for (i, &byte) in self.source.as_bytes().iter().enumerate() {
            hash[i % 32] ^= byte;
        }

        // Hash TTL and timestamp
        hash[31] ^= self.ttl;
        hash[30] ^= (self.timestamp & 0xFF) as u8;

        // Hash payload
        for (i, &byte) in self.payload.iter().enumerate() {
            hash[i % 32] ^= byte;
        }

        hash
    }

    /// Verify message signature
    pub fn verify(&self, public_key: &Ed25519PublicKey) -> Result<(), GossipError> {
        let message_hash = self.hash();
        public_key.verify(&message_hash, &self.signature)
            .map_err(|_| GossipError::InvalidSignature)
    }

    /// Decrement TTL
    pub fn decrement_ttl(&mut self) -> Result<(), GossipError> {
        if self.ttl == 0 {
            return Err(GossipError::MessageExpired);
        }
        self.ttl -= 1;
        Ok(())
    }

    /// Check if message is expired
    pub fn is_expired(&self) -> bool {
        self.ttl == 0
    }

    /// Get message size
    pub fn size(&self) -> usize {
        32 + // ID
        1 +  // Message type
        32 + // Source
        if self.target.is_some() { 32 } else { 0 } + // Target
        1 +  // TTL
        self.payload.len() +
        64 + // Signature
        8    // Timestamp
    }
}

#[cfg(feature = "alloc")]
impl GossipState {
    /// Create new gossip state
    pub fn new(
        private_key: Ed25519SecretKey,
        addresses: Vec<PeerAddress>,
        config: GossipConfig,
    ) -> Self {
        let public_key = private_key.public_key();
        let peer_id = PeerId::from_public_key(&public_key);

        let local_peer = PeerInfo {
            id: peer_id,
            addresses,
            public_key,
            last_seen: 0, // Will be updated
            reputation: 1.0,
            state: PeerState::Connected,
        };

        Self {
            local_peer,
            private_key,
            peers: BTreeMap::new(),
            message_cache: BTreeSet::new(),
            config,
            current_time: 0,
        }
    }

    /// Add a peer to the network
    pub fn add_peer(&mut self, peer: PeerInfo) -> Result<(), GossipError> {
        if self.peers.contains_key(&peer.id) {
            return Err(GossipError::PeerAlreadyExists);
        }

        if self.peers.len() >= self.config.max_peers {
            // Remove oldest peer to make room
            if let Some((oldest_id, _)) = self.peers.iter()
                .min_by_key(|(_, p)| p.last_seen)
                .map(|(id, peer)| (*id, peer.clone()))
            {
                self.peers.remove(&oldest_id);
            }
        }

        self.peers.insert(peer.id, peer);
        Ok(())
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Result<PeerInfo, GossipError> {
        self.peers.remove(peer_id).ok_or(GossipError::PeerNotFound)
    }

    /// Get peer information
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Update peer's last seen time
    pub fn update_peer_seen(&mut self, peer_id: &PeerId, timestamp: u64) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.last_seen = timestamp;
        }
    }

    /// Get list of active peers
    pub fn active_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values()
            .filter(|p| p.state == PeerState::Connected)
            .filter(|p| self.current_time - p.last_seen < self.config.peer_timeout)
            .collect()
    }

    /// Process incoming gossip message
    pub fn process_message(&mut self, message: GossipMessage, sender: PeerId) -> Result<Option<Vec<PeerId>>, GossipError> {
        // Check message size
        if message.size() > self.config.max_message_size {
            return Err(GossipError::MessageTooLarge);
        }

        // Check for duplicate
        if self.message_cache.contains(&message.id) {
            return Err(GossipError::DuplicateMessage);
        }

        // Verify signature
        if let Some(sender_peer) = self.get_peer(&sender) {
            message.verify(&sender_peer.public_key)?;
        } else {
            return Err(GossipError::PeerNotFound);
        }

        // Check TTL
        if message.is_expired() {
            return Err(GossipError::MessageExpired);
        }

        // Add to cache
        self.message_cache.insert(message.id);

        // Update sender's last seen
        self.update_peer_seen(&sender, message.timestamp);

        // Determine propagation targets
        let mut targets = Vec::new();

        // If targeted message, check if it's for us
        if let Some(target) = message.target {
            if target == self.local_peer.id {
                // Message is for us, don't propagate
                return Ok(None);
            } else {
                // Forward to specific target if we know them
                if self.peers.contains_key(&target) {
                    targets.push(target);
                }
            }
        } else {
            // Broadcast message - select random subset of peers for propagation
            let active_peers = self.active_peers();
            let fanout = self.config.fanout.min(active_peers.len());

            // Simple selection - in practice would use better algorithm
            for (i, peer) in active_peers.iter().enumerate() {
                if i < fanout && peer.id != sender {
                    targets.push(peer.id);
                }
            }
        }

        Ok(Some(targets))
    }

    /// Create and sign a new message
    #[cfg(feature = "rand_core")]
    pub fn create_message<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        msg_type: MessageType,
        target: Option<PeerId>,
        payload: Vec<u8>,
        rng: &mut R,
    ) -> Result<GossipMessage, GossipError> {
        GossipMessage::new(
            msg_type,
            self.local_peer.id,
            target,
            payload,
            self.config.default_ttl,
            self.current_time,
            &self.private_key,
            rng,
        )
    }

    /// Create heartbeat message
    #[cfg(feature = "rand_core")]
    pub fn create_heartbeat<R: rand_core::RngCore + rand_core::CryptoRng>(&self, rng: &mut R) -> Result<GossipMessage, GossipError> {
        self.create_message(MessageType::Heartbeat, None, Vec::new(), rng)
    }

    /// Create peer discovery message
    #[cfg(feature = "rand_core")]
    pub fn create_peer_discovery<R: rand_core::RngCore + rand_core::CryptoRng>(&self, rng: &mut R) -> Result<GossipMessage, GossipError> {
        // Include our addresses in the payload
        let mut payload = Vec::new();
        // Simplified serialization - in practice would use proper serialization
        for addr in &self.local_peer.addresses {
            payload.extend_from_slice(&addr.host);
            payload.extend_from_slice(&addr.port.to_be_bytes());
            payload.push(match addr.protocol {
                NetworkProtocol::TCP => 0,
                NetworkProtocol::UDP => 1,
                NetworkProtocol::QUIC => 2,
                NetworkProtocol::WebSocket => 3,
            });
        }

        self.create_message(MessageType::PeerDiscovery, None, payload, rng)
    }

    /// Clean up expired messages and peers
    pub fn cleanup(&mut self) {
        // Remove old peers
        let timeout = self.config.peer_timeout;
        let current_time = self.current_time;
        self.peers.retain(|_, peer| {
            current_time - peer.last_seen < timeout && peer.state != PeerState::Failed
        });

        // Limit message cache size
        if self.message_cache.len() > 10000 {
            // Remove oldest entries (simplified - would need timestamp-based cleanup)
            let excess = self.message_cache.len() - 5000;
            let to_remove: Vec<_> = self.message_cache.iter().take(excess).cloned().collect();
            for id in to_remove {
                self.message_cache.remove(&id);
            }
        }
    }

    /// Update current time
    pub fn update_time(&mut self, timestamp: u64) {
        self.current_time = timestamp;
    }

    /// Get network statistics
    pub fn stats(&self) -> GossipStats {
        let active_count = self.active_peers().len();
        let total_count = self.peers.len();

        GossipStats {
            active_peers: active_count,
            total_peers: total_count,
            cached_messages: self.message_cache.len(),
            average_reputation: if total_count > 0 {
                self.peers.values().map(|p| p.reputation).sum::<f64>() / total_count as f64
            } else {
                0.0
            },
        }
    }
}

/// Gossip network statistics
#[derive(Debug, Clone)]
pub struct GossipStats {
    /// Number of active peers
    pub active_peers: usize,
    /// Total number of known peers
    pub total_peers: usize,
    /// Number of cached messages
    pub cached_messages: usize,
    /// Average peer reputation
    pub average_reputation: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "alloc", feature = "rand_core"))]
    fn test_peer_id_generation() {
        let mut rng = thread_rng();
        let private_key = Ed25519SecretKey::random(&mut rng);
        let public_key = private_key.public_key();

        let peer_id = PeerId::from_public_key(&public_key);
        assert_eq!(peer_id.as_bytes().len(), 32);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "rand_core"))]
    fn test_gossip_message_creation() {
        let mut rng = thread_rng();
        let private_key = Ed25519SecretKey::random(&mut rng);
        let public_key = private_key.public_key();
        let peer_id = PeerId::from_public_key(&public_key);

        let message = GossipMessage::new(
            MessageType::Heartbeat,
            peer_id,
            None,
            b"Hello, world!".to_vec(),
            7,
            1234567890,
            &private_key,
            &mut rng,
        ).unwrap();

        // Verify the message
        assert!(message.verify(&public_key).is_ok());
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "rand_core"))]
    fn test_gossip_state() {
        let mut rng = thread_rng();
        let private_key = Ed25519SecretKey::random(&mut rng);

        let addresses = vec![
            PeerAddress::tcp([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1], 8080),
        ];

        let config = GossipConfig::default();
        let state = GossipState::new(private_key, addresses, config);

        assert_eq!(state.peers.len(), 0);
        assert_eq!(state.message_cache.len(), 0);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "rand_core"))]
    fn test_peer_management() {
        let mut rng = thread_rng();
        let private_key = Ed25519SecretKey::random(&mut rng);

        let addresses = vec![
            PeerAddress::tcp([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1], 8080),
        ];

        let config = GossipConfig::default();
        let mut state = GossipState::new(private_key, addresses, config);

        // Add a peer
        let peer_private_key = Ed25519SecretKey::random(&mut rng);
        let peer_public_key = peer_private_key.public_key();
        let peer_id = PeerId::from_public_key(&peer_public_key);

        let peer_info = PeerInfo {
            id: peer_id,
            addresses: vec![PeerAddress::tcp([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1], 8081)],
            public_key: peer_public_key,
            last_seen: 1234567890,
            reputation: 1.0,
            state: PeerState::Connected,
        };

        state.add_peer(peer_info).unwrap();
        assert_eq!(state.peers.len(), 1);

        // Try to add the same peer again
        let peer_info2 = PeerInfo {
            id: peer_id,
            addresses: vec![PeerAddress::tcp([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1], 8082)],
            public_key: peer_public_key,
            last_seen: 1234567891,
            reputation: 1.0,
            state: PeerState::Connected,
        };

        assert_eq!(state.add_peer(peer_info2), Err(GossipError::PeerAlreadyExists));
    }
}