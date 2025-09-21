//! Guardian Framework Authentication
//!
//! Provides zero-trust authentication for Ghostchain ecosystem services
//! including GHOSTD, WALLETD, CNS, and GID services.

use crate::{
    EdwardsPoint, Scalar,
    protocols::ed25519::{SecretKey, PublicKey, Signature, sign, verify},
    hash::blake3_hash,
};
use core::fmt;

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String, boxed::Box};

/// Guardian authentication errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianError {
    /// Invalid token format
    InvalidToken,
    /// Token has expired
    Expired,
    /// Invalid signature
    InvalidSignature,
    /// Insufficient permissions
    InsufficientPermissions,
    /// Unknown issuer
    UnknownIssuer,
    /// Token creation failed
    CreationFailed,
    /// DID validation failed
    InvalidDid,
}

impl fmt::Display for GuardianError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardianError::InvalidToken => write!(f, "Invalid Guardian token format"),
            GuardianError::Expired => write!(f, "Guardian token has expired"),
            GuardianError::InvalidSignature => write!(f, "Invalid Guardian token signature"),
            GuardianError::InsufficientPermissions => write!(f, "Insufficient permissions for operation"),
            GuardianError::UnknownIssuer => write!(f, "Unknown Guardian token issuer"),
            GuardianError::CreationFailed => write!(f, "Failed to create Guardian token"),
            GuardianError::InvalidDid => write!(f, "Invalid DID format"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GuardianError {}

/// Decentralized Identifier (DID) for identity management
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg(feature = "alloc")]
pub struct Did {
    method: String,
    identifier: String,
}

#[cfg(feature = "alloc")]
impl Did {
    /// Create a new DID
    pub fn new(method: String, identifier: String) -> Result<Self, GuardianError> {
        if method.is_empty() || identifier.is_empty() {
            return Err(GuardianError::InvalidDid);
        }

        Ok(Self { method, identifier })
    }

    /// Create a DID from string representation (did:method:identifier)
    pub fn from_string(did_str: &str) -> Result<Self, GuardianError> {
        let parts: Vec<&str> = did_str.split(':').collect();
        if parts.len() != 3 || parts[0] != "did" {
            return Err(GuardianError::InvalidDid);
        }

        Ok(Self {
            method: parts[1].to_string(),
            identifier: parts[2].to_string(),
        })
    }

    /// Convert DID to string representation
    pub fn to_string(&self) -> String {
        format!("did:{}:{}", self.method, self.identifier)
    }

    /// Get DID method
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Get DID identifier
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Create a Ghostchain DID from public key
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let key_bytes = public_key.to_bytes();
        let hash = blake3_hash(&key_bytes);
        let identifier = hex::encode(&hash[..16]); // Use first 16 bytes as identifier

        Self {
            method: "ghostchain".to_string(),
            identifier,
        }
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Guardian authentication token for zero-trust access
#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub struct GuardianToken {
    /// Decentralized identifier of the token holder
    pub did: Did,
    /// Granted permissions
    pub permissions: Vec<super::permissions::Permission>,
    /// Token issuance timestamp
    pub issued_at: u64,
    /// Token expiration timestamp
    pub expires_at: u64,
    /// Token nonce for replay protection
    pub nonce: [u8; 16],
    /// Issuer's signature over the token
    pub signature: Signature,
}

#[cfg(feature = "alloc")]
impl GuardianToken {
    /// Get the token payload for signing
    fn get_signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // DID
        payload.extend_from_slice(self.did.to_string().as_bytes());

        // Permissions (sorted for deterministic signing)
        let mut perms = self.permissions.clone();
        perms.sort_by(|a, b| a.service.cmp(&b.service));
        for perm in perms {
            payload.extend_from_slice(perm.service.as_bytes());
            for op in &perm.operations {
                payload.extend_from_slice(op.as_bytes());
            }
        }

        // Timestamps
        payload.extend_from_slice(&self.issued_at.to_le_bytes());
        payload.extend_from_slice(&self.expires_at.to_le_bytes());

        // Nonce
        payload.extend_from_slice(&self.nonce);

        payload
    }

    /// Check if token is valid at given timestamp
    pub fn is_valid_at(&self, timestamp: u64) -> bool {
        timestamp >= self.issued_at && timestamp < self.expires_at
    }

    /// Check if token is currently valid
    #[cfg(feature = "std")]
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.is_valid_at(now)
    }

    /// Check if token has permission for a specific operation
    pub fn has_permission(&self, service: &str, operation: &str) -> bool {
        self.permissions.iter().any(|perm| {
            perm.service == service && perm.operations.contains(&operation.to_string())
        })
    }

    /// Get remaining token lifetime in seconds
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
}

/// Guardian token issuer for creating and verifying tokens
#[cfg(feature = "alloc")]
pub struct GuardianIssuer {
    secret_key: SecretKey,
    public_key: PublicKey,
    issuer_did: Did,
}

#[cfg(feature = "alloc")]
impl GuardianIssuer {
    /// Create a new Guardian issuer
    pub fn new(secret_key: SecretKey) -> Self {
        let public_key = PublicKey::from(&secret_key);
        let issuer_did = Did::from_public_key(&public_key);

        Self {
            secret_key,
            public_key,
            issuer_did,
        }
    }

    /// Get issuer's public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get issuer's DID
    pub fn did(&self) -> &Did {
        &self.issuer_did
    }

    /// Issue a new Guardian token
    #[cfg(feature = "std")]
    pub fn issue_token(
        &self,
        did: Did,
        permissions: Vec<super::permissions::Permission>,
        ttl_seconds: u64,
    ) -> Result<GuardianToken, GuardianError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GuardianError::CreationFailed)?
            .as_secs();

        self.issue_token_with_timestamps(did, permissions, now, now + ttl_seconds)
    }

    /// Issue a token with explicit timestamps
    pub fn issue_token_with_timestamps(
        &self,
        did: Did,
        permissions: Vec<super::permissions::Permission>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<GuardianToken, GuardianError> {
        if expires_at <= issued_at {
            return Err(GuardianError::CreationFailed);
        }

        // Generate random nonce
        let mut nonce = [0u8; 16];
        #[cfg(feature = "rand_core")]
        {
            use rand_core::RngCore;
            let mut rng = rand_core::OsRng;
            rng.fill_bytes(&mut nonce);
        }
        #[cfg(not(feature = "rand_core"))]
        {
            // Fallback: use timestamp-based nonce
            let ts_bytes = issued_at.to_le_bytes();
            nonce[..8].copy_from_slice(&ts_bytes);
            nonce[8..].copy_from_slice(&ts_bytes);
        }

        let mut token = GuardianToken {
            did,
            permissions,
            issued_at,
            expires_at,
            nonce,
            signature: Signature::from_bytes([0u8; 64]), // Placeholder
        };

        // Sign the token
        let payload = token.get_signing_payload();
        let signature = sign(&self.secret_key, &payload);
        token.signature = signature;

        Ok(token)
    }

    /// Verify a Guardian token
    pub fn verify_token(&self, token: &GuardianToken) -> Result<(), GuardianError> {
        // Check if token is valid (not expired)
        #[cfg(feature = "std")]
        if !token.is_valid() {
            return Err(GuardianError::Expired);
        }

        // Verify signature
        let payload = token.get_signing_payload();
        if !verify(&self.public_key, &payload, &token.signature) {
            return Err(GuardianError::InvalidSignature);
        }

        Ok(())
    }
}

/// Guardian token verifier for validating tokens without issuing capability
#[cfg(feature = "alloc")]
pub struct GuardianVerifier {
    trusted_issuers: Vec<(Did, PublicKey)>,
}

#[cfg(feature = "alloc")]
impl GuardianVerifier {
    /// Create a new verifier with trusted issuers
    pub fn new() -> Self {
        Self {
            trusted_issuers: Vec::new(),
        }
    }

    /// Add a trusted issuer
    pub fn add_trusted_issuer(&mut self, did: Did, public_key: PublicKey) {
        self.trusted_issuers.push((did, public_key));
    }

    /// Remove a trusted issuer
    pub fn remove_trusted_issuer(&mut self, did: &Did) {
        self.trusted_issuers.retain(|(issuer_did, _)| issuer_did != did);
    }

    /// Verify a token against trusted issuers
    pub fn verify_token(&self, token: &GuardianToken) -> Result<&PublicKey, GuardianError> {
        // Check if token is valid (not expired)
        #[cfg(feature = "std")]
        if !token.is_valid() {
            return Err(GuardianError::Expired);
        }

        // Try to find a trusted issuer and verify signature
        let payload = token.get_signing_payload();

        for (issuer_did, public_key) in &self.trusted_issuers {
            if verify(public_key, &payload, &token.signature) {
                return Ok(public_key);
            }
        }

        Err(GuardianError::InvalidSignature)
    }

    /// Verify token and check specific permission
    pub fn verify_permission(
        &self,
        token: &GuardianToken,
        service: &str,
        operation: &str,
    ) -> Result<(), GuardianError> {
        // First verify the token
        self.verify_token(token)?;

        // Check permission
        if !token.has_permission(service, operation) {
            return Err(GuardianError::InsufficientPermissions);
        }

        Ok(())
    }

    /// Get list of trusted issuer DIDs
    pub fn trusted_issuer_dids(&self) -> Vec<&Did> {
        self.trusted_issuers.iter().map(|(did, _)| did).collect()
    }
}

#[cfg(feature = "alloc")]
impl Default for GuardianVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scalar;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_did_creation() {
        let did = Did::new("ghostchain".to_string(), "test123".to_string()).unwrap();
        assert_eq!(did.method(), "ghostchain");
        assert_eq!(did.identifier(), "test123");
        assert_eq!(did.to_string(), "did:ghostchain:test123");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_did_from_string() {
        let did_str = "did:ghostchain:abc123";
        let did = Did::from_string(did_str).unwrap();
        assert_eq!(did.method(), "ghostchain");
        assert_eq!(did.identifier(), "abc123");
        assert_eq!(did.to_string(), did_str);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_did_from_public_key() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let secret_key = SecretKey::from_scalar(secret);
        let public_key = PublicKey::from(&secret_key);

        let did = Did::from_public_key(&public_key);
        assert_eq!(did.method(), "ghostchain");
        assert!(!did.identifier().is_empty());
    }

    #[cfg(all(feature = "alloc", feature = "std"))]
    #[test]
    fn test_guardian_token_issuance() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let secret_key = SecretKey::from_scalar(secret);
        let issuer = GuardianIssuer::new(secret_key);

        let holder_did = Did::new("ghostchain".to_string(), "holder123".to_string()).unwrap();
        let permissions = vec![
            super::permissions::Permission::new(
                "ghostd".to_string(),
                vec!["read".to_string(), "write".to_string()],
            ),
        ];

        let token = issuer.issue_token(holder_did.clone(), permissions, 3600).unwrap();

        assert_eq!(token.did, holder_did);
        assert!(token.is_valid());
        assert!(token.has_permission("ghostd", "read"));
        assert!(token.has_permission("ghostd", "write"));
        assert!(!token.has_permission("walletd", "read"));
    }

    #[cfg(all(feature = "alloc", feature = "std"))]
    #[test]
    fn test_guardian_token_verification() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let secret_key = SecretKey::from_scalar(secret);
        let issuer = GuardianIssuer::new(secret_key);

        let holder_did = Did::new("ghostchain".to_string(), "holder123".to_string()).unwrap();
        let permissions = vec![
            super::permissions::Permission::new(
                "ghostd".to_string(),
                vec!["read".to_string()],
            ),
        ];

        let token = issuer.issue_token(holder_did, permissions, 3600).unwrap();

        // Issuer should be able to verify its own token
        assert!(issuer.verify_token(&token).is_ok());

        // Verifier with trusted issuer should accept the token
        let mut verifier = GuardianVerifier::new();
        verifier.add_trusted_issuer(issuer.did().clone(), *issuer.public_key());

        assert!(verifier.verify_token(&token).is_ok());
        assert!(verifier.verify_permission(&token, "ghostd", "read").is_ok());
        assert!(verifier.verify_permission(&token, "ghostd", "write").is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_expired_token() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let secret_key = SecretKey::from_scalar(secret);
        let issuer = GuardianIssuer::new(secret_key);

        let holder_did = Did::new("ghostchain".to_string(), "holder123".to_string()).unwrap();
        let permissions = vec![];

        // Create an already expired token
        let now = 1000u64;
        let expired_token = issuer.issue_token_with_timestamps(
            holder_did,
            permissions,
            now - 100,
            now - 50,
        ).unwrap();

        assert!(!expired_token.is_valid_at(now));
    }
}