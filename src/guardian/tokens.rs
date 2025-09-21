//! Guardian token serialization and transport
//!
//! Provides utilities for serializing, deserializing, and transporting
//! Guardian tokens across the Ghostchain ecosystem.

use super::{GuardianToken, GuardianError};
use crate::{protocols::ed25519::Signature, hash::blake3_hash};
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String};

/// Token encoding formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenFormat {
    /// Binary format for high-performance scenarios
    Binary,
    /// Base64 encoded for text transport
    Base64,
    /// JSON format for web APIs
    #[cfg(feature = "alloc")]
    Json,
}

/// Token serialization errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Invalid token format
    InvalidFormat,
    /// Serialization failed
    SerializationFailed,
    /// Deserialization failed
    DeserializationFailed,
    /// Unsupported format
    UnsupportedFormat,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::InvalidFormat => write!(f, "Invalid token format"),
            TokenError::SerializationFailed => write!(f, "Token serialization failed"),
            TokenError::DeserializationFailed => write!(f, "Token deserialization failed"),
            TokenError::UnsupportedFormat => write!(f, "Unsupported token format"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TokenError {}

/// Guardian token serializer/deserializer
#[cfg(feature = "alloc")]
pub struct TokenCodec;

#[cfg(feature = "alloc")]
impl TokenCodec {
    /// Serialize a Guardian token to bytes
    pub fn serialize_binary(token: &GuardianToken) -> Result<Vec<u8>, TokenError> {
        let mut buffer = Vec::new();

        // Version (1 byte)
        buffer.push(1u8);

        // DID length and data
        let did_str = token.did.to_string();
        let did_bytes = did_str.as_bytes();
        if did_bytes.len() > 255 {
            return Err(TokenError::SerializationFailed);
        }
        buffer.push(did_bytes.len() as u8);
        buffer.extend_from_slice(did_bytes);

        // Timestamps (8 bytes each)
        buffer.extend_from_slice(&token.issued_at.to_le_bytes());
        buffer.extend_from_slice(&token.expires_at.to_le_bytes());

        // Nonce (16 bytes)
        buffer.extend_from_slice(&token.nonce);

        // Permissions count
        if token.permissions.len() > 65535 {
            return Err(TokenError::SerializationFailed);
        }
        buffer.extend_from_slice(&(token.permissions.len() as u16).to_le_bytes());

        // Permissions
        for perm in &token.permissions {
            // Service name
            let service_bytes = perm.service.as_bytes();
            if service_bytes.len() > 255 {
                return Err(TokenError::SerializationFailed);
            }
            buffer.push(service_bytes.len() as u8);
            buffer.extend_from_slice(service_bytes);

            // Operations count
            if perm.operations.len() > 255 {
                return Err(TokenError::SerializationFailed);
            }
            buffer.push(perm.operations.len() as u8);

            // Operations
            for op in &perm.operations {
                let op_bytes = op.as_bytes();
                if op_bytes.len() > 255 {
                    return Err(TokenError::SerializationFailed);
                }
                buffer.push(op_bytes.len() as u8);
                buffer.extend_from_slice(op_bytes);
            }

            // Constraints flag (simplified - just a boolean for now)
            buffer.push(if perm.constraints.is_some() { 1 } else { 0 });
        }

        // Signature (64 bytes)
        buffer.extend_from_slice(&token.signature.to_bytes());

        Ok(buffer)
    }

    /// Deserialize a Guardian token from bytes
    pub fn deserialize_binary(data: &[u8]) -> Result<GuardianToken, TokenError> {
        if data.is_empty() {
            return Err(TokenError::InvalidFormat);
        }

        let mut offset = 0;

        // Version
        let version = data[offset];
        offset += 1;
        if version != 1 {
            return Err(TokenError::UnsupportedFormat);
        }

        // DID
        if offset >= data.len() {
            return Err(TokenError::InvalidFormat);
        }
        let did_len = data[offset] as usize;
        offset += 1;

        if offset + did_len > data.len() {
            return Err(TokenError::InvalidFormat);
        }
        let did_str = String::from_utf8(data[offset..offset + did_len].to_vec())
            .map_err(|_| TokenError::DeserializationFailed)?;
        let did = super::auth::Did::from_string(&did_str)
            .map_err(|_| TokenError::DeserializationFailed)?;
        offset += did_len;

        // Timestamps
        if offset + 16 > data.len() {
            return Err(TokenError::InvalidFormat);
        }
        let issued_at = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;

        let expires_at = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;

        // Nonce
        if offset + 16 > data.len() {
            return Err(TokenError::InvalidFormat);
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;

        // Permissions count
        if offset + 2 > data.len() {
            return Err(TokenError::InvalidFormat);
        }
        let perm_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Permissions
        let mut permissions = Vec::with_capacity(perm_count);
        for _ in 0..perm_count {
            // Service name
            if offset >= data.len() {
                return Err(TokenError::InvalidFormat);
            }
            let service_len = data[offset] as usize;
            offset += 1;

            if offset + service_len > data.len() {
                return Err(TokenError::InvalidFormat);
            }
            let service = String::from_utf8(data[offset..offset + service_len].to_vec())
                .map_err(|_| TokenError::DeserializationFailed)?;
            offset += service_len;

            // Operations count
            if offset >= data.len() {
                return Err(TokenError::InvalidFormat);
            }
            let op_count = data[offset] as usize;
            offset += 1;

            // Operations
            let mut operations = Vec::with_capacity(op_count);
            for _ in 0..op_count {
                if offset >= data.len() {
                    return Err(TokenError::InvalidFormat);
                }
                let op_len = data[offset] as usize;
                offset += 1;

                if offset + op_len > data.len() {
                    return Err(TokenError::InvalidFormat);
                }
                let operation = String::from_utf8(data[offset..offset + op_len].to_vec())
                    .map_err(|_| TokenError::DeserializationFailed)?;
                operations.push(operation);
                offset += op_len;
            }

            // Constraints flag
            if offset >= data.len() {
                return Err(TokenError::InvalidFormat);
            }
            let _has_constraints = data[offset] != 0;
            offset += 1;

            permissions.push(super::permissions::Permission::new(service, operations));
        }

        // Signature
        if offset + 64 > data.len() {
            return Err(TokenError::InvalidFormat);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&data[offset..offset + 64]);
        let signature = Signature::from_bytes(sig_bytes);

        Ok(GuardianToken {
            did,
            permissions,
            issued_at,
            expires_at,
            nonce,
            signature,
        })
    }

    /// Encode token as base64 string
    pub fn encode_base64(token: &GuardianToken) -> Result<String, TokenError> {
        let binary = Self::serialize_binary(token)?;
        Ok(base64_encode(&binary))
    }

    /// Decode token from base64 string
    pub fn decode_base64(encoded: &str) -> Result<GuardianToken, TokenError> {
        let binary = base64_decode(encoded)
            .map_err(|_| TokenError::DeserializationFailed)?;
        Self::deserialize_binary(&binary)
    }

    /// Encode token as JSON string
    #[cfg(feature = "serde")]
    pub fn encode_json(token: &GuardianToken) -> Result<String, TokenError> {
        serde_json::to_string(token)
            .map_err(|_| TokenError::SerializationFailed)
    }

    /// Decode token from JSON string
    #[cfg(feature = "serde")]
    pub fn decode_json(json: &str) -> Result<GuardianToken, TokenError> {
        serde_json::from_str(json)
            .map_err(|_| TokenError::DeserializationFailed)
    }
}

/// Simple base64 encoding (basic implementation)
fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in input.chunks(3) {
        let mut buf = [0u8; 3];
        for (i, &byte) in chunk.iter().enumerate() {
            buf[i] = byte;
        }

        let b = (buf[0] as u32) << 16 | (buf[1] as u32) << 8 | (buf[2] as u32);

        result.push(CHARS[((b >> 18) & 63) as usize] as char);
        result.push(CHARS[((b >> 12) & 63) as usize] as char);
        result.push(if chunk.len() > 1 { CHARS[((b >> 6) & 63) as usize] as char } else { '=' });
        result.push(if chunk.len() > 2 { CHARS[(b & 63) as usize] as char } else { '=' });
    }

    result
}

/// Simple base64 decoding (basic implementation)
#[cfg(feature = "alloc")]
fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let chars = input.as_bytes();
    let mut result = Vec::new();

    for chunk in chars.chunks(4) {
        if chunk.len() != 4 {
            return Err("Invalid base64 length");
        }

        let mut values = [0u8; 4];
        for (i, &c) in chunk.iter().enumerate() {
            values[i] = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => 0,
                _ => return Err("Invalid base64 character"),
            };
        }

        let b = (values[0] as u32) << 18 | (values[1] as u32) << 12 | (values[2] as u32) << 6 | (values[3] as u32);

        result.push((b >> 16) as u8);
        if chunk[2] != b'=' {
            result.push((b >> 8) as u8);
        }
        if chunk[3] != b'=' {
            result.push(b as u8);
        }
    }

    Ok(result)
}

/// HTTP Authorization header utilities
#[cfg(feature = "alloc")]
pub struct AuthorizationHeader;

#[cfg(feature = "alloc")]
impl AuthorizationHeader {
    /// Create Bearer token authorization header
    pub fn bearer(token: &GuardianToken) -> Result<String, TokenError> {
        let encoded = TokenCodec::encode_base64(token)?;
        Ok(format!("Bearer {}", encoded))
    }

    /// Parse Bearer token from authorization header
    pub fn parse_bearer(header: &str) -> Result<GuardianToken, TokenError> {
        if !header.starts_with("Bearer ") {
            return Err(TokenError::InvalidFormat);
        }

        let token_part = &header[7..]; // Skip "Bearer "
        TokenCodec::decode_base64(token_part)
    }

    /// Create custom Guardian authorization header
    pub fn guardian(token: &GuardianToken) -> Result<String, TokenError> {
        let encoded = TokenCodec::encode_base64(token)?;
        Ok(format!("Guardian {}", encoded))
    }

    /// Parse Guardian token from authorization header
    pub fn parse_guardian(header: &str) -> Result<GuardianToken, TokenError> {
        if !header.starts_with("Guardian ") {
            return Err(TokenError::InvalidFormat);
        }

        let token_part = &header[9..]; // Skip "Guardian "
        TokenCodec::decode_base64(token_part)
    }
}

/// Token validation utilities
#[cfg(feature = "alloc")]
pub struct TokenValidator;

#[cfg(feature = "alloc")]
impl TokenValidator {
    /// Quick validation of token format without cryptographic verification
    pub fn validate_format(token: &GuardianToken) -> Result<(), GuardianError> {
        // Check basic token structure
        if token.did.to_string().is_empty() {
            return Err(GuardianError::InvalidToken);
        }

        if token.expires_at <= token.issued_at {
            return Err(GuardianError::InvalidToken);
        }

        if token.permissions.is_empty() {
            return Err(GuardianError::InvalidToken);
        }

        // Check permission format
        for perm in &token.permissions {
            if perm.service.is_empty() || perm.operations.is_empty() {
                return Err(GuardianError::InvalidToken);
            }
        }

        Ok(())
    }

    /// Calculate token fingerprint for caching/indexing
    pub fn fingerprint(token: &GuardianToken) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(token.did.to_string().as_bytes());
        hasher.update(&token.issued_at.to_le_bytes());
        hasher.update(&token.expires_at.to_le_bytes());
        hasher.update(&token.nonce);

        let hash = hasher.finalize();
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(hash.as_bytes());
        fingerprint
    }

    /// Check if token will expire within given seconds
    #[cfg(feature = "std")]
    pub fn expires_within(token: &GuardianToken, seconds: u64) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        token.expires_at <= now + seconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scalar;
    use crate::protocols::ed25519::SecretKey;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_token_binary_serialization() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let secret_key = SecretKey::from_scalar(secret);
        let issuer = super::super::auth::GuardianIssuer::new(secret_key);

        let holder_did = super::super::auth::Did::new("ghostchain".to_string(), "test123".to_string()).unwrap();
        let permissions = vec![
            super::super::permissions::Permission::new(
                "ghostd".to_string(),
                vec!["read".to_string(), "write".to_string()],
            ),
        ];

        let token = issuer.issue_token_with_timestamps(holder_did, permissions, 1000, 2000).unwrap();

        // Serialize and deserialize
        let serialized = TokenCodec::serialize_binary(&token).unwrap();
        let deserialized = TokenCodec::deserialize_binary(&serialized).unwrap();

        assert_eq!(token.did, deserialized.did);
        assert_eq!(token.issued_at, deserialized.issued_at);
        assert_eq!(token.expires_at, deserialized.expires_at);
        assert_eq!(token.nonce, deserialized.nonce);
        assert_eq!(token.permissions.len(), deserialized.permissions.len());
        assert_eq!(token.signature.to_bytes(), deserialized.signature.to_bytes());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_base64_encoding() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let secret_key = SecretKey::from_scalar(secret);
        let issuer = super::super::auth::GuardianIssuer::new(secret_key);

        let holder_did = super::super::auth::Did::new("ghostchain".to_string(), "test123".to_string()).unwrap();
        let permissions = vec![
            super::super::permissions::Permission::new(
                "ghostd".to_string(),
                vec!["read".to_string()],
            ),
        ];

        let token = issuer.issue_token_with_timestamps(holder_did, permissions, 1000, 2000).unwrap();

        // Encode and decode
        let encoded = TokenCodec::encode_base64(&token).unwrap();
        let decoded = TokenCodec::decode_base64(&encoded).unwrap();

        assert_eq!(token.did, decoded.did);
        assert_eq!(token.signature.to_bytes(), decoded.signature.to_bytes());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_authorization_headers() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let secret_key = SecretKey::from_scalar(secret);
        let issuer = super::super::auth::GuardianIssuer::new(secret_key);

        let holder_did = super::super::auth::Did::new("ghostchain".to_string(), "test123".to_string()).unwrap();
        let permissions = vec![
            super::super::permissions::Permission::new(
                "ghostd".to_string(),
                vec!["read".to_string()],
            ),
        ];

        let token = issuer.issue_token_with_timestamps(holder_did, permissions, 1000, 2000).unwrap();

        // Test Bearer header
        let bearer_header = AuthorizationHeader::bearer(&token).unwrap();
        assert!(bearer_header.starts_with("Bearer "));

        let parsed_bearer = AuthorizationHeader::parse_bearer(&bearer_header).unwrap();
        assert_eq!(token.did, parsed_bearer.did);

        // Test Guardian header
        let guardian_header = AuthorizationHeader::guardian(&token).unwrap();
        assert!(guardian_header.starts_with("Guardian "));

        let parsed_guardian = AuthorizationHeader::parse_guardian(&guardian_header).unwrap();
        assert_eq!(token.did, parsed_guardian.did);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_token_validation() {
        let secret = Scalar::from_bytes_mod_order([1u8; 32]);
        let secret_key = SecretKey::from_scalar(secret);
        let issuer = super::super::auth::GuardianIssuer::new(secret_key);

        let holder_did = super::super::auth::Did::new("ghostchain".to_string(), "test123".to_string()).unwrap();
        let permissions = vec![
            super::super::permissions::Permission::new(
                "ghostd".to_string(),
                vec!["read".to_string()],
            ),
        ];

        let token = issuer.issue_token_with_timestamps(holder_did, permissions, 1000, 2000).unwrap();

        assert!(TokenValidator::validate_format(&token).is_ok());

        let fingerprint1 = TokenValidator::fingerprint(&token);
        let fingerprint2 = TokenValidator::fingerprint(&token);
        assert_eq!(fingerprint1, fingerprint2);
    }
}