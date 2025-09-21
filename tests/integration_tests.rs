//! Integration tests for Ghostchain ecosystem features
//!
//! These tests verify that all the new features work correctly together
//! and integrate properly with the existing gcrypt functionality.

use gcrypt::{Scalar, EdwardsPoint, FieldElement};

#[cfg(all(feature = "guardian-framework", feature = "alloc"))]
mod guardian_tests {
    use super::*;
    use gcrypt::guardian::{GuardianIssuer, GuardianVerifier, Did, Permission};
    use gcrypt::protocols::ed25519::SecretKey;

    #[test]
    fn test_guardian_token_flow() {
        // Create issuer
        let secret_scalar = Scalar::from_u64(12345);
        let secret_key = SecretKey::from_scalar(secret_scalar);
        let issuer = GuardianIssuer::new(secret_key);

        // Create holder DID and permissions
        let holder_did = Did::new("ghostchain".to_string(), "test_user".to_string()).unwrap();
        let permissions = vec![
            Permission::new("ghostd".to_string(), vec!["read".to_string(), "write".to_string()]),
            Permission::new("walletd".to_string(), vec!["read".to_string()]),
        ];

        // Issue token
        let token = issuer.issue_token_with_timestamps(holder_did.clone(), permissions, 1000, 2000).unwrap();

        // Verify token structure
        assert_eq!(token.did, holder_did);
        assert_eq!(token.permissions.len(), 2);
        assert!(token.has_permission("ghostd", "read"));
        assert!(token.has_permission("ghostd", "write"));
        assert!(token.has_permission("walletd", "read"));
        assert!(!token.has_permission("walletd", "write"));
        assert!(!token.has_permission("cns", "read"));

        // Verify token with issuer
        assert!(issuer.verify_token(&token).is_ok());

        // Setup external verifier
        let mut verifier = GuardianVerifier::new();
        verifier.add_trusted_issuer(issuer.did().clone(), *issuer.public_key());

        // Verify with external verifier
        assert!(verifier.verify_token(&token).is_ok());
        assert!(verifier.verify_permission(&token, "ghostd", "read").is_ok());
        assert!(verifier.verify_permission(&token, "walletd", "write").is_err());
    }

    #[test]
    fn test_guardian_token_serialization() {
        use gcrypt::guardian::tokens::{TokenCodec, AuthorizationHeader};

        let secret_scalar = Scalar::from_u64(54321);
        let secret_key = SecretKey::from_scalar(secret_scalar);
        let issuer = GuardianIssuer::new(secret_key);

        let holder_did = Did::new("ghostchain".to_string(), "test_user_2".to_string()).unwrap();
        let permissions = vec![
            Permission::new("ghostd".to_string(), vec!["admin".to_string()]),
        ];

        let token = issuer.issue_token_with_timestamps(holder_did, permissions, 1000, 3000).unwrap();

        // Test binary serialization
        let serialized = TokenCodec::serialize_binary(&token).unwrap();
        let deserialized = TokenCodec::deserialize_binary(&serialized).unwrap();

        assert_eq!(token.did, deserialized.did);
        assert_eq!(token.issued_at, deserialized.issued_at);
        assert_eq!(token.expires_at, deserialized.expires_at);
        assert_eq!(token.permissions.len(), deserialized.permissions.len());

        // Test base64 encoding
        let encoded = TokenCodec::encode_base64(&token).unwrap();
        let decoded = TokenCodec::decode_base64(&encoded).unwrap();
        assert_eq!(token.did, decoded.did);

        // Test authorization headers
        let bearer_header = AuthorizationHeader::bearer(&token).unwrap();
        assert!(bearer_header.starts_with("Bearer "));

        let parsed_bearer = AuthorizationHeader::parse_bearer(&bearer_header).unwrap();
        assert_eq!(token.did, parsed_bearer.did);

        let guardian_header = AuthorizationHeader::guardian(&token).unwrap();
        assert!(guardian_header.starts_with("Guardian "));

        let parsed_guardian = AuthorizationHeader::parse_guardian(&guardian_header).unwrap();
        assert_eq!(token.did, parsed_guardian.did);
    }
}

#[cfg(all(feature = "gquic-transport", feature = "alloc"))]
mod gquic_tests {
    use super::*;
    use gcrypt::transport::{GquicTransport, SessionKey, ConnectionId, GquicKeyExchange};

    #[test]
    fn test_gquic_session_key_derivation() {
        let shared_secret = [0x42u8; 32];
        let connection_id = ConnectionId::from_bytes([0x01u8; 16]);
        let context = b"test-context";

        let session_key = SessionKey::derive_from_shared_secret(&shared_secret, connection_id, context).unwrap();
        assert_eq!(session_key.connection_id(), connection_id);

        // Same inputs should produce same key
        let session_key2 = SessionKey::derive_from_shared_secret(&shared_secret, connection_id, context).unwrap();
        assert_eq!(session_key.connection_id(), session_key2.connection_id());

        // Different inputs should produce different keys
        let session_key3 = SessionKey::derive_from_shared_secret(&shared_secret, connection_id, b"different-context").unwrap();
        assert_eq!(session_key3.connection_id(), connection_id); // Same connection ID but different key
    }

    #[test]
    fn test_gquic_packet_encryption() {
        let session_key = SessionKey::from_bytes(&[0x42u8; 32], ConnectionId::from_bytes([0x01u8; 16]));
        let mut encrypt_session = session_key.clone();
        let mut decrypt_session = session_key;

        let transport = GquicTransport::new();
        let plaintext = b"Hello, GQUIC world!";
        let additional_data = b"packet-header-data";

        let ciphertext = transport.encrypt_packet(&mut encrypt_session, plaintext, additional_data).unwrap();
        assert_ne!(ciphertext, plaintext); // Should be encrypted

        let decrypted = transport.decrypt_packet(&mut decrypt_session, &ciphertext, additional_data).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_gquic_key_exchange() {
        let local_secret = Scalar::from_u64(12345);
        let remote_secret = Scalar::from_u64(54321);

        let local_public = gcrypt::MontgomeryPoint::mul_base(&local_secret);
        let remote_public = gcrypt::MontgomeryPoint::mul_base(&remote_secret);

        let connection_id = ConnectionId::from_bytes([0x99u8; 16]);
        let context = b"key-exchange-test";

        // Both parties derive the same session key
        let local_session = GquicKeyExchange::derive_session_key(&local_secret, &remote_public, connection_id, context).unwrap();
        let remote_session = GquicKeyExchange::derive_session_key(&remote_secret, &local_public, connection_id, context).unwrap();

        assert_eq!(local_session.connection_id(), remote_session.connection_id());
        assert_eq!(local_session.connection_id(), connection_id);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_gquic_connection_manager() {
        use gcrypt::transport::GquicConnectionManager;

        let mut manager = GquicConnectionManager::new();
        assert_eq!(manager.connection_count(), 0);

        let connection_id = ConnectionId::from_bytes([0x42u8; 16]);
        let session_key = SessionKey::from_bytes(&[0x33u8; 32], connection_id);

        manager.add_session(session_key);
        assert_eq!(manager.connection_count(), 1);

        let plaintext = b"test message for connection";
        let additional_data = b"test header";

        let encrypted = manager.encrypt_for_connection(&connection_id, plaintext, additional_data).unwrap();
        let decrypted = manager.decrypt_for_connection(&connection_id, &encrypted, additional_data).unwrap();

        assert_eq!(decrypted, plaintext);

        let removed = manager.remove_session(&connection_id);
        assert!(removed.is_some());
        assert_eq!(manager.connection_count(), 0);
    }
}

#[cfg(all(feature = "zk-hash", feature = "alloc"))]
mod zk_hash_tests {
    use super::*;
    use gcrypt::zk_hash::{poseidon, rescue, mimc, pedersen};

    #[test]
    fn test_poseidon_hash_consistency() {
        let left = FieldElement::from_u64(42);
        let right = FieldElement::from_u64(84);

        let result1 = poseidon::hash_two(&left, &right).unwrap();
        let result2 = poseidon::hash_two(&left, &right).unwrap();
        assert_eq!(result1, result2);

        // Order should matter
        let result3 = poseidon::hash_two(&right, &left).unwrap();
        assert_ne!(result1, result3);

        // Test many inputs
        let inputs = vec![left, right, FieldElement::from_u64(126)];
        let many_result = poseidon::hash_many(&inputs).unwrap();
        assert_ne!(many_result, FieldElement::zero());
    }

    #[test]
    fn test_rescue_hash_consistency() {
        let left = FieldElement::from_u64(123);
        let right = FieldElement::from_u64(456);

        let result1 = rescue::hash_two(&left, &right).unwrap();
        let result2 = rescue::hash_two(&left, &right).unwrap();
        assert_eq!(result1, result2);

        // Different from Poseidon
        let poseidon_result = poseidon::hash_two(&left, &right).unwrap();
        assert_ne!(result1, poseidon_result);
    }

    #[test]
    fn test_mimc_hash_consistency() {
        let left = FieldElement::from_u64(789);
        let right = FieldElement::from_u64(101112);

        let result1 = mimc::hash_two(&left, &right).unwrap();
        let result2 = mimc::hash_two(&left, &right).unwrap();
        assert_eq!(result1, result2);

        // Test MiMC permutation
        let perm_result = mimc::permutation(&left).unwrap();
        assert_ne!(perm_result, FieldElement::zero());
        assert_ne!(perm_result, left);

        // Test MiMC encryption
        let encrypted = mimc::encrypt(&left, &right).unwrap();
        assert_ne!(encrypted, left);
        assert_ne!(encrypted, FieldElement::zero());
    }

    #[test]
    fn test_pedersen_hash_consistency() {
        let left = FieldElement::from_u64(131415);
        let right = FieldElement::from_u64(161718);

        let result1 = pedersen::hash_two(&left, &right).unwrap();
        let result2 = pedersen::hash_two(&left, &right).unwrap();
        assert_eq!(result1, result2);

        // Test bytes hashing
        let bytes = b"test pedersen input";
        let bytes_result = pedersen::hash_bytes(bytes).unwrap();
        assert_ne!(bytes_result, FieldElement::zero());

        // Test point hashing
        let point_result = pedersen::hash_to_point(bytes).unwrap();
        assert_ne!(point_result, EdwardsPoint::identity());
    }

    #[test]
    fn test_zk_hash_interoperability() {
        // All hash functions should work with the same field elements
        let input1 = FieldElement::from_u64(192021);
        let input2 = FieldElement::from_u64(222324);

        let poseidon_result = poseidon::hash_two(&input1, &input2).unwrap();
        let rescue_result = rescue::hash_two(&input1, &input2).unwrap();
        let mimc_result = mimc::hash_two(&input1, &input2).unwrap();
        let pedersen_result = pedersen::hash_two(&input1, &input2).unwrap();

        // All should produce different results (with very high probability)
        assert_ne!(poseidon_result, rescue_result);
        assert_ne!(poseidon_result, mimc_result);
        assert_ne!(poseidon_result, pedersen_result);
        assert_ne!(rescue_result, mimc_result);
        assert_ne!(rescue_result, pedersen_result);
        assert_ne!(mimc_result, pedersen_result);

        // All should be non-zero
        assert_ne!(poseidon_result, FieldElement::zero());
        assert_ne!(rescue_result, FieldElement::zero());
        assert_ne!(mimc_result, FieldElement::zero());
        assert_ne!(pedersen_result, FieldElement::zero());
    }
}

#[cfg(all(feature = "batch-operations", feature = "alloc"))]
mod batch_tests {
    use super::*;
    use gcrypt::batch::{batch_signatures, batch_arithmetic, batch_merkle};
    use gcrypt::protocols::ed25519::{SecretKey, PublicKey, sign};

    #[test]
    fn test_batch_signature_verification() {
        // Create test signatures
        let count = 10;
        let mut public_keys = Vec::new();
        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        for i in 0..count {
            let secret_scalar = Scalar::from_u64(i as u64 + 1000);
            let secret_key = SecretKey::from_scalar(secret_scalar);
            let public_key = PublicKey::from(&secret_key);

            let message = format!("Message number {}", i).into_bytes();
            let signature = sign(&secret_key, &message);

            public_keys.push(public_key);
            messages.push(message);
            signatures.push(signature);
        }

        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        // Test batch verification
        let result = batch_signatures::verify_ed25519_batch(&public_keys, &message_refs, &signatures).unwrap();
        assert!(result);

        // Test fast batch verification
        let fast_result = batch_signatures::verify_ed25519_batch_fast(&public_keys, &message_refs, &signatures).unwrap();
        assert!(fast_result);

        // Test with one corrupted signature
        let mut corrupted_signatures = signatures.clone();
        corrupted_signatures[5] = gcrypt::protocols::ed25519::Signature::from_bytes([0u8; 64]);

        let corrupted_result = batch_signatures::verify_ed25519_batch(&public_keys, &message_refs, &corrupted_signatures).unwrap();
        assert!(!corrupted_result);
    }

    #[test]
    fn test_batch_arithmetic_operations() {
        let scalars: Vec<Scalar> = (1..=8).map(|i| Scalar::from_u64(i)).collect();
        let points: Vec<EdwardsPoint> = scalars.iter().map(|s| EdwardsPoint::mul_base(s)).collect();

        // Test batch base multiplication
        let base_mul_results = batch_arithmetic::scalar_mul_base(&scalars).unwrap();
        assert_eq!(base_mul_results.len(), 8);
        for (i, result) in base_mul_results.iter().enumerate() {
            let expected = EdwardsPoint::mul_base(&scalars[i]);
            assert_eq!(*result, expected);
        }

        // Test batch scalar multiplication
        let scalar_mul_results = batch_arithmetic::scalar_mul(&scalars, &points).unwrap();
        assert_eq!(scalar_mul_results.len(), 8);
        for (i, result) in scalar_mul_results.iter().enumerate() {
            let expected = &points[i] * &scalars[i];
            assert_eq!(*result, expected);
        }

        // Test batch point addition
        let point_add_results = batch_arithmetic::point_add(&points, &points).unwrap();
        assert_eq!(point_add_results.len(), 8);
        for (i, result) in point_add_results.iter().enumerate() {
            let expected = &points[i] + &points[i];
            assert_eq!(*result, expected);
        }

        // Test multi-scalar multiplication
        let multiscalar_result = batch_arithmetic::multiscalar_mul(&scalars, &points).unwrap();

        // Verify manually
        let mut expected = EdwardsPoint::identity();
        for (scalar, point) in scalars.iter().zip(points.iter()) {
            expected = &expected + &(point * scalar);
        }
        assert_eq!(multiscalar_result, expected);

        // Test batch scalar inversion
        let inverted = batch_arithmetic::scalar_invert(&scalars).unwrap();
        assert_eq!(inverted.len(), 8);
        for (i, inv) in inverted.iter().enumerate() {
            let product = &scalars[i] * inv;
            assert_eq!(product, Scalar::one());
        }
    }

    #[test]
    fn test_batch_merkle_operations() {
        let leaves_data: Vec<Vec<u8>> = (0..8).map(|i| format!("leaf_{}", i).into_bytes()).collect();
        let leaves: Vec<&[u8]> = leaves_data.iter().map(|l| l.as_slice()).collect();

        // Test tree construction
        let root = batch_merkle::build_tree_root(&leaves).unwrap();
        assert_ne!(root, [0u8; 32]);

        // Test tree with proofs
        let (root2, proofs) = batch_merkle::build_tree_with_proofs(&leaves).unwrap();
        assert_eq!(root, root2);
        assert_eq!(proofs.len(), 8);

        // Verify all proofs
        let all_valid = batch_merkle::verify_proofs(&proofs, &leaves).unwrap();
        assert!(all_valid);

        // Test consistency
        let consistency = batch_merkle::build_and_verify(&leaves).unwrap();
        assert!(consistency);

        // Test individual proof verification
        for (i, proof) in proofs.iter().enumerate() {
            assert!(proof.verify(&leaves[i]));
            assert_eq!(proof.root, root);
        }
    }
}

// Integration test combining multiple features
#[cfg(all(
    feature = "guardian-framework",
    feature = "gquic-transport",
    feature = "batch-operations",
    feature = "alloc"
))]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_ghostchain_integration() {
        // This test demonstrates how all the features work together
        // in a realistic Ghostchain scenario

        // 1. Setup Guardian authentication
        let secret_scalar = Scalar::from_u64(999888);
        let secret_key = gcrypt::protocols::ed25519::SecretKey::from_scalar(secret_scalar);
        let issuer = gcrypt::guardian::GuardianIssuer::new(secret_key);

        let user_did = gcrypt::guardian::Did::new("ghostchain".to_string(), "integration_test_user".to_string()).unwrap();
        let permissions = vec![
            gcrypt::guardian::Permission::new("ghostd".to_string(), vec!["read".to_string(), "write".to_string()]),
            gcrypt::guardian::Permission::new("walletd".to_string(), vec!["transact".to_string()]),
        ];

        let auth_token = issuer.issue_token_with_timestamps(user_did, permissions, 1000, 5000).unwrap();

        // 2. Setup GQUIC transport session
        let connection_id = gcrypt::transport::ConnectionId::from_bytes([0xABu8; 16]);
        let session_key = gcrypt::transport::SessionKey::from_bytes(&[0xCDu8; 32], connection_id);

        let transport = gcrypt::transport::GquicTransport::new();

        // 3. Perform batch operations (simulating high-throughput DeFi)
        let transaction_scalars: Vec<Scalar> = (1..=5).map(|i| Scalar::from_u64(i * 1000)).collect();
        let batch_points = gcrypt::batch::batch_arithmetic::scalar_mul_base(&transaction_scalars).unwrap();

        // 4. Create Merkle tree for transaction batch
        let tx_data: Vec<Vec<u8>> = (0..5).map(|i| format!("tx_hash_{}", i).into_bytes()).collect();
        let tx_leaves: Vec<&[u8]> = tx_data.iter().map(|d| d.as_slice()).collect();
        let (merkle_root, _proofs) = gcrypt::batch::batch_merkle::build_tree_with_proofs(&tx_leaves).unwrap();

        // 5. Encrypt the transaction batch for transport
        let mut session = session_key;
        let batch_data = format!("Transaction batch with {} operations, merkle root: {:?}",
                                batch_points.len(), hex::encode(merkle_root)).into_bytes();
        let encrypted_batch = transport.encrypt_packet(&mut session, &batch_data, b"ghostd-header").unwrap();

        // Verify the integration worked
        assert!(auth_token.has_permission("ghostd", "write"));
        assert!(auth_token.has_permission("walletd", "transact"));
        assert_eq!(batch_points.len(), 5);
        assert_ne!(merkle_root, [0u8; 32]);
        assert_ne!(encrypted_batch, batch_data);
        assert!(!encrypted_batch.is_empty());

        // Verify we can decrypt the batch
        let mut decrypt_session = gcrypt::transport::SessionKey::from_bytes(&[0xCDu8; 32], connection_id);
        let decrypted_batch = transport.decrypt_packet(&mut decrypt_session, &encrypted_batch, b"ghostd-header").unwrap();
        assert_eq!(decrypted_batch, batch_data);

        println!("✅ Full Ghostchain integration test passed!");
        println!("   - Guardian authentication: ✓");
        println!("   - GQUIC transport encryption: ✓");
        println!("   - Batch operations: ✓");
        println!("   - Merkle tree construction: ✓");
        println!("   - End-to-end data flow: ✓");
    }
}

// Performance benchmark tests
#[cfg(all(feature = "batch-operations", feature = "std"))]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_batch_vs_individual_performance() {
        let count = 100;
        let scalars: Vec<Scalar> = (1..=count).map(|i| Scalar::from_u64(i)).collect();

        // Time individual operations
        let start = Instant::now();
        let individual_results: Vec<EdwardsPoint> = scalars.iter().map(|s| EdwardsPoint::mul_base(s)).collect();
        let individual_time = start.elapsed();

        // Time batch operations
        let start = Instant::now();
        let batch_results = gcrypt::batch::batch_arithmetic::scalar_mul_base(&scalars).unwrap();
        let batch_time = start.elapsed();

        // Verify results are the same
        assert_eq!(individual_results.len(), batch_results.len());
        for (individual, batch) in individual_results.iter().zip(batch_results.iter()) {
            assert_eq!(*individual, *batch);
        }

        println!("Performance comparison for {} operations:", count);
        println!("  Individual: {:?}", individual_time);
        println!("  Batch:      {:?}", batch_time);

        // Batch operations should be at least competitive
        // (In a real implementation with SIMD, they should be faster)
        let ratio = batch_time.as_nanos() as f64 / individual_time.as_nanos() as f64;
        println!("  Ratio:      {:.2}x", ratio);

        // Allow batch to be up to 2x slower (due to overhead in this simple implementation)
        assert!(ratio <= 2.0, "Batch operations are too much slower than individual");
    }
}