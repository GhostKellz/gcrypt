//! Ghostchain Ecosystem Integration Example
//!
//! This example demonstrates how to use all the new Ghostchain ecosystem
//! features together in a realistic scenario.

use gcrypt::{Scalar, EdwardsPoint, FieldElement};

#[cfg(all(
    feature = "guardian-framework",
    feature = "gquic-transport",
    feature = "zk-hash",
    feature = "batch-operations",
    feature = "alloc"
))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Ghostchain Ecosystem Integration Demo");
    println!("=========================================\n");

    // 1. Guardian Framework - Zero-trust authentication
    println!("1. Setting up Guardian Framework authentication...");

    let secret_scalar = Scalar::from_u64(12345);
    let secret_key = gcrypt::protocols::ed25519::SecretKey::from_scalar(secret_scalar);
    let issuer = gcrypt::guardian::GuardianIssuer::new(secret_key);

    let user_did = gcrypt::guardian::Did::new(
        "ghostchain".to_string(),
        "demo_user_001".to_string()
    )?;

    let permissions = vec![
        gcrypt::guardian::Permission::new(
            "ghostd".to_string(),
            vec!["read".to_string(), "write".to_string(), "submit_transaction".to_string()]
        ),
        gcrypt::guardian::Permission::new(
            "walletd".to_string(),
            vec!["read".to_string(), "send_transaction".to_string()]
        ),
        gcrypt::guardian::Permission::new(
            "cns".to_string(),
            vec!["resolve_name".to_string()]
        ),
    ];

    let auth_token = issuer.issue_token(user_did.clone(), permissions, 3600)?;
    println!("   ✓ Guardian token issued for DID: {}", user_did);
    println!("   ✓ Token has {} permissions", auth_token.permissions.len());
    println!("   ✓ Token expires in {} seconds", auth_token.remaining_lifetime());

    // Create authorization header for HTTP/gRPC requests
    let bearer_header = gcrypt::guardian::AuthorizationHeader::bearer(&auth_token)?;
    println!("   ✓ Authorization header: {}...", &bearer_header[..30]);

    // 2. GQUIC Transport - High-performance networking
    println!("\n2. Setting up GQUIC transport for high-performance networking...");

    let connection_id = gcrypt::transport::ConnectionId::from_bytes([0x42u8; 16]);

    // Simulate X25519 key exchange
    let local_secret = Scalar::from_u64(67890);
    let remote_secret = Scalar::from_u64(98765);
    let remote_public = gcrypt::MontgomeryPoint::mul_base(&remote_secret);

    let session_key = gcrypt::transport::GquicKeyExchange::derive_session_key(
        &local_secret,
        &remote_public,
        connection_id,
        b"ghostchain-demo"
    )?;

    println!("   ✓ GQUIC session established");
    println!("   ✓ Connection ID: {:?}", hex::encode(session_key.connection_id().as_bytes()));

    let transport = gcrypt::transport::GquicTransport::new();

    // Encrypt some data
    let mut encrypt_session = session_key.clone();
    let demo_data = b"Ghostchain transaction data: transfer 100 GSPR to ghost1abc...";
    let encrypted = transport.encrypt_packet(&mut encrypt_session, demo_data, b"ghostd-v1")?;

    println!("   ✓ Encrypted {} bytes -> {} bytes", demo_data.len(), encrypted.len());

    // 3. ZK-Friendly Hash Functions - Privacy features
    println!("\n3. Using ZK-friendly hash functions for privacy...");

    let value1 = FieldElement::from_u64(1000); // Transaction amount
    let value2 = FieldElement::from_u64(2000); // Account balance
    let nonce = FieldElement::from_u64(42);    // Transaction nonce

    // Poseidon hash (most efficient in circuits)
    let poseidon_commitment = gcrypt::zk_hash::poseidon::hash_many(&[value1, value2, nonce])?;
    println!("   ✓ Poseidon commitment: {:?}", hex::encode(poseidon_commitment.to_bytes())[..16]);

    // Rescue hash (alternative)
    let rescue_commitment = gcrypt::zk_hash::rescue::hash_two(&value1, &nonce)?;
    println!("   ✓ Rescue commitment: {:?}", hex::encode(rescue_commitment.to_bytes())[..16]);

    // MiMC hash (minimal multiplicative complexity)
    let mimc_commitment = gcrypt::zk_hash::mimc::hash_two(&value2, &nonce)?;
    println!("   ✓ MiMC commitment: {:?}", hex::encode(mimc_commitment.to_bytes())[..16]);

    // Pedersen hash (homomorphic properties)
    let pedersen_commitment = gcrypt::zk_hash::pedersen::hash_two(&value1, &value2)?;
    println!("   ✓ Pedersen commitment: {:?}", hex::encode(pedersen_commitment.to_bytes())[..16]);

    // 4. Batch Operations - High-throughput DeFi
    println!("\n4. Performing batch operations for high-throughput DeFi...");

    // Simulate a batch of transactions
    let tx_count = 20;
    let transaction_scalars: Vec<Scalar> = (1..=tx_count)
        .map(|i| Scalar::from_u64(i * 1000 + 12345))
        .collect();

    println!("   Processing {} transactions in batch...", tx_count);

    // Batch signature verification simulation
    let mut public_keys = Vec::new();
    let mut messages = Vec::new();
    let mut signatures = Vec::new();

    for (i, &scalar) in transaction_scalars.iter().enumerate() {
        let secret_key = gcrypt::protocols::ed25519::SecretKey::from_scalar(scalar);
        let public_key = gcrypt::protocols::ed25519::PublicKey::from(&secret_key);
        let message = format!("Transaction #{}: transfer {} GSPR", i, i * 100).into_bytes();
        let signature = gcrypt::protocols::ed25519::sign(&secret_key, &message);

        public_keys.push(public_key);
        messages.push(message);
        signatures.push(signature);
    }

    let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

    // Batch verify all signatures
    let verification_start = std::time::Instant::now();
    let all_valid = gcrypt::batch::batch_signatures::verify_ed25519_batch(
        &public_keys,
        &message_refs,
        &signatures
    )?;
    let verification_time = verification_start.elapsed();

    println!("   ✓ Batch signature verification: {} ({:.2}ms)",
             if all_valid { "VALID" } else { "INVALID" },
             verification_time.as_millis());

    // Batch arithmetic operations
    let arithmetic_start = std::time::Instant::now();
    let batch_points = gcrypt::batch::batch_arithmetic::scalar_mul_base(&transaction_scalars)?;
    let arithmetic_time = arithmetic_start.elapsed();

    println!("   ✓ Batch scalar multiplication: {} points ({:.2}ms)",
             batch_points.len(), arithmetic_time.as_millis());

    // Build Merkle tree for the transaction batch
    let tx_hashes: Vec<Vec<u8>> = (0..tx_count)
        .map(|i| format!("tx_hash_{:08x}", i * 0x1000 + 0xABCD).into_bytes())
        .collect();
    let tx_leaves: Vec<&[u8]> = tx_hashes.iter().map(|h| h.as_slice()).collect();

    let merkle_start = std::time::Instant::now();
    let (merkle_root, merkle_proofs) = gcrypt::batch::batch_merkle::build_tree_with_proofs(&tx_leaves)?;
    let merkle_time = merkle_start.elapsed();

    println!("   ✓ Merkle tree construction: {} proofs ({:.2}ms)",
             merkle_proofs.len(), merkle_time.as_millis());
    println!("   ✓ Merkle root: {:?}", hex::encode(merkle_root)[..16]);

    // 5. Full Integration - Putting it all together
    println!("\n5. Full integration demonstration...");

    // Create a block with authenticated user, encrypted transport, ZK commitments, and batch processing
    let block_data = serde_json::json!({
        "block_number": 12345,
        "previous_hash": hex::encode([0x1A; 32]),
        "merkle_root": hex::encode(merkle_root),
        "transaction_count": tx_count,
        "zk_commitments": {
            "poseidon": hex::encode(poseidon_commitment.to_bytes()),
            "rescue": hex::encode(rescue_commitment.to_bytes()),
            "mimc": hex::encode(mimc_commitment.to_bytes()),
            "pedersen": hex::encode(pedersen_commitment.to_bytes())
        },
        "authenticated_by": user_did.to_string(),
        "timestamp": 1640995200u64
    });

    let block_json = serde_json::to_string_pretty(&block_data)?;
    println!("   ✓ Block data prepared:");
    println!("{}", block_json);

    // Encrypt the block for network transmission
    let mut final_session = session_key;
    let encrypted_block = transport.encrypt_packet(
        &mut final_session,
        block_json.as_bytes(),
        b"ghostchain-block-v1"
    )?;

    println!("\n   ✓ Block encrypted for transmission ({} bytes)", encrypted_block.len());

    // Performance summary
    let total_time = verification_time + arithmetic_time + merkle_time;
    println!("\n6. Performance Summary:");
    println!("   • Signature verification: {:.2}ms ({:.1} tx/ms)",
             verification_time.as_millis(),
             tx_count as f64 / verification_time.as_millis() as f64);
    println!("   • Arithmetic operations: {:.2}ms ({:.1} ops/ms)",
             arithmetic_time.as_millis(),
             tx_count as f64 / arithmetic_time.as_millis() as f64);
    println!("   • Merkle tree building: {:.2}ms", merkle_time.as_millis());
    println!("   • Total processing time: {:.2}ms", total_time.as_millis());
    println!("   • Overall throughput: {:.1} tx/ms",
             tx_count as f64 / total_time.as_millis() as f64);

    println!("\n🎉 Ghostchain ecosystem integration completed successfully!");
    println!("   All features working together seamlessly for high-performance blockchain operations.");

    Ok(())
}

#[cfg(not(all(
    feature = "guardian-framework",
    feature = "gquic-transport",
    feature = "zk-hash",
    feature = "batch-operations",
    feature = "alloc"
)))]
fn main() {
    println!("This example requires the following features to be enabled:");
    println!("  --features guardian-framework,gquic-transport,zk-hash,batch-operations,alloc");
    println!("\nRun with:");
    println!("  cargo run --example ghostchain_integration --features guardian-framework,gquic-transport,zk-hash,batch-operations,alloc");
}