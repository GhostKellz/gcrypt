//! Guardian Framework Authentication Example
//!
//! Demonstrates zero-trust authentication for Ghostchain ecosystem services
//! including token issuance, verification, and serialization.

use gcrypt::Scalar;

#[cfg(all(feature = "guardian-framework", feature = "alloc"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️  Guardian Framework Demo");
    println!("===========================\n");

    // 1. Setup Guardian Issuer (Authority)
    println!("1. Setting up Guardian Authority...");

    let authority_secret = Scalar::from_u64(0x123456789ABCDEF0u64);
    let secret_key = gcrypt::protocols::ed25519::SecretKey::from_scalar(authority_secret);
    let issuer = gcrypt::guardian::GuardianIssuer::new(secret_key);

    println!("   ✓ Authority DID: {}", issuer.did());
    println!("   ✓ Authority public key: {:?}", hex::encode(issuer.public_key().to_bytes())[..16]);

    // 2. Create User Identities
    println!("\n2. Creating user identities...");

    let users = vec![
        ("alice", vec![
            ("ghostd", vec!["read", "write", "submit_transaction"]),
            ("walletd", vec!["read", "send_transaction"]),
            ("cns", vec!["resolve_name", "register_name"]),
        ]),
        ("bob", vec![
            ("ghostd", vec!["read"]),
            ("walletd", vec!["read"]),
            ("cns", vec!["resolve_name"]),
        ]),
        ("charlie", vec![
            ("ghostd", vec!["read", "write", "submit_transaction", "broadcast_block"]),
            ("walletd", vec!["read", "send_transaction", "create_wallet"]),
            ("cns", vec!["resolve_name", "register_name", "update_record"]),
            ("gid", vec!["create_identity", "issue_credential"]),
        ]),
    ];

    let mut user_tokens = Vec::new();

    for (username, service_perms) in users {
        let user_did = gcrypt::guardian::Did::new(
            "ghostchain".to_string(),
            format!("user_{}", username)
        )?;

        let mut permissions = Vec::new();
        for (service, operations) in service_perms {
            let ops: Vec<String> = operations.iter().map(|s| s.to_string()).collect();
            permissions.push(gcrypt::guardian::Permission::new(service.to_string(), ops));
        }

        let token = issuer.issue_token(user_did.clone(), permissions, 7200)?; // 2 hours

        println!("   ✓ Created token for {}: {} permissions, expires in {}s",
                 username, token.permissions.len(), token.remaining_lifetime());

        user_tokens.push((username, token));
    }

    // 3. Token Verification
    println!("\n3. Verifying tokens...");

    let mut verifier = gcrypt::guardian::GuardianVerifier::new();
    verifier.add_trusted_issuer(issuer.did().clone(), *issuer.public_key());

    for (username, token) in &user_tokens {
        match verifier.verify_token(token) {
            Ok(_) => println!("   ✓ {}'s token is VALID", username),
            Err(e) => println!("   ❌ {}'s token is INVALID: {}", username, e),
        }

        // Test specific permissions
        let test_cases = vec![
            ("ghostd", "read"),
            ("ghostd", "submit_transaction"),
            ("walletd", "send_transaction"),
            ("cns", "register_name"),
            ("gid", "create_identity"),
        ];

        for (service, operation) in test_cases {
            match verifier.verify_permission(token, service, operation) {
                Ok(_) => println!("     ✓ {} can {} on {}", username, operation, service),
                Err(_) => println!("     ❌ {} cannot {} on {}", username, operation, service),
            }
        }
        println!();
    }

    // 4. Token Serialization for HTTP/gRPC
    println!("4. Token serialization for HTTP/gRPC transport...");

    let (alice_name, alice_token) = &user_tokens[0];

    // Binary serialization
    let binary_data = gcrypt::guardian::tokens::TokenCodec::serialize_binary(alice_token)?;
    println!("   ✓ Binary serialization: {} bytes", binary_data.len());

    let deserialized = gcrypt::guardian::tokens::TokenCodec::deserialize_binary(&binary_data)?;
    println!("   ✓ Binary deserialization successful");

    // Base64 encoding for text transport
    let base64_token = gcrypt::guardian::tokens::TokenCodec::encode_base64(alice_token)?;
    println!("   ✓ Base64 encoding: {}...", &base64_token[..50]);

    let decoded_token = gcrypt::guardian::tokens::TokenCodec::decode_base64(&base64_token)?;
    println!("   ✓ Base64 decoding successful");

    // HTTP Authorization headers
    let bearer_header = gcrypt::guardian::tokens::AuthorizationHeader::bearer(alice_token)?;
    let guardian_header = gcrypt::guardian::tokens::AuthorizationHeader::guardian(alice_token)?;

    println!("   ✓ Bearer header: {}...", &bearer_header[..40]);
    println!("   ✓ Guardian header: {}...", &guardian_header[..40]);

    // Parse headers back
    let parsed_bearer = gcrypt::guardian::tokens::AuthorizationHeader::parse_bearer(&bearer_header)?;
    let parsed_guardian = gcrypt::guardian::tokens::AuthorizationHeader::parse_guardian(&guardian_header)?;

    println!("   ✓ Header parsing successful");

    // 5. Permission Constraints Demo
    println!("\n5. Advanced permission constraints...");

    // Create a time-constrained permission
    let time_constraints = gcrypt::guardian::permissions::TimeConstraints::new()
        .with_validity_period(1000, 5000); // Valid from timestamp 1000 to 5000

    let resource_constraints = gcrypt::guardian::permissions::ResourceConstraints::new()
        .allow_path("/api/v1/wallets/".to_string())
        .deny_path("/api/v1/wallets/admin/".to_string())
        .with_max_size(1024 * 1024); // 1MB max

    let rate_constraints = gcrypt::guardian::permissions::RateConstraints::new(100, 60) // 100 requests per minute
        .with_burst_size(10);

    let constraints = gcrypt::guardian::permissions::PermissionConstraints::new()
        .with_time_constraints(time_constraints)
        .with_resource_constraints(resource_constraints)
        .with_rate_constraints(rate_constraints);

    let constrained_permission = gcrypt::guardian::permissions::Permission::with_constraints(
        "walletd".to_string(),
        vec!["read".to_string(), "list_transactions".to_string()],
        constraints
    );

    println!("   ✓ Created permission with time, resource, and rate constraints");

    // Test constraint evaluation
    let context = gcrypt::guardian::permissions::PermissionContext::new(
        2500, // timestamp within valid range
        "/api/v1/wallets/user123".to_string() // allowed path
    ).with_rate_info(50, 60); // 50 requests in 60 seconds

    let is_allowed = constrained_permission.check_constraints(&context);
    println!("   ✓ Constraint check result: {}", if is_allowed { "ALLOWED" } else { "DENIED" });

    // 6. Predefined Ghostchain Service Permissions
    println!("\n6. Predefined Ghostchain service permissions...");

    let service_perms = vec![
        ("GHOSTD Read", gcrypt::guardian::permissions::GhostchainPermissions::ghostd_read()),
        ("GHOSTD Write", gcrypt::guardian::permissions::GhostchainPermissions::ghostd_write()),
        ("GHOSTD Admin", gcrypt::guardian::permissions::GhostchainPermissions::ghostd_admin()),
        ("WALLETD Read", gcrypt::guardian::permissions::GhostchainPermissions::walletd_read()),
        ("WALLETD Transact", gcrypt::guardian::permissions::GhostchainPermissions::walletd_transact()),
        ("CNS Read", gcrypt::guardian::permissions::GhostchainPermissions::cns_read()),
        ("CNS Write", gcrypt::guardian::permissions::GhostchainPermissions::cns_write()),
        ("GID Read", gcrypt::guardian::permissions::GhostchainPermissions::gid_read()),
        ("GID Write", gcrypt::guardian::permissions::GhostchainPermissions::gid_write()),
    ];

    for (name, permission) in service_perms {
        println!("   ✓ {}: {} operations on {}",
                 name, permission.operations().len(), permission.service);
    }

    // 7. Token Validation and Fingerprinting
    println!("\n7. Token validation and fingerprinting...");

    for (username, token) in &user_tokens {
        match gcrypt::guardian::tokens::TokenValidator::validate_format(token) {
            Ok(_) => println!("   ✓ {}'s token format is valid", username),
            Err(e) => println!("   ❌ {}'s token format is invalid: {}", username, e),
        }

        let fingerprint = gcrypt::guardian::tokens::TokenValidator::fingerprint(token);
        println!("     Fingerprint: {:?}", hex::encode(fingerprint)[..16]);

        let expires_soon = gcrypt::guardian::tokens::TokenValidator::expires_within(token, 3600);
        println!("     Expires within 1 hour: {}", expires_soon);
    }

    // 8. Realistic gRPC Service Authorization Demo
    println!("\n8. Realistic gRPC service authorization simulation...");

    fn simulate_grpc_request(
        verifier: &gcrypt::guardian::GuardianVerifier,
        auth_header: &str,
        service: &str,
        method: &str
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Parse authorization header
        let token = if auth_header.starts_with("Bearer ") {
            gcrypt::guardian::tokens::AuthorizationHeader::parse_bearer(auth_header)?
        } else if auth_header.starts_with("Guardian ") {
            gcrypt::guardian::tokens::AuthorizationHeader::parse_guardian(auth_header)?
        } else {
            return Err("Invalid authorization header".into());
        };

        // Verify token and permission
        verifier.verify_permission(&token, service, method)?;

        Ok(format!("✓ Authorized: {} can {} on {}", token.did, method, service))
    }

    let test_requests = vec![
        (&bearer_header, "ghostd", "get_block"),
        (&guardian_header, "walletd", "send_transaction"),
        (&bearer_header, "cns", "resolve_name"),
        (&guardian_header, "ghostd", "configure_node"), // Should fail
    ];

    for (header, service, method) in test_requests {
        match simulate_grpc_request(&verifier, header, service, method) {
            Ok(msg) => println!("   {}", msg),
            Err(e) => println!("   ❌ Unauthorized: {}", e),
        }
    }

    println!("\n🎉 Guardian Framework demo completed!");
    println!("   Zero-trust authentication ready for Ghostchain services!");

    Ok(())
}

#[cfg(not(all(feature = "guardian-framework", feature = "alloc")))]
fn main() {
    println!("This example requires the following features:");
    println!("  --features guardian-framework,alloc");
    println!("\nRun with:");
    println!("  cargo run --example guardian_auth --features guardian-framework,alloc");
}