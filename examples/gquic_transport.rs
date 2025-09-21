//! GQUIC Transport Example
//!
//! Demonstrates high-performance packet encryption and session management
//! for the GQUIC transport protocol used in Etherlink.

use gcrypt::{Scalar, MontgomeryPoint};

#[cfg(all(feature = "gquic-transport", feature = "alloc"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 GQUIC Transport Demo");
    println!("======================\n");

    // 1. Key Exchange - X25519 based
    println!("1. Performing X25519 key exchange...");

    let (alice_secret, alice_public) = generate_keypair();
    let (bob_secret, bob_public) = generate_keypair();

    println!("   Alice public key: {:?}", hex::encode(alice_public.to_bytes())[..16]);
    println!("   Bob public key:   {:?}", hex::encode(bob_public.to_bytes())[..16]);

    // 2. Session Key Derivation
    println!("\n2. Deriving GQUIC session keys...");

    let connection_id = gcrypt::transport::ConnectionId::from_bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    let context = b"gquic-demo-session";

    let alice_session = gcrypt::transport::GquicKeyExchange::derive_session_key(
        &alice_secret,
        &bob_public,
        connection_id,
        context
    )?;

    let bob_session = gcrypt::transport::GquicKeyExchange::derive_session_key(
        &bob_secret,
        &alice_public,
        connection_id,
        context
    )?;

    println!("   ✓ Alice and Bob derived session keys");
    println!("   ✓ Connection ID: {:?}", hex::encode(connection_id.as_bytes()));

    // 3. Packet Encryption/Decryption
    println!("\n3. Encrypting and decrypting GQUIC packets...");

    let transport = gcrypt::transport::GquicTransport::new();

    // Alice sends a packet to Bob
    let mut alice_encrypt_session = alice_session.clone();
    let alice_message = b"Hello Bob! This is a GQUIC packet from Alice.";
    let packet_header = b"GQUIC-HEADER-v1";

    let encrypted_packet = transport.encrypt_packet(
        &mut alice_encrypt_session,
        alice_message,
        packet_header
    )?;

    println!("   📤 Alice encrypted: \"{}\"", String::from_utf8_lossy(alice_message));
    println!("      Ciphertext length: {} bytes", encrypted_packet.len());

    // Bob receives and decrypts the packet
    let mut bob_decrypt_session = bob_session.clone();
    let decrypted_packet = transport.decrypt_packet(
        &mut bob_decrypt_session,
        &encrypted_packet,
        packet_header
    )?;

    println!("   📥 Bob decrypted: \"{}\"", String::from_utf8_lossy(&decrypted_packet));

    // Bob sends a reply
    let mut bob_encrypt_session = bob_session;
    let bob_message = b"Hi Alice! Got your message. GQUIC is working great!";

    let reply_packet = transport.encrypt_packet(
        &mut bob_encrypt_session,
        bob_message,
        packet_header
    )?;

    println!("   📤 Bob encrypted reply: \"{}\"", String::from_utf8_lossy(bob_message));

    // Alice receives Bob's reply
    let mut alice_decrypt_session = alice_session;
    let decrypted_reply = transport.decrypt_packet(
        &mut alice_decrypt_session,
        &reply_packet,
        packet_header
    )?;

    println!("   📥 Alice decrypted reply: \"{}\"", String::from_utf8_lossy(&decrypted_reply));

    // 4. Batch Packet Processing
    println!("\n4. Demonstrating batch packet processing...");

    let packet_count = 10;
    let mut sessions = Vec::new();
    let mut packets = Vec::new();
    let mut headers = Vec::new();

    // Prepare multiple sessions and packets
    for i in 0..packet_count {
        let conn_id = gcrypt::transport::ConnectionId::from_bytes([i as u8; 16]);
        let session = gcrypt::transport::SessionKey::from_bytes(&[(i + 1) as u8; 32], conn_id);
        let packet = format!("Batch packet #{} with some data", i).into_bytes();
        let header = format!("header-{}", i).into_bytes();

        sessions.push(session);
        packets.push(packet);
        headers.push(header);
    }

    let packet_refs: Vec<&[u8]> = packets.iter().map(|p| p.as_slice()).collect();
    let header_refs: Vec<&[u8]> = headers.iter().map(|h| h.as_slice()).collect();

    let batch_start = std::time::Instant::now();
    let encrypted_batch = transport.batch_encrypt_packets(
        &mut sessions,
        &packet_refs,
        &header_refs
    )?;
    let batch_time = batch_start.elapsed();

    println!("   ✓ Batch encrypted {} packets in {:.2}ms", packet_count, batch_time.as_millis());
    println!("   ✓ Average: {:.2}ms per packet", batch_time.as_millis() as f64 / packet_count as f64);

    // Verify batch decryption
    let mut decrypt_sessions = Vec::new();
    for i in 0..packet_count {
        let conn_id = gcrypt::transport::ConnectionId::from_bytes([i as u8; 16]);
        let session = gcrypt::transport::SessionKey::from_bytes(&[(i + 1) as u8; 32], conn_id);
        decrypt_sessions.push(session);
    }

    let encrypted_refs: Vec<&[u8]> = encrypted_batch.iter().map(|e| e.as_slice()).collect();
    let decrypted_batch = transport.batch_decrypt_packets(
        &mut decrypt_sessions,
        &encrypted_refs,
        &header_refs
    )?;

    println!("   ✓ Batch decrypted {} packets", decrypted_batch.len());

    // Verify all packets decrypted correctly
    for (i, (original, decrypted)) in packets.iter().zip(decrypted_batch.iter()).enumerate() {
        if *original == *decrypted {
            println!("   ✓ Packet #{} verified", i);
        } else {
            println!("   ❌ Packet #{} mismatch!", i);
        }
    }

    // 5. Connection Manager Demo
    #[cfg(feature = "std")]
    {
        println!("\n5. Using GQUIC Connection Manager...");

        let mut manager = gcrypt::transport::GquicConnectionManager::new();

        // Add multiple connections
        for i in 0..3 {
            let conn_id = gcrypt::transport::ConnectionId::from_bytes([(i + 10) as u8; 16]);
            let session = gcrypt::transport::SessionKey::from_bytes(&[(i + 50) as u8; 32], conn_id);
            manager.add_session(session);
            println!("   ✓ Added connection #{}", i + 1);
        }

        println!("   ✓ Managing {} active connections", manager.connection_count());

        // Send data through specific connection
        let conn_id = gcrypt::transport::ConnectionId::from_bytes([10u8; 16]);
        let data = b"Data sent through connection manager";
        let header = b"manager-header";

        let encrypted = manager.encrypt_for_connection(&conn_id, data, header)?;
        let decrypted = manager.decrypt_for_connection(&conn_id, &encrypted, header)?;

        println!("   ✓ Connection manager test: \"{}\"", String::from_utf8_lossy(&decrypted));
    }

    println!("\n🎉 GQUIC Transport demo completed successfully!");
    println!("   Ready for high-performance Ghostchain networking!");

    Ok(())
}

#[cfg(all(feature = "gquic-transport", feature = "alloc"))]
fn generate_keypair() -> (Scalar, MontgomeryPoint) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Generate deterministic "random" scalar for demo
    let mut hasher = DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    let random_value = hasher.finish();

    let secret = Scalar::from_u64(random_value);
    let public = MontgomeryPoint::mul_base(&secret);

    (secret, public)
}

#[cfg(not(all(feature = "gquic-transport", feature = "alloc")))]
fn main() {
    println!("This example requires the following features:");
    println!("  --features gquic-transport,alloc");
    println!("\nRun with:");
    println!("  cargo run --example gquic_transport --features gquic-transport,alloc");
}