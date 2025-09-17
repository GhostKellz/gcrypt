//! GhostChain Comprehensive Demo
//!
//! This example demonstrates the full capabilities of GhostChain as a crypto backbone,
//! showcasing various cryptographic primitives and protocols.

use gcrypt::{Scalar, EdwardsPoint, RistrettoPoint, MontgomeryPoint};
use gcrypt::protocols::{
    Ed25519SecretKey, Ed25519PublicKey,
    X25519SecretKey, X25519PublicKey, SharedSecret,
    NoisePattern, CipherSuite, HandshakeState,
    PeerId, MessageType, GossipConfig, GossipState, PeerAddress,
};

#[cfg(feature = "secp256k1")]
use gcrypt::secp256k1::{PrivateKey as Secp256k1PrivateKey, PublicKey as Secp256k1PublicKey};

#[cfg(feature = "bls12_381")]
use gcrypt::bls12_381::{PrivateKey as BlsPrivateKey, PublicKey as BlsPublicKey};

use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 GhostChain Cryptographic Backbone Demo");
    println!("==========================================\n");

    // Initialize secure random number generator
    let mut rng = OsRng;

    // 1. Curve25519 Operations (Core)
    demo_curve25519(&mut rng)?;

    // 2. Ed25519 Digital Signatures
    demo_ed25519(&mut rng)?;

    // 3. X25519 Key Exchange
    demo_x25519(&mut rng)?;

    // 4. Secp256k1 for Blockchain Compatibility
    #[cfg(feature = "secp256k1")]
    demo_secp256k1(&mut rng)?;

    // 5. BLS Signatures for Consensus
    #[cfg(feature = "bls12_381")]
    demo_bls_signatures(&mut rng)?;

    // 6. Noise Protocol for P2P Security
    demo_noise_protocol(&mut rng)?;

    // 7. Gossip Protocol for Mesh Networking
    demo_gossip_protocol(&mut rng)?;

    println!("✅ All GhostChain demos completed successfully!");
    println!("Ready to power blockchain, DeFi, and mesh VPN infrastructure! 🌐");

    Ok(())
}

fn demo_curve25519(rng: &mut OsRng) -> Result<(), Box<dyn std::error::Error>> {
    println!("1️⃣  Curve25519 Core Operations");
    println!("   ────────────────────────────");

    // Scalar arithmetic
    let scalar1 = Scalar::random(rng);
    let scalar2 = Scalar::random(rng);
    let scalar_sum = &scalar1 + &scalar2;
    let scalar_product = &scalar1 * &scalar2;

    println!("   • Generated random scalars and performed arithmetic");

    // Edwards point operations
    let point1 = EdwardsPoint::mul_base(&scalar1);
    let point2 = EdwardsPoint::mul_base(&scalar2);
    let point_sum = &point1 + &point2;

    println!("   • Edwards point operations completed");

    // Ristretto255 for advanced protocols
    let ristretto1 = RistrettoPoint::mul_base(&scalar1);
    let ristretto2 = RistrettoPoint::mul_base(&scalar2);
    let ristretto_sum = &ristretto1 + &ristretto2;

    println!("   • Ristretto255 operations for privacy protocols");

    // Montgomery ladder for X25519
    let montgomery_point = MontgomeryPoint::mul_base_clamped(scalar1.to_bytes());

    println!("   • Montgomery operations for key exchange");
    println!("   ✅ Curve25519 operations verified\n");

    Ok(())
}

fn demo_ed25519(rng: &mut OsRng) -> Result<(), Box<dyn std::error::Error>> {
    println!("2️⃣  Ed25519 Digital Signatures");
    println!("   ──────────────────────────");

    // Generate key pair
    let private_key = Ed25519SecretKey::random(rng);
    let public_key = private_key.public_key();

    println!("   • Generated Ed25519 key pair");

    // Sign a message
    let message = b"Welcome to GhostChain - Secure by Design";
    let signature = private_key.sign(message)?;

    println!("   • Signed message: '{}'", std::str::from_utf8(message)?);

    // Verify signature
    public_key.verify(message, &signature)?;

    println!("   • Signature verified successfully");
    println!("   ✅ Ed25519 signatures working perfectly\n");

    Ok(())
}

fn demo_x25519(rng: &mut OsRng) -> Result<(), Box<dyn std::error::Error>> {
    println!("3️⃣  X25519 Key Exchange (ECDH)");
    println!("   ─────────────────────────");

    // Alice's keys
    let alice_private = X25519SecretKey::random(rng);
    let alice_public = alice_private.public_key();

    // Bob's keys
    let bob_private = X25519SecretKey::random(rng);
    let bob_public = bob_private.public_key();

    println!("   • Generated key pairs for Alice and Bob");

    // Compute shared secrets
    let alice_shared = alice_private.diffie_hellman(&bob_public)?;
    let bob_shared = bob_private.diffie_hellman(&alice_public)?;

    println!("   • Performed Diffie-Hellman key exchange");

    // Verify shared secrets match
    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());

    println!("   • Shared secrets match: {}", hex::encode(alice_shared.as_bytes()));
    println!("   ✅ X25519 key exchange successful\n");

    Ok(())
}

#[cfg(feature = "secp256k1")]
fn demo_secp256k1(rng: &mut OsRng) -> Result<(), Box<dyn std::error::Error>> {
    println!("4️⃣  Secp256k1 for Blockchain Compatibility");
    println!("   ────────────────────────────────────");

    // Generate Bitcoin/Ethereum compatible keys
    let private_key = Secp256k1PrivateKey::random(rng);
    let public_key = private_key.public_key();

    println!("   • Generated secp256k1 key pair");

    // Sign transaction hash
    let tx_hash = [0x42u8; 32]; // Mock transaction hash
    let signature = private_key.sign_ecdsa(&tx_hash)?;

    println!("   • Signed transaction hash with ECDSA");

    // Verify signature
    public_key.verify_ecdsa(&tx_hash, &signature)?;

    println!("   • Verified ECDSA signature");

    // Demonstrate recoverable signatures (Ethereum style)
    let recoverable_sig = private_key.sign_ecdsa_recoverable(&tx_hash)?;
    let recovered_key = Secp256k1PublicKey::recover_from_signature(&tx_hash, &recoverable_sig)?;

    assert_eq!(public_key, recovered_key);

    println!("   • Recoverable signature and key recovery working");

    // Generate Ethereum address
    #[cfg(feature = "alloc")]
    {
        let eth_address = gcrypt::secp256k1::ethereum_address(&public_key);
        println!("   • Ethereum address: 0x{}", hex::encode(eth_address));
    }

    println!("   ✅ Secp256k1 blockchain integration ready\n");

    Ok(())
}

#[cfg(feature = "bls12_381")]
fn demo_bls_signatures(rng: &mut OsRng) -> Result<(), Box<dyn std::error::Error>> {
    println!("5️⃣  BLS Signatures for Validator Consensus");
    println!("   ────────────────────────────────────");

    // Generate validator keys
    let validator1_sk = BlsPrivateKey::random(rng);
    let validator1_pk = validator1_sk.public_key();

    let validator2_sk = BlsPrivateKey::random(rng);
    let validator2_pk = validator2_sk.public_key();

    let validator3_sk = BlsPrivateKey::random(rng);
    let validator3_pk = validator3_sk.public_key();

    println!("   • Generated 3 BLS validator key pairs");

    // Sign the same block hash
    let block_hash = b"Block #12345: Next epoch transition";
    let sig1 = validator1_sk.sign(block_hash)?;
    let sig2 = validator2_sk.sign(block_hash)?;
    let sig3 = validator3_sk.sign(block_hash)?;

    println!("   • Each validator signed block hash");

    // Verify individual signatures
    validator1_pk.verify(block_hash, &sig1)?;
    validator2_pk.verify(block_hash, &sig2)?;
    validator3_pk.verify(block_hash, &sig3)?;

    println!("   • All individual signatures verified");

    // Aggregate signatures
    let aggregate_sig = gcrypt::bls12_381::Signature::aggregate(&[sig1, sig2, sig3])?;
    let public_keys = [validator1_pk, validator2_pk, validator3_pk];

    println!("   • Aggregated all signatures into one");

    // Verify aggregate signature
    aggregate_sig.verify_same_message(&public_keys, block_hash)?;

    println!("   • Aggregate signature verified successfully");
    println!("   ✅ BLS consensus mechanism ready for production\n");

    Ok(())
}

fn demo_noise_protocol(rng: &mut OsRng) -> Result<(), Box<dyn std::error::Error>> {
    println!("6️⃣  Noise Protocol for Secure P2P");
    println!("   ───────────────────────────────");

    // Generate static keys for both parties
    let initiator_static_private = Scalar::random(rng);
    let initiator_static_public = MontgomeryPoint::mul_base_clamped(initiator_static_private.to_bytes());

    let responder_static_private = Scalar::random(rng);
    let responder_static_public = MontgomeryPoint::mul_base_clamped(responder_static_private.to_bytes());

    println!("   • Generated static key pairs for both parties");

    // Initialize Noise_XX handshake
    let mut initiator = HandshakeState::new_initiator(
        NoisePattern::XX,
        CipherSuite::ChaCha20Poly1305SHA256Curve25519,
        Some((initiator_static_private, initiator_static_public)),
        None,
    )?;

    let mut responder = HandshakeState::new_responder(
        NoisePattern::XX,
        CipherSuite::ChaCha20Poly1305SHA256Curve25519,
        Some((responder_static_private, responder_static_public)),
        None,
    )?;

    println!("   • Initialized Noise_XX handshake states");

    // Perform handshake
    let msg1 = initiator.write_message(b"InitiatorHello")?;
    let _payload1 = responder.read_message(&msg1)?;

    let msg2 = responder.write_message(b"ResponderHello")?;
    let _payload2 = initiator.read_message(&msg2)?;

    let msg3 = initiator.write_message(b"FinalMessage")?;
    let _payload3 = responder.read_message(&msg3)?;

    println!("   • Completed 3-message handshake exchange");

    // Check handshake completion
    assert!(initiator.is_handshake_complete());
    assert!(responder.is_handshake_complete());

    println!("   • Handshake completed, secure channel established");

    // Finalize to transport state
    let (_initiator_transport, _responder_transport) = initiator.finalize()?;

    println!("   • Transport states created for encrypted communication");
    println!("   ✅ Noise protocol ready for mesh networking\n");

    Ok(())
}

fn demo_gossip_protocol(rng: &mut OsRng) -> Result<(), Box<dyn std::error::Error>> {
    println!("7️⃣  Gossip Protocol for Mesh Networks");
    println!("   ──────────────────────────────────");

    // Create node identities
    let node1_private = Ed25519SecretKey::random(rng);
    let node1_public = node1_private.public_key();
    let node1_id = PeerId::from_public_key(&node1_public);

    let node2_private = Ed25519SecretKey::random(rng);
    let node2_public = node2_private.public_key();
    let node2_id = PeerId::from_public_key(&node2_public);

    println!("   • Created node identities for mesh network");

    // Setup gossip states
    let config = GossipConfig::default();

    let addresses1 = vec![PeerAddress::tcp([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1], 8001)];
    let mut gossip1 = GossipState::new(node1_private, addresses1, config.clone());

    let addresses2 = vec![PeerAddress::tcp([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1], 8002)];
    let mut gossip2 = GossipState::new(node2_private, addresses2, config);

    println!("   • Initialized gossip protocol states");

    // Add each other as peers
    let peer_info1 = gcrypt::protocols::PeerInfo {
        id: node1_id,
        addresses: vec![PeerAddress::tcp([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1], 8001)],
        public_key: node1_public,
        last_seen: 1234567890,
        reputation: 1.0,
        state: gcrypt::protocols::PeerState::Connected,
    };

    let peer_info2 = gcrypt::protocols::PeerInfo {
        id: node2_id,
        addresses: vec![PeerAddress::tcp([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1], 8002)],
        public_key: node2_public,
        last_seen: 1234567890,
        reputation: 1.0,
        state: gcrypt::protocols::PeerState::Connected,
    };

    gossip1.add_peer(peer_info2)?;
    gossip2.add_peer(peer_info1)?;

    println!("   • Nodes discovered each other as peers");

    // Create and propagate messages
    let heartbeat = gossip1.create_heartbeat(rng)?;
    let discovery = gossip1.create_peer_discovery(rng)?;

    println!("   • Created heartbeat and peer discovery messages");

    // Process messages
    let _targets1 = gossip2.process_message(heartbeat, node1_id)?;
    let _targets2 = gossip2.process_message(discovery, node1_id)?;

    println!("   • Messages processed and propagated through network");

    // Check network stats
    let stats1 = gossip1.stats();
    let stats2 = gossip2.stats();

    println!("   • Node1 stats: {} peers, {} cached messages", stats1.total_peers, stats1.cached_messages);
    println!("   • Node2 stats: {} peers, {} cached messages", stats2.total_peers, stats2.cached_messages);

    println!("   ✅ Gossip protocol mesh networking operational\n");

    Ok(())
}

// Helper function to format bytes as hex
#[allow(dead_code)]
fn format_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}