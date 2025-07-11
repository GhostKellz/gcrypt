//! Example demonstrating AES-GCM usage for GQUIC/QUIC packet encryption

#[cfg(all(feature = "aes-gcm", feature = "alloc", feature = "rand_core"))]
fn main() {
    use gcrypt::protocols::aes_gcm::*;
    
    println!("=== AES-GCM Example for GQUIC/QUIC ===");
    
    // Generate random keys and nonce (in real usage, these would be derived from key exchange)
    let aes128_key = generate_aes128_key();
    let aes256_key = generate_aes256_key();
    let nonce = generate_nonce();
    
    println!("Generated AES-128 key: {:02x?}", aes128_key);
    println!("Generated AES-256 key: {:02x?}", aes256_key);
    println!("Generated nonce: {:02x?}", nonce);
    
    // Sample QUIC packet payload
    let packet_payload = b"This is a sample QUIC packet payload that needs to be encrypted";
    let associated_data = b"QUIC packet header"; // In real QUIC, this would be the packet header
    
    println!("\nOriginal payload: {:?}", std::str::from_utf8(packet_payload).unwrap());
    println!("Associated data: {:?}", std::str::from_utf8(associated_data).unwrap());
    
    // Test with AES-128-GCM
    println!("\n=== AES-128-GCM Test ===");
    let cipher_128 = Aes128GcmCipher::new(&aes128_key);
    
    let encrypted_128 = cipher_128.encrypt(&nonce, packet_payload, associated_data)
        .expect("Encryption failed");
    println!("Encrypted payload (AES-128): {} bytes", encrypted_128.len());
    
    let decrypted_128 = cipher_128.decrypt(&nonce, &encrypted_128, associated_data)
        .expect("Decryption failed");
    println!("Decrypted payload: {:?}", std::str::from_utf8(&decrypted_128).unwrap());
    
    // Test with AES-256-GCM
    println!("\n=== AES-256-GCM Test ===");
    let cipher_256 = Aes256GcmCipher::new(&aes256_key);
    
    let encrypted_256 = cipher_256.encrypt(&nonce, packet_payload, associated_data)
        .expect("Encryption failed");
    println!("Encrypted payload (AES-256): {} bytes", encrypted_256.len());
    
    let decrypted_256 = cipher_256.decrypt(&nonce, &encrypted_256, associated_data)
        .expect("Decryption failed");
    println!("Decrypted payload: {:?}", std::str::from_utf8(&decrypted_256).unwrap());
    
    // Demonstrate authentication failure
    println!("\n=== Authentication Test ===");
    let mut tampered_ciphertext = encrypted_128.clone();
    tampered_ciphertext[0] ^= 1; // Corrupt the first byte
    
    match cipher_128.decrypt(&nonce, &tampered_ciphertext, associated_data) {
        Ok(_) => println!("ERROR: Authentication should have failed!"),
        Err(AesGcmError::AuthenticationFailed) => println!("✓ Authentication correctly failed for tampered data"),
        Err(e) => println!("Unexpected error: {:?}", e),
    }
    
    println!("\n=== Success! ===");
    println!("AES-GCM is ready for use in GQUIC/QUIC implementations");
}

#[cfg(not(all(feature = "aes-gcm", feature = "alloc", feature = "rand_core")))]
fn main() {
    println!("This example requires the 'aes-gcm', 'alloc', and 'rand_core' features to be enabled.");
    println!("Run with: cargo run --example aes_gcm_example --features 'aes-gcm,alloc,rand_core'");
}