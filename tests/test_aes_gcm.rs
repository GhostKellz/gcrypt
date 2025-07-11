#[cfg(all(feature = "aes-gcm", feature = "alloc"))]
mod aes_gcm_tests {
    use gcrypt::protocols::aes_gcm::*;

    #[test]
    fn test_aes128_gcm_encrypt_decrypt() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, AES-GCM!";
        let aad = b"associated data";

        let cipher = Aes128GcmCipher::new(&key);
        
        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aes256_gcm_encrypt_decrypt() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, AES-GCM with 256-bit key!";
        let aad = b"associated data";

        let cipher = Aes256GcmCipher::new(&key);
        
        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_authentication_failure() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, AES-GCM!";
        let aad = b"associated data";

        let cipher = Aes128GcmCipher::new(&key);
        
        let mut ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        // Corrupt the ciphertext to cause authentication failure
        ciphertext[0] ^= 1;
        
        let result = cipher.decrypt(&nonce, &ciphertext, aad);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AesGcmError::AuthenticationFailed);
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn test_key_and_nonce_generation() {
        let key1 = generate_aes128_key();
        let key2 = generate_aes128_key();
        assert_ne!(key1, key2);

        let key1 = generate_aes256_key();
        let key2 = generate_aes256_key();
        assert_ne!(key1, key2);

        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2);
    }
}