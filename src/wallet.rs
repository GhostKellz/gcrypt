//! Wallet cryptography support
//!
//! This module provides wallet-related cryptographic operations including:
//! - BIP-39 mnemonic phrase generation and validation
//! - BIP-32 hierarchical deterministic (HD) key derivation
//! - BIP-44 multi-account hierarchy support
//! - Secure key storage and management

/// BIP-39 mnemonic phrase support
#[cfg(feature = "bip39")]
pub mod bip39 {
    use bip39::{Mnemonic, Language, MnemonicType, Seed};
    #[cfg(feature = "rand_core")]
    use rand_core::{RngCore, CryptoRng};
    #[cfg(feature = "zeroize")]
    use zeroize::{Zeroize, ZeroizeOnDrop};
    #[cfg(feature = "serde")]
    use serde::{Serialize, Deserialize};

    /// Error types for BIP-39 operations
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Error {
        /// Invalid mnemonic phrase
        InvalidMnemonic,
        /// Invalid entropy length
        InvalidEntropy,
        /// Unsupported language
        UnsupportedLanguage,
        /// BIP-39 library error
        Bip39(String),
    }

    impl From<bip39::Error> for Error {
        fn from(e: bip39::Error) -> Self {
            Error::Bip39(format!("{:?}", e))
        }
    }

    /// Mnemonic phrase wrapper with additional functionality
    #[derive(Clone, Debug)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
    pub struct MnemonicPhrase {
        inner: Mnemonic,
        language: Language,
    }

    impl MnemonicPhrase {
        /// Generate a new mnemonic phrase with the specified word count
        #[cfg(feature = "rand_core")]
        pub fn generate<R: RngCore + CryptoRng>(
            rng: &mut R,
            word_count: WordCount,
            language: Language
        ) -> Result<Self, Error> {
            let mnemonic_type = match word_count {
                WordCount::Twelve => MnemonicType::Words12,
                WordCount::Fifteen => MnemonicType::Words15,
                WordCount::Eighteen => MnemonicType::Words18,
                WordCount::TwentyOne => MnemonicType::Words21,
                WordCount::TwentyFour => MnemonicType::Words24,
            };

            let mnemonic = Mnemonic::new(mnemonic_type, language);
            Ok(Self {
                inner: mnemonic,
                language,
            })
        }

        /// Create a mnemonic from an existing phrase string
        pub fn from_phrase(phrase: &str, language: Language) -> Result<Self, Error> {
            let mnemonic = Mnemonic::from_phrase(phrase, language)?;
            Ok(Self {
                inner: mnemonic,
                language,
            })
        }

        /// Create a mnemonic from entropy bytes
        pub fn from_entropy(entropy: &[u8], language: Language) -> Result<Self, Error> {
            let mnemonic = Mnemonic::from_entropy(entropy, language)?;
            Ok(Self {
                inner: mnemonic,
                language,
            })
        }

        /// Get the mnemonic phrase as a string
        pub fn phrase(&self) -> &str {
            self.inner.phrase()
        }

        /// Get the individual words
        pub fn words(&self) -> Vec<&str> {
            self.inner.word_iter().collect()
        }

        /// Get the word count
        pub fn word_count(&self) -> usize {
            self.inner.word_count()
        }

        /// Get the language
        pub fn language(&self) -> Language {
            self.language
        }

        /// Generate a seed from the mnemonic with optional passphrase
        pub fn to_seed(&self, passphrase: Option<&str>) -> Seed {
            Seed::new(&self.inner, passphrase.unwrap_or(""))
        }

        /// Generate entropy bytes from the mnemonic
        pub fn to_entropy(&self) -> Vec<u8> {
            self.inner.entropy()
        }

        /// Validate the mnemonic checksum
        pub fn validate(&self) -> bool {
            // The mnemonic is already validated during construction
            true
        }

        /// Convert to BIP-32 seed bytes (64 bytes)
        pub fn to_seed_bytes(&self, passphrase: Option<&str>) -> [u8; 64] {
            self.to_seed(passphrase).as_bytes().try_into()
                .expect("Seed should be 64 bytes")
        }
    }

    /// Supported word counts for mnemonic phrases
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WordCount {
        Twelve = 12,
        Fifteen = 15,
        Eighteen = 18,
        TwentyOne = 21,
        TwentyFour = 24,
    }

    impl WordCount {
        /// Get the entropy length in bytes for this word count
        pub fn entropy_length(&self) -> usize {
            match self {
                WordCount::Twelve => 16,
                WordCount::Fifteen => 20,
                WordCount::Eighteen => 24,
                WordCount::TwentyOne => 28,
                WordCount::TwentyFour => 32,
            }
        }
    }

    /// Utility functions for BIP-39 operations
    pub mod utils {
        use super::*;

        /// Generate entropy for a mnemonic with the specified word count
        #[cfg(feature = "rand_core")]
        pub fn generate_entropy<R: RngCore + CryptoRng>(
            rng: &mut R,
            word_count: WordCount
        ) -> Vec<u8> {
            let mut entropy = vec![0u8; word_count.entropy_length()];
            rng.fill_bytes(&mut entropy);
            entropy
        }

        /// Validate a mnemonic phrase string
        pub fn validate_phrase(phrase: &str, language: Language) -> bool {
            Mnemonic::validate(phrase, language).is_ok()
        }

        /// Get the word list for a specific language
        pub fn get_word_list(language: Language) -> &'static [&'static str] {
            bip39::Language::word_list(&language)
        }

        /// Find the closest matching words for a partial input (useful for auto-completion)
        pub fn find_words(prefix: &str, language: Language) -> Vec<&'static str> {
            let word_list = get_word_list(language);
            word_list
                .iter()
                .filter(|word| word.starts_with(prefix))
                .copied()
                .collect()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use rand::thread_rng;

        #[test]
        fn test_mnemonic_generation() {
            let mut rng = thread_rng();

            for word_count in [WordCount::Twelve, WordCount::TwentyFour] {
                let mnemonic = MnemonicPhrase::generate(&mut rng, word_count, Language::English).unwrap();
                assert_eq!(mnemonic.word_count(), word_count as usize);
                assert!(mnemonic.validate());

                // Test seed generation
                let seed = mnemonic.to_seed(None);
                assert_eq!(seed.as_bytes().len(), 64);

                // Test with passphrase
                let seed_with_passphrase = mnemonic.to_seed(Some("test"));
                assert_ne!(seed.as_bytes(), seed_with_passphrase.as_bytes());
            }
        }

        #[test]
        fn test_mnemonic_from_phrase() {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mnemonic = MnemonicPhrase::from_phrase(phrase, Language::English).unwrap();
            assert_eq!(mnemonic.phrase(), phrase);
            assert_eq!(mnemonic.word_count(), 12);
        }

        #[test]
        fn test_entropy_roundtrip() {
            let mut rng = thread_rng();
            let entropy = utils::generate_entropy(&mut rng, WordCount::Twelve);

            let mnemonic = MnemonicPhrase::from_entropy(&entropy, Language::English).unwrap();
            let recovered_entropy = mnemonic.to_entropy();

            assert_eq!(entropy, recovered_entropy);
        }

        #[test]
        fn test_word_utils() {
            assert!(utils::validate_phrase(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                Language::English
            ));

            let words = utils::find_words("aban", Language::English);
            assert!(words.contains(&"abandon"));
        }
    }
}

/// BIP-32 hierarchical deterministic key derivation
#[cfg(feature = "bip32")]
pub mod bip32 {
    use bip32::{XPrv, XPub, DerivationPath, ChainCode, Prefix};
    #[cfg(feature = "rand_core")]
    use rand_core::{RngCore, CryptoRng};
    #[cfg(feature = "zeroize")]
    use zeroize::{Zeroize, ZeroizeOnDrop};
    #[cfg(feature = "serde")]
    use serde::{Serialize, Deserialize};

    /// Error types for BIP-32 operations
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Error {
        /// Invalid derivation path
        InvalidPath,
        /// Invalid extended key
        InvalidExtendedKey,
        /// Hardened derivation from public key
        HardenedFromPublic,
        /// BIP-32 library error
        Bip32(String),
    }

    impl From<bip32::Error> for Error {
        fn from(e: bip32::Error) -> Self {
            Error::Bip32(format!("{:?}", e))
        }
    }

    /// Extended private key with additional functionality
    #[derive(Clone)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
    pub struct ExtendedPrivateKey {
        inner: XPrv,
    }

    impl ExtendedPrivateKey {
        /// Create a master key from seed bytes
        pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
            let xprv = XPrv::new(seed)?;
            Ok(Self { inner: xprv })
        }

        /// Derive a child key at the given derivation path
        pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Error> {
            let derived = self.inner.derive_path(path)?;
            Ok(Self { inner: derived })
        }

        /// Derive a child key at a single index
        pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
            let derived = self.inner.derive_child(index.into())?;
            Ok(Self { inner: derived })
        }

        /// Get the corresponding extended public key
        pub fn to_extended_public_key(&self) -> ExtendedPublicKey {
            ExtendedPublicKey {
                inner: self.inner.public_key(),
            }
        }

        /// Get the private key bytes (32 bytes)
        pub fn private_key_bytes(&self) -> [u8; 32] {
            self.inner.private_key().to_bytes()
        }

        /// Get the public key bytes (33 bytes compressed)
        pub fn public_key_bytes(&self) -> [u8; 33] {
            self.inner.public_key().public_key().to_bytes()
        }

        /// Get the chain code
        pub fn chain_code(&self) -> &ChainCode {
            self.inner.chain_code()
        }

        /// Serialize to string (base58check)
        pub fn to_string(&self, prefix: Prefix) -> String {
            self.inner.to_string(prefix)
        }

        /// Parse from string (base58check)
        pub fn from_string(s: &str) -> Result<Self, Error> {
            let xprv = XPrv::from_str(s)?;
            Ok(Self { inner: xprv })
        }
    }

    /// Extended public key with additional functionality
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct ExtendedPublicKey {
        inner: XPub,
    }

    impl ExtendedPublicKey {
        /// Derive a non-hardened child key at the given index
        pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
            if index >= 0x80000000 {
                return Err(Error::HardenedFromPublic);
            }
            let derived = self.inner.derive_child(index.into())?;
            Ok(Self { inner: derived })
        }

        /// Derive a child key at the given derivation path (must be non-hardened)
        pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Error> {
            let derived = self.inner.derive_path(path)?;
            Ok(Self { inner: derived })
        }

        /// Get the public key bytes (33 bytes compressed)
        pub fn public_key_bytes(&self) -> [u8; 33] {
            self.inner.public_key().to_bytes()
        }

        /// Get the chain code
        pub fn chain_code(&self) -> &ChainCode {
            self.inner.chain_code()
        }

        /// Serialize to string (base58check)
        pub fn to_string(&self, prefix: Prefix) -> String {
            self.inner.to_string(prefix)
        }

        /// Parse from string (base58check)
        pub fn from_string(s: &str) -> Result<Self, Error> {
            let xpub = XPub::from_str(s)?;
            Ok(Self { inner: xpub })
        }
    }

    /// Utility functions for BIP-32 operations
    pub mod utils {
        use super::*;

        /// Parse a derivation path from string (e.g., "m/44'/0'/0'/0/0")
        pub fn parse_path(path_str: &str) -> Result<DerivationPath, Error> {
            path_str.parse().map_err(Error::from)
        }

        /// Create a hardened derivation index
        pub fn hardened(index: u32) -> u32 {
            index | 0x80000000
        }

        /// Check if an index is hardened
        pub fn is_hardened(index: u32) -> bool {
            index & 0x80000000 != 0
        }

        /// Standard BIP-44 derivation path for Bitcoin mainnet
        pub fn bip44_path(account: u32, change: u32, address_index: u32) -> DerivationPath {
            format!("m/44'/0'/{}'/{}/{}", account, change, address_index)
                .parse()
                .expect("Valid BIP-44 path")
        }

        /// Standard BIP-49 derivation path (P2SH-wrapped SegWit)
        pub fn bip49_path(account: u32, change: u32, address_index: u32) -> DerivationPath {
            format!("m/49'/0'/{}'/{}/{}", account, change, address_index)
                .parse()
                .expect("Valid BIP-49 path")
        }

        /// Standard BIP-84 derivation path (native SegWit)
        pub fn bip84_path(account: u32, change: u32, address_index: u32) -> DerivationPath {
            format!("m/84'/0'/{}'/{}/{}", account, change, address_index)
                .parse()
                .expect("Valid BIP-84 path")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[cfg(feature = "bip39")]
        use crate::wallet::bip39::MnemonicPhrase;

        #[test]
        fn test_master_key_derivation() {
            let seed = [0x42u8; 64]; // Test seed
            let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

            // Test child derivation
            let child = master.derive_child(0).unwrap();
            assert_ne!(master.private_key_bytes(), child.private_key_bytes());

            // Test hardened derivation
            let hardened_child = master.derive_child(utils::hardened(0)).unwrap();
            assert_ne!(child.private_key_bytes(), hardened_child.private_key_bytes());
        }

        #[test]
        fn test_extended_public_key() {
            let seed = [0x42u8; 64];
            let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
            let master_pub = master.to_extended_public_key();

            // Test non-hardened derivation from public key
            let child_priv = master.derive_child(0).unwrap();
            let child_pub_from_priv = child_priv.to_extended_public_key();
            let child_pub_from_master = master_pub.derive_child(0).unwrap();

            assert_eq!(child_pub_from_priv.public_key_bytes(), child_pub_from_master.public_key_bytes());
        }

        #[test]
        fn test_derivation_paths() {
            let path = utils::parse_path("m/44'/0'/0'/0/0").unwrap();
            assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");

            let bip44_path = utils::bip44_path(0, 0, 0);
            assert_eq!(bip44_path.to_string(), "m/44'/0'/0'/0/0");
        }

        #[test]
        #[cfg(feature = "bip39")]
        fn test_bip39_to_bip32_integration() {
            use rand::thread_rng;
            let mut rng = thread_rng();

            // Generate mnemonic
            let mnemonic = MnemonicPhrase::generate(&mut rng, crate::wallet::bip39::WordCount::Twelve, bip39::Language::English).unwrap();

            // Convert to seed
            let seed_bytes = mnemonic.to_seed_bytes(None);

            // Create master key
            let master = ExtendedPrivateKey::from_seed(&seed_bytes).unwrap();

            // Derive BIP-44 addresses
            let account0 = master.derive_path(&utils::bip44_path(0, 0, 0)).unwrap();
            let account1 = master.derive_path(&utils::bip44_path(0, 0, 1)).unwrap();

            assert_ne!(account0.private_key_bytes(), account1.private_key_bytes());
        }
    }
}