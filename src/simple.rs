//! Simple password-based vault backend
//!
//! Based on the original prusia-core vault implementation.

use crate::error::{VaultError, VaultResult};
use crate::VaultConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Secret {
    key: String,
    value: Vec<u8>,
    encrypted_value: Vec<u8>,
    nonce: Vec<u8>,
    created_at: i64,
    updated_at: i64,
    metadata: HashMap<String, String>,
}

impl Secret {
    fn new(key: String, value: Vec<u8>, encrypted: Vec<u8>, nonce: Vec<u8>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        Self {
            key,
            value,
            encrypted_value: encrypted,
            nonce,
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        }
    }
}

/// Simple password-based vault
pub struct SimpleVault {
    secrets: HashMap<String, Secret>,
    master_key: Vec<u8>,
    data_dir: PathBuf,
    initialized: bool,
}

impl SimpleVault {
    /// Create a new simple vault with default configuration
    pub fn new() -> Self {
        Self::with_config(VaultConfig::default())
    }

    /// Create a new simple vault with custom configuration
    pub fn with_config(config: VaultConfig) -> Self {
        let data_dir = config.data_dir.unwrap_or_else(|| {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("prusia-vault")
                .join("simple")
        });

        std::fs::create_dir_all(&data_dir).ok();

        Self {
            secrets: HashMap::new(),
            master_key: Vec::new(),
            data_dir,
            initialized: false,
        }
    }

    /// Initialize the vault with a password
    pub fn initialize(&mut self, password: &str) -> VaultResult<()> {
        self.master_key = Self::derive_key(password);
        self.load()?;
        self.initialized = true;
        Ok(())
    }

    /// Check if the vault is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn derive_key(password: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(b"prusia-vault-v1-salt");
        hasher.update(b"zero-trust-prusia");
        hasher.finalize().to_vec()
    }

    /// Load vault data from disk
    pub fn load(&mut self) -> VaultResult<()> {
        let vault_file = self.data_dir.join("vault.enc");

        if vault_file.exists() {
            let data = std::fs::read(&vault_file)?;
            if !data.is_empty() {
                if let Ok(decrypted) = self.decrypt_vault(&data) {
                    if let Ok(secrets) =
                        serde_json::from_slice::<HashMap<String, Secret>>(&decrypted)
                    {
                        self.secrets = secrets;
                    }
                }
            }
        }

        Ok(())
    }

    /// Save vault data to disk
    pub fn save(&self) -> VaultResult<()> {
        let data = serde_json::to_vec(&self.secrets)?;
        let encrypted = self.encrypt_vault(&data)?;

        std::fs::write(self.data_dir.join("vault.enc"), encrypted)?;
        Ok(())
    }

    fn encrypt(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        let nonce = self.generate_nonce(16);
        let key = &self.master_key;

        let mut result = Vec::with_capacity(nonce.len() + data.len() + 32);
        result.extend_from_slice(&nonce);

        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key[i % key.len()];
            let nonce_byte = nonce[i % nonce.len()];
            result.push(byte ^ key_byte ^ nonce_byte);
        }

        let checksum = self.checksum(data);
        result.extend_from_slice(&checksum);

        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        if data.len() < 48 {
            // nonce(16) + at least 1 byte + checksum(32)
            return Err(VaultError::Decryption("Invalid encrypted data".to_string()));
        }

        let nonce = &data[..16];
        let ciphertext = &data[16..data.len() - 32];
        let key = &self.master_key;

        let mut decrypted = Vec::with_capacity(ciphertext.len());
        for (i, &byte) in ciphertext.iter().enumerate() {
            let key_byte = key[i % key.len()];
            let nonce_byte = nonce[i % nonce.len()];
            decrypted.push(byte ^ key_byte ^ nonce_byte);
        }

        let checksum_received = &data[data.len() - 32..];
        let checksum = self.checksum(&decrypted);
        if checksum != checksum_received {
            return Err(VaultError::ChecksumMismatch);
        }

        Ok(decrypted)
    }

    fn generate_nonce(&self, len: usize) -> Vec<u8> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut nonce = Vec::with_capacity(len);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        for i in 0..len {
            let mix = now.wrapping_mul((i as u64).wrapping_add(1).wrapping_mul(0x517cc1b727220a95));
            nonce.push((mix as u8).wrapping_add(i as u8));
        }

        let key_sum: u32 = self.master_key.iter().map(|&b| u32::from(b)).sum();
        let key_byte = (key_sum & 0xFF) as u8;
        nonce.iter_mut().for_each(|b| *b ^= key_byte);

        nonce
    }

    fn checksum(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&self.master_key);
        hasher.finalize().to_vec()
    }

    fn encrypt_vault(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        self.encrypt(data)
    }

    fn decrypt_vault(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        self.decrypt(data)
    }

    /// Store a secret
    pub fn store(&mut self, key: &str, value: &str) -> VaultResult<()> {
        if !self.initialized {
            return Err(VaultError::NotInitialized);
        }

        let encrypted = self.encrypt(value.as_bytes())?;
        let nonce = encrypted[..16].to_vec();

        let secret = Secret::new(
            key.to_string(),
            value.as_bytes().to_vec(),
            encrypted[16..encrypted.len() - 32].to_vec(),
            nonce,
        );

        self.secrets.insert(key.to_string(), secret);
        self.save()
    }

    /// Retrieve a secret
    pub fn retrieve(&self, key: &str) -> VaultResult<String> {
        if !self.initialized {
            return Err(VaultError::NotInitialized);
        }

        let secret = self
            .secrets
            .get(key)
            .ok_or_else(|| VaultError::SecretNotFound(key.to_string()))?;

        let mut full_data = secret.nonce.clone();
        full_data.extend_from_slice(&secret.encrypted_value);
        full_data.extend_from_slice(&self.checksum(&secret.value));

        let decrypted = self.decrypt(&full_data)?;

        String::from_utf8(decrypted).map_err(|e| VaultError::Other(format!("UTF-8 error: {}", e)))
    }

    /// List all secret keys
    pub fn list(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }

    /// Delete a secret
    pub fn delete(&mut self, key: &str) -> VaultResult<()> {
        if !self.initialized {
            return Err(VaultError::NotInitialized);
        }

        if self.secrets.remove(key).is_none() {
            return Err(VaultError::SecretNotFound(key.to_string()));
        }
        self.save()
    }

    /// Generate and store an API key
    pub fn generate_api_key(&mut self, service: &str) -> VaultResult<String> {
        let api_key = generate_secure_key(32);
        self.store(&format!("{service}_api_key"), &api_key)?;
        Ok(api_key)
    }

    /// Wipe all vault data
    pub fn wipe(&mut self) -> VaultResult<()> {
        for secret in self.secrets.values_mut() {
            secret.value.iter_mut().for_each(|b| *b = 0);
            secret.encrypted_value.iter_mut().for_each(|b| *b = 0);
        }
        self.secrets.clear();

        let vault_file = self.data_dir.join("vault.enc");
        if vault_file.exists() {
            std::fs::remove_file(&vault_file)?;
        }

        self.master_key.iter_mut().for_each(|b| *b = 0);
        self.master_key.clear();

        self.initialized = false;
        Ok(())
    }
}

impl Default for SimpleVault {
    fn default() -> Self {
        Self::new()
    }
}

fn generate_secure_key(len: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        .chars()
        .collect();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut key = String::with_capacity(len);
    for i in 0..len {
        let mix = now.wrapping_mul((i as u64).wrapping_add(1).wrapping_mul(0x517cc1b727220a95));
        let idx = ((mix ^ (mix >> 17)) as usize) % chars.len();
        key.push(chars[idx]);
    }

    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_vault_lifecycle() {
        let dir = tempdir().unwrap();
        let config = VaultConfig {
            data_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };

        let mut vault = SimpleVault::with_config(config);

        // Should not be initialized
        assert!(!vault.is_initialized());

        // Initialize
        vault.initialize("test-password").unwrap();
        assert!(vault.is_initialized());

        // Store and retrieve
        vault.store("test-key", "test-value").unwrap();
        let value = vault.retrieve("test-key").unwrap();
        assert_eq!(value, "test-value");

        // List
        let keys = vault.list();
        assert_eq!(keys, vec!["test-key".to_string()]);

        // Delete
        vault.delete("test-key").unwrap();
        assert!(vault.retrieve("test-key").is_err());

        // Wipe
        vault.store("another-key", "another-value").unwrap();
        vault.wipe().unwrap();
        assert!(!vault.is_initialized());
        assert!(vault.list().is_empty());
    }
}
