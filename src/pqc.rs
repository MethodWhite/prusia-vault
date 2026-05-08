//! PQC (Post-Quantum Cryptography) vault backend with TPM support
//!
//! Based on the Synapsis vault implementation.

use crate::error::{VaultError, VaultResult};
use crate::VaultConfig;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64;
use getrandom;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher =
        aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|e| format!("Key error: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("Random generation failed: {}", e))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption error: {}", e))?;

    let mut result = Vec::new();
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 12 {
        return Err("Ciphertext too short".to_string());
    }

    let nonce_bytes = &ciphertext[..12];
    let data = &ciphertext[12..];

    let cipher =
        aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|e| format!("Key error: {}", e))?;

    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, data)
        .map_err(|e| format!("Decryption error: {}", e))?;

    Ok(plaintext)
}

fn generate_kyber_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let (pk, sk) = kyber512::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

fn kyber_encapsulate(pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let public_key =
        kyber512::PublicKey::from_bytes(pk).map_err(|e| format!("Invalid public key: {}", e))?;
    let (ss, ct) = kyber512::encapsulate(&public_key);
    Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

fn kyber_decapsulate(ct: &[u8], sk: &[u8]) -> Result<Vec<u8>, String> {
    let secret_key =
        kyber512::SecretKey::from_bytes(sk).map_err(|e| format!("Invalid secret key: {}", e))?;
    let ciphertext =
        kyber512::Ciphertext::from_bytes(ct).map_err(|e| format!("Invalid ciphertext: {}", e))?;
    let ss = kyber512::decapsulate(&ciphertext, &secret_key);
    Ok(ss.as_bytes().to_vec())
}

const PQC_PASSPHRASE_ENV: &str = "PRUSIA_PQC_PASSPHRASE";
const PQC_KEYPAIR_FILE: &str = "vault_pqc.json";
const PQC_ENCRYPTED_MASTER_KEY_FILE: &str = "vault_master.pqc";

fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(salt);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PqcKeyPair {
    public_key: Vec<u8>,
    encrypted_secret_key: Vec<u8>,
    salt: Vec<u8>,
}

/// Session key for PQC encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKey {
    /// Unique session identifier
    pub session_id: String,
    /// Encryption key material
    pub encryption_key: Vec<u8>,
    /// MAC key for integrity verification
    pub mac_key: Vec<u8>,
    /// Unix timestamp when key was created
    pub created_at: i64,
    /// Unix timestamp of last key usage
    pub last_used: i64,
    /// Number of times key has been rotated
    pub rotation_count: u32,
    /// Optional expiration timestamp
    pub expires_at: Option<i64>,
}

impl SessionKey {
    /// Check if the session key has expired
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.map(|e| now > e).unwrap_or(false)
    }
}

/// Vault entry for storing encrypted session keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Unique session identifier
    pub session_id: String,
    /// Encrypted key material
    pub encrypted_key: Vec<u8>,
    /// Fingerprint of the encryption key
    pub key_fingerprint: String,
    /// Unix timestamp when entry was created
    pub created_at: i64,
    /// Unix timestamp of last access
    pub last_used: i64,
    /// Number of times key has been rotated
    pub rotation_count: u32,
    /// Whether key is protected by TPM
    pub tpm_protected: bool,
}

struct MasterKey {
    key: Vec<u8>,
    created_at: i64,
    key_id: String,
}

impl serde::Serialize for MasterKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("MasterKey", 3)?;
        s.serialize_field("key", &base64_encode(&self.key))?;
        s.serialize_field("created_at", &self.created_at)?;
        s.serialize_field("key_id", &self.key_id)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for MasterKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct RawMasterKey {
            key: String,
            created_at: i64,
            key_id: String,
        }
        let raw = RawMasterKey::deserialize(deserializer)?;
        Ok(MasterKey {
            key: base64_decode(&raw.key).map_err(serde::de::Error::custom)?,
            created_at: raw.created_at,
            key_id: raw.key_id,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PqcEncryptedMasterKey {
    version: u8,
    public_key: Vec<u8>,
    encrypted_secret_key: Vec<u8>,
    encrypted_master_key: Vec<u8>,
    nonce: Vec<u8>,
}

/// PQC vault with TPM support
pub struct PqcVault {
    /// In-memory cache of vault entries
    entries: Arc<RwLock<HashMap<String, VaultEntry>>>,
    /// Master encryption key (in-memory only)
    master_key: Arc<RwLock<Option<MasterKey>>>,
    /// PQC public key for encryption
    pq_public_key: Arc<RwLock<Option<Vec<u8>>>>,
    /// PQC secret key for decryption
    pq_secret_key: Arc<RwLock<Option<Vec<u8>>>>,
    /// Whether to use TPM for key protection
    use_tpm: bool,
    /// Directory for vault data storage
    data_dir: PathBuf,
    /// In-memory secrets cache
    secrets: Arc<RwLock<HashMap<String, Secret>>>,
}

/// Secret entry in the vault
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Secret {
    /// Secret identifier
    key: String,
    /// Encrypted secret value
    encrypted_value: Vec<u8>,
    /// Nonce for encryption
    nonce: Vec<u8>,
    /// Creation timestamp
    created_at: i64,
    /// Additional metadata
    metadata: HashMap<String, String>,
}

impl PqcVault {
    /// Create a new PQC vault with default configuration
    pub fn new(data_dir: PathBuf) -> Self {
        Self::with_config(data_dir, VaultConfig::default())
    }

    /// Create a new PQC vault with custom configuration
    pub fn with_config(data_dir: PathBuf, config: VaultConfig) -> Self {
        std::fs::create_dir_all(&data_dir).ok();

        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            master_key: Arc::new(RwLock::new(None)),
            pq_public_key: Arc::new(RwLock::new(None)),
            pq_secret_key: Arc::new(RwLock::new(None)),
            use_tpm: config.use_tpm && Self::check_tpm_availability(),
            data_dir,
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn check_tpm_availability() -> bool {
        #[cfg(target_os = "linux")]
        {
            std::path::Path::new("/dev/tpm0").exists()
                || std::path::Path::new("/dev/tpmrm0").exists()
        }

        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Check if TPM is available
    pub fn is_tpm_available(&self) -> bool {
        self.use_tpm
    }

    /// Initialize the vault with a passphrase
    pub fn initialize_with_passphrase(&self, passphrase: &str) -> VaultResult<()> {
        std::fs::create_dir_all(&self.data_dir)?;

        let entries_path = self.data_dir.join("vault_entries.json");
        if entries_path.exists() {
            let data = std::fs::read_to_string(&entries_path)?;
            if let Ok(entries) = serde_json::from_str::<HashMap<String, VaultEntry>>(&data) {
                let mut e = self.entries.write().unwrap_or_else(|e| e.into_inner());
                *e = entries;
            }
        }

        let secrets_path = self.data_dir.join("secrets.json");
        if secrets_path.exists() {
            let data = std::fs::read_to_string(&secrets_path)?;
            if let Ok(secrets) = serde_json::from_str::<HashMap<String, Secret>>(&data) {
                let mut s = self.secrets.write().unwrap_or_else(|e| e.into_inner());
                *s = secrets;
            }
        }

        self.initialize_pqc(passphrase)?;

        Ok(())
    }

    fn initialize_pqc(&self, passphrase: &str) -> VaultResult<()> {
        let keypair_path = self.data_dir.join(PQC_KEYPAIR_FILE);
        let encrypted_master_key_path = self.data_dir.join(PQC_ENCRYPTED_MASTER_KEY_FILE);

        // Load or generate PQC keypair
        if keypair_path.exists() {
            let data = std::fs::read(&keypair_path)?;
            let keypair: PqcKeyPair = serde_json::from_slice(&data)?;

            let passphrase_env = std::env::var(PQC_PASSPHRASE_ENV)
                .map_err(|_| VaultError::PqcError("PQC passphrase not set".to_string()))?;

            if passphrase_env != passphrase {
                return Err(VaultError::InvalidCredentials);
            }

            // Decrypt secret key using passphrase
            let key = derive_key_from_passphrase(&passphrase_env, &keypair.salt);
            let decrypted_sk = decrypt(&keypair.encrypted_secret_key, &key).map_err(|e| {
                VaultError::PqcError(format!("Failed to decrypt PQC secret key: {}", e))
            })?;

            let mut pk = self
                .pq_public_key
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *pk = Some(keypair.public_key);
            let mut sk = self
                .pq_secret_key
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *sk = Some(decrypted_sk);
        } else {
            // Generate new PQC keypair
            let (public_key, secret_key) = generate_kyber_keypair().map_err(|e| {
                VaultError::PqcError(format!("Failed to generate PQC keypair: {}", e))
            })?;

            // Encrypt secret key with passphrase
            let passphrase_env = std::env::var(PQC_PASSPHRASE_ENV)
                .map_err(|_| VaultError::PqcError("PQC passphrase not set".to_string()))?;
            let salt = generate_nonce(16);
            let key = derive_key_from_passphrase(&passphrase_env, &salt);
            let encrypted_secret_key = encrypt(&secret_key, &key).map_err(|e| {
                VaultError::PqcError(format!("Failed to encrypt PQC secret key: {}", e))
            })?;

            let keypair = PqcKeyPair {
                public_key,
                encrypted_secret_key,
                salt,
            };

            let data = serde_json::to_vec(&keypair)?;
            std::fs::write(&keypair_path, data)?;

            let mut pk = self
                .pq_public_key
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *pk = Some(keypair.public_key);
            let mut sk = self
                .pq_secret_key
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *sk = Some(secret_key);
        }

        // Load or generate master key with PQC encryption
        let master_key_path = self.data_dir.join("vault_master.key");
        if encrypted_master_key_path.exists() {
            // Load and decrypt PQC encrypted master key
            let data = std::fs::read(&encrypted_master_key_path)?;
            let enc_master_key: PqcEncryptedMasterKey = serde_json::from_slice(&data)?;
            let master_key_bytes = self.decrypt_master_key_with_pqc(&enc_master_key)?;
            let key_id = base64_encode(&compute_hash(&master_key_bytes)[..8]);
            let master_key = MasterKey {
                key: master_key_bytes,
                created_at: current_timestamp(),
                key_id,
            };
            let mut mk = self.master_key.write().unwrap_or_else(|e| e.into_inner());
            *mk = Some(master_key);
        } else if master_key_path.exists() {
            // Migration: plain master key exists, encrypt with PQC and store encrypted
            let data = std::fs::read(&master_key_path)?;
            let master_key = serde_json::from_slice::<MasterKey>(&data)?;
            let enc_master_key = self.encrypt_master_key_with_pqc(&master_key.key)?;
            let enc_data = serde_json::to_vec(&enc_master_key)?;
            std::fs::write(&encrypted_master_key_path, enc_data)?;
            // Optionally delete plain master key file
            let _ = std::fs::remove_file(&master_key_path);
            // Set master key in memory
            let mut mk = self.master_key.write().unwrap_or_else(|e| e.into_inner());
            *mk = Some(master_key);
        } else {
            // Generate new master key and encrypt with PQC
            let master_key = Self::generate_master_key()?;
            let enc_master_key = self.encrypt_master_key_with_pqc(&master_key.key)?;
            let enc_data = serde_json::to_vec(&enc_master_key)?;
            std::fs::write(&encrypted_master_key_path, enc_data)?;
            // Set master key in memory
            let mut mk = self.master_key.write().unwrap_or_else(|e| e.into_inner());
            *mk = Some(master_key);
        }

        Ok(())
    }

    fn encrypt_master_key_with_pqc(
        &self,
        master_key: &[u8],
    ) -> Result<PqcEncryptedMasterKey, VaultError> {
        let pk = self.pq_public_key.read().unwrap();
        let public_key = pk.as_ref().ok_or(VaultError::PqcError(
            "PQC public key not initialized".to_string(),
        ))?;

        let (ciphertext, shared_secret) = kyber_encapsulate(public_key)
            .map_err(|e| VaultError::PqcError(format!("Kyber encapsulation failed: {}", e)))?;

        // Ensure shared_secret is 32 bytes
        if shared_secret.len() != 32 {
            return Err(VaultError::PqcError(format!(
                "Invalid shared secret length: {}",
                shared_secret.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&shared_secret);

        let encrypted_master_key = encrypt(master_key, &key)
            .map_err(|e| VaultError::PqcError(format!("AES encryption failed: {}", e)))?;

        Ok(PqcEncryptedMasterKey {
            version: 1,
            public_key: public_key.clone(),
            encrypted_secret_key: ciphertext,
            encrypted_master_key,
            nonce: Vec::new(), // nonce is already prepended in encrypted_master_key
        })
    }

    fn decrypt_master_key_with_pqc(
        &self,
        enc: &PqcEncryptedMasterKey,
    ) -> Result<Vec<u8>, VaultError> {
        let sk = self.pq_secret_key.read().unwrap();
        let secret_key = sk.as_ref().ok_or(VaultError::PqcError(
            "PQC secret key not initialized".to_string(),
        ))?;

        let shared_secret = kyber_decapsulate(&enc.encrypted_secret_key, secret_key)
            .map_err(|e| VaultError::PqcError(format!("Kyber decapsulation failed: {}", e)))?;

        if shared_secret.len() != 32 {
            return Err(VaultError::PqcError(format!(
                "Invalid shared secret length: {}",
                shared_secret.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&shared_secret);

        decrypt(&enc.encrypted_master_key, &key)
            .map_err(|e| VaultError::PqcError(format!("AES decryption failed: {}", e)))
    }

    fn generate_master_key() -> Result<MasterKey, VaultError> {
        let mut key = vec![0u8; 32];
        getrandom::getrandom(&mut key)
            .map_err(|e| VaultError::Encryption(format!("random generation failed: {}", e)))?;

        let key_id = base64_encode(&compute_hash(&key)[..8]);

        Ok(MasterKey {
            key,
            created_at: current_timestamp(),
            key_id,
        })
    }

    /// Check if the vault is initialized
    pub fn is_initialized(&self) -> bool {
        self.master_key.read().unwrap().is_some()
    }

    /// Store a session key
    pub fn store_session_key(&self, session_id: &str, key_data: &[u8]) -> VaultResult<()> {
        if !self.is_initialized() {
            return Err(VaultError::NotInitialized);
        }

        let fingerprint = base64_encode(&compute_hash(key_data)[..16]);
        let encrypted_key = self.encrypt_key(key_data)?;

        let entry = VaultEntry {
            session_id: session_id.to_string(),
            encrypted_key,
            key_fingerprint: fingerprint,
            created_at: current_timestamp(),
            last_used: 0,
            rotation_count: 0,
            tpm_protected: self.use_tpm,
        };

        self.entries
            .write()
            .unwrap()
            .insert(session_id.to_string(), entry);
        self.save_entries()?;

        Ok(())
    }

    /// Get a session key
    pub fn get_session_key(&self, session_id: &str) -> VaultResult<Option<Vec<u8>>> {
        if !self.is_initialized() {
            return Err(VaultError::NotInitialized);
        }

        let entry = {
            let entries = self.entries.read().unwrap();
            entries.get(session_id).cloned()
        };

        match entry {
            Some(e) => {
                let key_data = self.decrypt_key(&e.encrypted_key)?;
                // Update last used
                let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
                if let Some(entry) = entries.get_mut(session_id) {
                    entry.last_used = current_timestamp();
                }
                Ok(Some(key_data))
            }
            None => Ok(None),
        }
    }

    /// Get a vault entry without decrypting the key
    pub fn get_entry(&self, session_id: &str) -> VaultResult<Option<VaultEntry>> {
        if !self.is_initialized() {
            return Err(VaultError::NotInitialized);
        }

        let entries = self.entries.read().unwrap();
        Ok(entries.get(session_id).cloned())
    }

    /// Rotate a session key
    pub fn rotate_session_key(&self, session_id: &str) -> VaultResult<Option<String>> {
        if !self.is_initialized() {
            return Err(VaultError::NotInitialized);
        }

        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(session_id) {
            entry.rotation_count += 1;
            entry.last_used = current_timestamp();

            // Generate new key (in real implementation)
            let new_key = vec![0u8; 32]; // Placeholder
            entry.encrypted_key = self.encrypt_key(&new_key)?;
            entry.key_fingerprint = base64_encode(&compute_hash(&entry.encrypted_key)[..16]);

            self.save_entries()?;
            Ok(Some(session_id.to_string()))
        } else {
            Ok(None)
        }
    }

    /// List all sessions
    pub fn list_sessions(&self) -> Vec<(String, String, i64)> {
        let entries = self.entries.read().unwrap();
        entries
            .values()
            .map(|e| {
                (
                    e.session_id.clone(),
                    e.key_fingerprint.clone(),
                    e.created_at,
                )
            })
            .collect()
    }

    /// Store a secret
    pub fn store_secret(&self, key: &str, value: &str) -> VaultResult<()> {
        if !self.is_initialized() {
            return Err(VaultError::NotInitialized);
        }

        let encrypted = self.encrypt_data(value.as_bytes())?;
        let nonce = encrypted[..12].to_vec();
        let encrypted_value = encrypted[12..].to_vec();

        let secret = Secret {
            key: key.to_string(),
            encrypted_value,
            nonce,
            created_at: current_timestamp(),
            metadata: HashMap::new(),
        };

        self.secrets
            .write()
            .unwrap()
            .insert(key.to_string(), secret);
        self.save_secrets()?;

        Ok(())
    }

    /// Retrieve a secret
    pub fn retrieve_secret(&self, key: &str) -> VaultResult<String> {
        if !self.is_initialized() {
            return Err(VaultError::NotInitialized);
        }

        let secrets = self.secrets.read().unwrap();
        let secret = secrets
            .get(key)
            .ok_or_else(|| VaultError::SecretNotFound(key.to_string()))?;

        let mut full = secret.nonce.clone();
        full.extend_from_slice(&secret.encrypted_value);
        let decrypted = self.decrypt_data(&full)?;

        String::from_utf8(decrypted).map_err(|e| VaultError::Other(format!("UTF-8 error: {}", e)))
    }

    /// List all secrets
    pub fn list_secrets(&self) -> Vec<String> {
        self.secrets.read().unwrap().keys().cloned().collect()
    }

    /// Delete a secret
    pub fn delete_secret(&self, key: &str) -> VaultResult<()> {
        if !self.is_initialized() {
            return Err(VaultError::NotInitialized);
        }

        if self
            .secrets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key)
            .is_none()
        {
            return Err(VaultError::SecretNotFound(key.to_string()));
        }

        self.save_secrets()
    }

    /// Wipe all vault data
    pub fn wipe(&self) -> VaultResult<()> {
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.secrets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        *self.master_key.write().unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .pq_public_key
            .write()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .pq_secret_key
            .write()
            .unwrap_or_else(|e| e.into_inner()) = None;

        // Remove files
        let _ = std::fs::remove_file(self.data_dir.join("vault_entries.json"));
        let _ = std::fs::remove_file(self.data_dir.join("secrets.json"));
        let _ = std::fs::remove_file(self.data_dir.join(PQC_KEYPAIR_FILE));
        let _ = std::fs::remove_file(self.data_dir.join(PQC_ENCRYPTED_MASTER_KEY_FILE));

        Ok(())
    }

    fn encrypt_key(&self, key: &[u8]) -> VaultResult<Vec<u8>> {
        self.encrypt_data(key)
    }

    fn encrypt_data(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        let master_key = self.master_key.read().unwrap();
        let mk = master_key.as_ref().ok_or(VaultError::NotInitialized)?;
        if mk.key.len() != 32 {
            return Err(VaultError::Encryption(
                "Invalid master key length".to_string(),
            ));
        }
        let key = Key::<Aes256Gcm>::from_slice(&mk.key);
        let cipher = Aes256Gcm::new(key);
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| VaultError::Encryption(format!("random generation failed: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    fn decrypt_data(&self, ciphertext: &[u8]) -> VaultResult<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(VaultError::Decryption("Ciphertext too short".to_string()));
        }
        let master_key = self.master_key.read().unwrap();
        let mk = master_key.as_ref().ok_or(VaultError::NotInitialized)?;
        if mk.key.len() != 32 {
            return Err(VaultError::Decryption(
                "Invalid master key length".to_string(),
            ));
        }
        let key = Key::<Aes256Gcm>::from_slice(&mk.key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let plaintext = cipher
            .decrypt(nonce, &ciphertext[12..])
            .map_err(|_| VaultError::Decryption("Decryption failed".to_string()))?;
        Ok(plaintext)
    }

    fn decrypt_key(&self, encrypted: &[u8]) -> VaultResult<Vec<u8>> {
        self.decrypt_data(encrypted)
    }

    fn save_entries(&self) -> VaultResult<()> {
        let entries = self.entries.read().unwrap();
        let data = serde_json::to_vec(&*entries)?;
        std::fs::write(self.data_dir.join("vault_entries.json"), data)?;
        Ok(())
    }

    fn save_secrets(&self) -> VaultResult<()> {
        let secrets = self.secrets.read().unwrap();
        let data = serde_json::to_vec(&*secrets)?;
        std::fs::write(self.data_dir.join("secrets.json"), data)?;
        Ok(())
    }
}

// Helper functions from synapsis vault

fn compute_hash(data: &[u8]) -> Vec<u8> {
    let h = [0x6a09e667u32, 0xbb67ae85u32, 0x3c6ef372u32, 0xa54ff53au32];

    let mut hash = [0u32; 4];
    for (i, val) in h.iter().enumerate() {
        hash[i] = *val;
    }

    for chunk in data.chunks(64) {
        let mut w = [0u32; 16];

        for (i, bytes) in chunk.chunks(4).enumerate() {
            if bytes.len() == 4 {
                w[i] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            }
        }

        for i in 0..16 {
            hash[i % 4] = hash[i % 4].wrapping_add(w[i]);
        }
    }

    let mut result = Vec::with_capacity(16);
    for val in hash.iter() {
        result.extend_from_slice(&val.to_be_bytes());
    }
    result
}

fn generate_nonce(len: usize) -> Vec<u8> {
    let mut nonce = vec![0u8; len];
    if let Err(_e) = getrandom::getrandom(&mut nonce) {
        // Fallback to weak randomness if getrandom fails (should not happen)
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        for (i, byte) in nonce.iter_mut().enumerate() {
            let val = seed.wrapping_mul(i as u64 + 1).wrapping_mul(1103515245);
            *byte = ((val >> 16) ^ val) as u8;
        }
    }
    nonce
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn base64_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>, VaultError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| VaultError::Base64(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_pqc_vault_basic() {
        let dir = tempdir().unwrap();
        let vault = PqcVault::new(dir.path().to_path_buf());

        // Should not be initialized yet
        assert!(!vault.is_initialized());

        // Initialize
        vault.initialize_with_passphrase("test-passphrase").unwrap();
        assert!(vault.is_initialized());

        // Store and retrieve a secret
        vault.store_secret("test-key", "test-value").unwrap();
        let value = vault.retrieve_secret("test-key").unwrap();
        assert_eq!(value, "test-value");

        // List secrets
        let secrets = vault.list_secrets();
        assert_eq!(secrets, vec!["test-key".to_string()]);

        // Delete secret
        vault.delete_secret("test-key").unwrap();
        assert!(vault.retrieve_secret("test-key").is_err());

        // Session key operations
        vault.store_session_key("session-1", &[1, 2, 3, 4]).unwrap();
        let key = vault.get_session_key("session-1").unwrap();
        assert!(key.is_some());

        let sessions = vault.list_sessions();
        assert_eq!(sessions.len(), 1);

        // Wipe
        vault.wipe().unwrap();
        assert!(!vault.is_initialized());
    }
}
