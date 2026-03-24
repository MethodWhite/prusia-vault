//! # Prusia Vault - Unified Secure Storage
//!
//! A secure vault system for the MethodWhite ecosystem with multiple backends:
//! - **Simple backend**: Password-based encryption (default)
//! - **PQC backend**: Post-quantum cryptography with TPM support (optional)
//!
//! ## Features
//!
//! - `simple`: Basic password-based encryption (enabled by default)
//! - `pqc`: Post-quantum cryptography with AES-GCM and ML-KEM
//! - `tpm`: TPM integration for hardware security (future)
//!
//! ## Usage
//!
//! ```rust,no_run
//! use prusia_vault::{Vault, VaultConfig};
//!
//! // Create a simple vault
//! let mut vault = Vault::simple();
//! vault.initialize("my-secret-password").unwrap();
//!
//! // Store a secret
//! vault.store("api_key", "secret-value").unwrap();
//!
//! // Retrieve a secret
//! let value = vault.retrieve("api_key").unwrap();
//! println!("Retrieved: {}", value);
//! ```
//!
//! With PQC backend:
//!
//! ```rust,ignore
//! use prusia_vault::{Vault, VaultConfig};
//!
//! let mut vault = Vault::pqc("/path/to/data");
//! vault.initialize_with_passphrase("pqc-passphrase").unwrap();
//!
//! // Store session keys or secrets
//! vault.store_session_key("session-1", &[1, 2, 3, 4]).unwrap();
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod error;

#[cfg(feature = "simple")]
pub mod simple;

#[cfg(feature = "pqc")]
pub mod pqc;

use error::{VaultError, VaultResult};

/// Vault configuration options
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Data directory for vault storage
    pub data_dir: Option<std::path::PathBuf>,
    /// Whether to use TPM if available
    pub use_tpm: bool,
    /// Auto-rotate keys after this many seconds
    pub key_rotation_interval: Option<u64>,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            data_dir: None,
            use_tpm: false,
            key_rotation_interval: None,
        }
    }
}

/// Main vault interface that abstracts over different backends
pub enum Vault {
    /// Simple password-based vault
    #[cfg(feature = "simple")]
    Simple(simple::SimpleVault),

    /// PQC-enhanced vault with TPM support
    #[cfg(feature = "pqc")]
    Pqc(pqc::PqcVault),
}

impl Vault {
    /// Create a new simple vault with default configuration
    #[cfg(feature = "simple")]
    pub fn simple() -> Self {
        Self::Simple(simple::SimpleVault::new())
    }

    /// Create a new simple vault with custom configuration
    #[cfg(feature = "simple")]
    pub fn simple_with_config(config: VaultConfig) -> Self {
        Self::Simple(simple::SimpleVault::with_config(config))
    }

    /// Create a new PQC vault with default configuration
    #[cfg(feature = "pqc")]
    pub fn pqc(data_dir: impl AsRef<std::path::Path>) -> Self {
        Self::Pqc(pqc::PqcVault::new(data_dir.as_ref().to_path_buf()))
    }

    /// Create a new PQC vault with custom configuration
    #[cfg(feature = "pqc")]
    pub fn pqc_with_config(data_dir: impl AsRef<std::path::Path>, config: VaultConfig) -> Self {
        Self::Pqc(pqc::PqcVault::with_config(
            data_dir.as_ref().to_path_buf(),
            config,
        ))
    }

    /// Initialize the vault with a password (for simple backend)
    pub fn initialize(&mut self, password: &str) -> VaultResult<()> {
        match self {
            #[cfg(feature = "simple")]
            Vault::Simple(vault) => vault.initialize(password),

            #[cfg(feature = "pqc")]
            Vault::Pqc(vault) => vault.initialize_with_passphrase(password),
        }
    }

    /// Check if the vault is initialized
    pub fn is_initialized(&self) -> bool {
        match self {
            #[cfg(feature = "simple")]
            Vault::Simple(vault) => vault.is_initialized(),

            #[cfg(feature = "pqc")]
            Vault::Pqc(vault) => vault.is_initialized(),
        }
    }

    /// Store a secret with the given key
    pub fn store(&mut self, key: &str, value: &str) -> VaultResult<()> {
        match self {
            #[cfg(feature = "simple")]
            Vault::Simple(vault) => vault.store(key, value),

            #[cfg(feature = "pqc")]
            Vault::Pqc(vault) => vault.store_secret(key, value),
        }
    }

    /// Retrieve a secret by key
    pub fn retrieve(&self, key: &str) -> VaultResult<String> {
        match self {
            #[cfg(feature = "simple")]
            Vault::Simple(vault) => vault.retrieve(key),

            #[cfg(feature = "pqc")]
            Vault::Pqc(vault) => vault.retrieve_secret(key),
        }
    }

    /// Delete a secret by key
    pub fn delete(&mut self, key: &str) -> VaultResult<()> {
        match self {
            #[cfg(feature = "simple")]
            Vault::Simple(vault) => vault.delete(key),

            #[cfg(feature = "pqc")]
            Vault::Pqc(vault) => vault.delete_secret(key),
        }
    }

    /// List all stored secret keys
    pub fn list(&self) -> Vec<String> {
        match self {
            #[cfg(feature = "simple")]
            Vault::Simple(vault) => vault.list(),

            #[cfg(feature = "pqc")]
            Vault::Pqc(vault) => vault.list_secrets(),
        }
    }

    /// Wipe all vault data (destructive!)
    pub fn wipe(&mut self) -> VaultResult<()> {
        match self {
            #[cfg(feature = "simple")]
            Vault::Simple(vault) => vault.wipe(),

            #[cfg(feature = "pqc")]
            Vault::Pqc(vault) => vault.wipe(),
        }
    }

    /// Get the backend type as a string
    pub fn backend_type(&self) -> &'static str {
        match self {
            #[cfg(feature = "simple")]
            Vault::Simple(_) => "simple",

            #[cfg(feature = "pqc")]
            Vault::Pqc(_) => "pqc",
        }
    }
}

/// Session key management (PQC backend only)
impl Vault {
    /// Store a session key (PQC backend only)
    #[cfg(feature = "pqc")]
    pub fn store_session_key(&self, session_id: &str, key_data: &[u8]) -> VaultResult<()> {
        match self {
            Vault::Pqc(vault) => vault.store_session_key(session_id, key_data),
            _ => Err(VaultError::UnsupportedOperation(
                "Session keys require PQC backend".to_string(),
            )),
        }
    }

    /// Get a session key (PQC backend only)
    #[cfg(feature = "pqc")]
    pub fn get_session_key(&self, session_id: &str) -> VaultResult<Option<Vec<u8>>> {
        match self {
            Vault::Pqc(vault) => vault.get_session_key(session_id),
            _ => Err(VaultError::UnsupportedOperation(
                "Session keys require PQC backend".to_string(),
            )),
        }
    }

    /// Rotate a session key (PQC backend only)
    #[cfg(feature = "pqc")]
    pub fn rotate_session_key(&self, session_id: &str) -> VaultResult<Option<String>> {
        match self {
            Vault::Pqc(vault) => vault.rotate_session_key(session_id),
            _ => Err(VaultError::UnsupportedOperation(
                "Session key rotation requires PQC backend".to_string(),
            )),
        }
    }

    /// List all sessions (PQC backend only)
    #[cfg(feature = "pqc")]
    pub fn list_sessions(&self) -> Vec<(String, String, i64)> {
        match self {
            Vault::Pqc(vault) => vault.list_sessions(),
            _ => vec![],
        }
    }

    /// Check if TPM is available (PQC backend only)
    #[cfg(feature = "pqc")]
    pub fn is_tpm_available(&self) -> bool {
        match self {
            Vault::Pqc(vault) => vault.is_tpm_available(),
            _ => false,
        }
    }
}
