//! Error types for the Prusia Vault

use thiserror::Error;

/// Result type for vault operations
pub type VaultResult<T> = std::result::Result<T, VaultError>;

/// Main error type for vault operations
#[derive(Error, Debug)]
pub enum VaultError {
    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 encoding/decoding errors
    #[cfg(feature = "pqc")]
    #[error("Base64 error: {0}")]
    Base64(base64::DecodeError),

    /// Encryption/decryption errors
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption errors
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Checksum mismatch
    #[error("Checksum mismatch")]
    ChecksumMismatch,

    /// Vault not initialized
    #[error("Vault not initialized")]
    NotInitialized,

    /// Secret not found
    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    /// Session not found
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    /// Invalid password or passphrase
    #[error("Invalid password or passphrase")]
    InvalidCredentials,

    /// PQC-specific errors
    #[error("PQC error: {0}")]
    PqcError(String),

    /// TPM-specific errors
    #[error("TPM error: {0}")]
    TpmError(String),

    /// Unsupported operation for current backend
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// Other errors
    #[error("Vault error: {0}")]
    Other(String),
}

impl From<String> for VaultError {
    fn from(s: String) -> Self {
        VaultError::Other(s)
    }
}

impl From<&str> for VaultError {
    fn from(s: &str) -> Self {
        VaultError::Other(s.to_string())
    }
}

#[cfg(feature = "pqc")]
impl From<base64::DecodeError> for VaultError {
    fn from(e: base64::DecodeError) -> Self {
        VaultError::Base64(e)
    }
}
