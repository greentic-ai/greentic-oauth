use std::path::{Component, Path, PathBuf};

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Canonical representation of where a secret is stored.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretPath(String);

impl SecretPath {
    /// Construct a new secret path, rejecting absolute and parent-traversing inputs.
    pub fn new(path: impl Into<String>) -> Result<Self, StorageError> {
        let path_string = path.into();
        let path = Path::new(&path_string);

        if path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(StorageError::InvalidPath(path_string));
        }

        Ok(Self(path_string))
    }

    /// Borrow the underlying path string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Create a [`PathBuf`] relative to a base directory.
    pub fn to_path_buf(&self) -> PathBuf {
        Path::new(&self.0).to_path_buf()
    }
}

/// High-level abstraction for storing JSON secrets.
pub trait SecretsManager: Send + Sync {
    /// Store (or replace) JSON-serializable data at the given path.
    fn put_json<T: Serialize>(&self, path: &SecretPath, value: &T) -> Result<(), StorageError>;
    /// Retrieve JSON data at the given path, if present.
    fn get_json<T: DeserializeOwned>(&self, path: &SecretPath) -> Result<Option<T>, StorageError>;
    /// Remove JSON data at the given path.
    fn delete(&self, path: &SecretPath) -> Result<(), StorageError>;
}

/// Errors arising from storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("secrets path is invalid: {0}")]
    InvalidPath(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("operation unsupported: {0}")]
    Unsupported(&'static str),
}
