use serde::{de::DeserializeOwned, Serialize};

use super::secrets_manager::{SecretPath, SecretsManager, StorageError};

/// Placeholder Google Cloud KMS secrets manager (to be implemented).
pub struct GcpKmsSecretsManager;

impl GcpKmsSecretsManager {
    pub fn new() -> Self {
        Self
    }
}

impl SecretsManager for GcpKmsSecretsManager {
    fn put_json<T: Serialize>(&self, _: &SecretPath, _: &T) -> Result<(), StorageError> {
        Err(StorageError::Unsupported(
            "gcp_kms feature not yet implemented",
        ))
    }

    fn get_json<T: DeserializeOwned>(&self, _: &SecretPath) -> Result<Option<T>, StorageError> {
        Err(StorageError::Unsupported(
            "gcp_kms feature not yet implemented",
        ))
    }

    fn delete(&self, _: &SecretPath) -> Result<(), StorageError> {
        Err(StorageError::Unsupported(
            "gcp_kms feature not yet implemented",
        ))
    }
}
