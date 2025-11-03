use serde::{Serialize, de::DeserializeOwned};

use super::secrets_manager::{SecretPath, SecretsManager, StorageError};

/// Placeholder AWS KMS secrets manager (to be implemented).
pub struct AwsKmsSecretsManager;

impl AwsKmsSecretsManager {
    pub fn new() -> Self {
        Self
    }
}

impl SecretsManager for AwsKmsSecretsManager {
    fn put_json<T: Serialize>(&self, _: &SecretPath, _: &T) -> Result<(), StorageError> {
        Err(StorageError::Unsupported(
            "aws_kms feature not yet implemented",
        ))
    }

    fn get_json<T: DeserializeOwned>(&self, _: &SecretPath) -> Result<Option<T>, StorageError> {
        Err(StorageError::Unsupported(
            "aws_kms feature not yet implemented",
        ))
    }

    fn delete(&self, _: &SecretPath) -> Result<(), StorageError> {
        Err(StorageError::Unsupported(
            "aws_kms feature not yet implemented",
        ))
    }
}
