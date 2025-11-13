use crate::storage::secrets_manager::{SecretPath, SecretsManager, StorageError};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::{Value, json};

pub trait SecretStore: Send + Sync {
    fn put_json_value(
        &self,
        path: &SecretPath,
        value: &serde_json::Value,
    ) -> Result<(), StorageError>;
    fn get_json_value(&self, path: &SecretPath) -> Result<Option<serde_json::Value>, StorageError>;
    fn delete_value(&self, path: &SecretPath) -> Result<(), StorageError>;
}

impl<T: SecretsManager> SecretStore for T {
    fn put_json_value(
        &self,
        path: &SecretPath,
        value: &serde_json::Value,
    ) -> Result<(), StorageError> {
        self.put_json(path, value)
    }

    fn get_json_value(&self, path: &SecretPath) -> Result<Option<serde_json::Value>, StorageError> {
        self.get_json(path)
    }

    fn delete_value(&self, path: &SecretPath) -> Result<(), StorageError> {
        self.delete(path)
    }
}

#[derive(Default)]
pub struct NoopSecretStore;

impl SecretStore for NoopSecretStore {
    fn put_json_value(
        &self,
        _path: &SecretPath,
        _value: &serde_json::Value,
    ) -> Result<(), StorageError> {
        Ok(())
    }

    fn get_json_value(
        &self,
        _path: &SecretPath,
    ) -> Result<Option<serde_json::Value>, StorageError> {
        Ok(None)
    }

    fn delete_value(&self, _path: &SecretPath) -> Result<(), StorageError> {
        Ok(())
    }
}

fn default_path(tenant: &str, provider: &str, key: &str) -> String {
    let normalized = key.replace('/', "_");
    format!("oauth/{tenant}/{provider}/{normalized}")
}

pub fn write_secret(
    secrets: &dyn SecretStore,
    tenant: &str,
    provider: &str,
    key: &str,
    value: &[u8],
) -> Result<(), StorageError> {
    let path = default_path(tenant, provider, key);
    write_secret_bytes_at(secrets, &path, value)
}

pub fn write_string_secret(
    secrets: &dyn SecretStore,
    tenant: &str,
    provider: &str,
    key: &str,
    value: &str,
) -> Result<(), StorageError> {
    let path = default_path(tenant, provider, key);
    write_string_secret_at(secrets, &path, value)
}

pub fn write_secret_bytes_at(
    secrets: &dyn SecretStore,
    path: &str,
    value: &[u8],
) -> Result<(), StorageError> {
    let path = SecretPath::new(path.to_string())?;
    let payload = json!({ "value": B64.encode(value) });
    secrets.put_json_value(&path, &payload)?;
    Ok(())
}

pub fn write_string_secret_at(
    secrets: &dyn SecretStore,
    path: &str,
    value: &str,
) -> Result<(), StorageError> {
    let path = SecretPath::new(path.to_string())?;
    let payload = json!({ "value": value });
    secrets.put_json_value(&path, &payload)?;
    Ok(())
}

pub fn delete_secret_at(secrets: &dyn SecretStore, path: &str) -> Result<(), StorageError> {
    let path = SecretPath::new(path.to_string())?;
    secrets.delete_value(&path)
}

pub fn messaging_global_path(provider: &str, key: &str) -> String {
    format!("messaging/global/{provider}/{key}")
}

pub fn messaging_tenant_path(tenant: &str, provider: &str, key: &str) -> String {
    format!("messaging/tenant/{tenant}/{provider}/{key}")
}

pub fn read_string_secret_at(
    secrets: &dyn SecretStore,
    path: &str,
) -> Result<Option<String>, StorageError> {
    let path = SecretPath::new(path.to_string())?;
    Ok(secrets.get_json_value(&path)?.and_then(|value| {
        value
            .get("value")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
    }))
}

pub fn read_string_secret(
    secrets: &dyn SecretStore,
    tenant: &str,
    provider: &str,
    key: &str,
) -> Result<Option<String>, StorageError> {
    let path = default_path(tenant, provider, key);
    read_string_secret_at(secrets, &path)
}
