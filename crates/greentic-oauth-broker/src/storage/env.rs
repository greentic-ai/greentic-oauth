use std::{collections::HashMap, fs, path::PathBuf, sync::RwLock};

use serde::{Serialize, de::DeserializeOwned};

use super::secrets_manager::{SecretPath, SecretsManager, StorageError};

/// Development-oriented secrets manager backed by the filesystem with an in-memory cache.
pub struct EnvSecretsManager {
    base_dir: PathBuf,
    cache: RwLock<HashMap<String, Vec<u8>>>,
}

impl EnvSecretsManager {
    /// Create a new secrets manager rooted at the provided directory.
    pub fn new(base_dir: PathBuf) -> Result<Self, StorageError> {
        fs::create_dir_all(&base_dir)?;
        Ok(Self {
            base_dir,
            cache: RwLock::new(HashMap::new()),
        })
    }

    fn path_for(&self, path: &SecretPath) -> PathBuf {
        let clean = path.to_path_buf();
        self.base_dir.join(clean)
    }
}

impl SecretsManager for EnvSecretsManager {
    fn put_json<T: Serialize>(&self, path: &SecretPath, value: &T) -> Result<(), StorageError> {
        let payload = serde_json::to_vec_pretty(value)?;
        {
            let mut cache = self.cache.write().expect("cache write lock poisoned");
            cache.insert(path.as_str().to_string(), payload.clone());
        }

        let fs_path = self.path_for(path);
        if let Some(parent) = fs_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(fs_path, payload)?;
        Ok(())
    }

    fn get_json<T: DeserializeOwned>(&self, path: &SecretPath) -> Result<Option<T>, StorageError> {
        if let Some(bytes) = self
            .cache
            .read()
            .expect("cache read lock poisoned")
            .get(path.as_str())
            .cloned()
        {
            return Ok(Some(serde_json::from_slice(&bytes)?));
        }

        let fs_path = self.path_for(path);
        match fs::read(fs_path) {
            Ok(bytes) => {
                let value = serde_json::from_slice(&bytes)?;
                self.cache
                    .write()
                    .expect("cache write lock poisoned")
                    .insert(path.as_str().to_string(), bytes);
                Ok(Some(value))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(StorageError::from(err)),
        }
    }

    fn delete(&self, path: &SecretPath) -> Result<(), StorageError> {
        self.cache
            .write()
            .expect("cache write lock poisoned")
            .remove(path.as_str());

        let fs_path = self.path_for(path);
        match fs::remove_file(fs_path) {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(StorageError::from(err)),
        }
    }
}
