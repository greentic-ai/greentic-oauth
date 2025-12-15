pub mod csrf;
pub mod discovery;
pub mod jwe;
pub mod jws;
pub mod pkce;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use thiserror::Error;

use crate::storage::secrets_manager::{SecretPath, SecretsManager, StorageError};
pub use csrf::CsrfKey;
pub use discovery::{DiscoverySigner, JwsSignature};
pub use jwe::JweVault;
pub use jws::JwsService;

const SECRET_JWS_ED25519_B64: &str = "oauth/security/jws-ed25519-base64";
const SECRET_JWE_AES256_GCM_B64: &str = "oauth/security/jwe-aes256-gcm-base64";
const SECRET_HMAC_B64: &str = "oauth/security/hmac-base64";
const SECRET_HMAC_RAW: &str = "oauth/security/hmac-raw";
const SECRET_DISCOVERY_JWK: &str = "oauth/security/discovery-jwk";

/// Collection of security primitives required for the broker to operate.
#[allow(dead_code)]
pub struct SecurityConfig {
    pub jws: JwsService,
    pub jwe: JweVault,
    pub csrf: CsrfKey,
    pub discovery: Option<DiscoverySigner>,
}

impl SecurityConfig {
    /// Load all security primitives from the secrets store.
    pub fn from_store<S: SecretsManager>(secrets: &S) -> Result<Self, SecurityError> {
        let jws_secret =
            read_required_string(secrets, SECRET_JWS_ED25519_B64, "ed25519 signing key")?;
        let jws = JwsService::from_base64_secret(&jws_secret)?;

        let jwe_key_b64 =
            read_required_string(secrets, SECRET_JWE_AES256_GCM_B64, "aes256-gcm key")?;
        let jwe_key = BASE64_STANDARD
            .decode(jwe_key_b64.as_bytes())
            .map_err(|err| SecurityError::Encoding(err.to_string()))?;

        let jwe = JweVault::from_key_bytes(&jwe_key)?;
        let csrf_key_bytes = if let Some(b64) = read_optional_string(secrets, SECRET_HMAC_B64)? {
            BASE64_STANDARD
                .decode(b64.as_bytes())
                .map_err(|err| SecurityError::Encoding(err.to_string()))?
        } else if let Some(raw) = read_optional_string(secrets, SECRET_HMAC_RAW)? {
            raw.as_bytes().to_vec()
        } else {
            jwe_key.clone()
        };
        let csrf = CsrfKey::new(&csrf_key_bytes)?;

        let discovery = load_discovery_signer(secrets)?;

        Ok(Self {
            jws,
            jwe,
            csrf,
            discovery,
        })
    }
}

fn load_discovery_signer<S: SecretsManager>(
    secrets: &S,
) -> Result<Option<DiscoverySigner>, SecurityError> {
    if let Some(jwk) = read_optional_string(secrets, SECRET_DISCOVERY_JWK)? {
        if jwk.trim().is_empty() {
            return Ok(None);
        }
        return Ok(Some(DiscoverySigner::from_jwk_str(&jwk)?));
    }

    Ok(None)
}

/// Error surface for security helpers.
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("missing secret `{key}` at `{path}`")]
    MissingSecret { key: &'static str, path: String },
    #[error("secrets backend error: {0}")]
    SecretBackend(String),
    #[error("invalid key material for {0}")]
    InvalidKey(&'static str),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("cryptographic error: {0}")]
    Crypto(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<base64::DecodeError> for SecurityError {
    fn from(err: base64::DecodeError) -> Self {
        SecurityError::Encoding(err.to_string())
    }
}

impl From<aes_gcm::Error> for SecurityError {
    fn from(err: aes_gcm::Error) -> Self {
        SecurityError::Crypto(err.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for SecurityError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        SecurityError::Crypto(err.to_string())
    }
}

impl From<hmac::digest::InvalidLength> for SecurityError {
    fn from(_: hmac::digest::InvalidLength) -> Self {
        SecurityError::InvalidKey("HMAC key")
    }
}

fn read_required_string<S: SecretsManager>(
    secrets: &S,
    path: &str,
    key: &'static str,
) -> Result<String, SecurityError> {
    let value = read_optional_string(secrets, path)?;
    value.ok_or(SecurityError::MissingSecret {
        key,
        path: path.to_string(),
    })
}

fn read_optional_string<S: SecretsManager>(
    secrets: &S,
    path: &str,
) -> Result<Option<String>, SecurityError> {
    let path = SecretPath::new(path.to_string())
        .map_err(|err| SecurityError::SecretBackend(err.to_string()))?;
    match secrets.get_json::<String>(&path) {
        Ok(value) => Ok(value),
        Err(StorageError::NotFound(_)) => Ok(None),
        Err(err) => Err(SecurityError::from(err)),
    }
}

impl From<StorageError> for SecurityError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::NotFound(path) => SecurityError::MissingSecret {
                key: "unknown-secret",
                path,
            },
            StorageError::InvalidPath(reason) => SecurityError::SecretBackend(reason),
            StorageError::Io(err) => SecurityError::SecretBackend(err.to_string()),
            StorageError::Serialization(err) => SecurityError::SecretBackend(err.to_string()),
            StorageError::Encoding(err) => SecurityError::SecretBackend(err),
            StorageError::Unsupported(reason) => SecurityError::SecretBackend(reason.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{EnvSecretsManager, secrets_manager::SecretPath};
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use tempfile::tempdir;

    #[test]
    fn loads_security_config_from_store() {
        let dir = tempdir().expect("tempdir");
        let store = EnvSecretsManager::new(dir.path().to_path_buf()).expect("store");

        let jws_secret = BASE64_STANDARD.encode([7u8; 32]);
        store
            .put_json(
                &SecretPath::new(SECRET_JWS_ED25519_B64).unwrap(),
                &jws_secret,
            )
            .unwrap();
        let jwe_secret = BASE64_STANDARD.encode([9u8; 32]);
        store
            .put_json(
                &SecretPath::new(SECRET_JWE_AES256_GCM_B64).unwrap(),
                &jwe_secret,
            )
            .unwrap();
        store
            .put_json(
                &SecretPath::new(SECRET_HMAC_B64).unwrap(),
                &BASE64_STANDARD.encode([11u8; 32]),
            )
            .unwrap();

        let config = SecurityConfig::from_store(&store).expect("security config");

        let token = config.csrf.generate_state().expect("csrf token");
        assert!(!token.is_empty(), "csrf token should be generated");
        let _ = config.jws;
    }

    #[test]
    fn missing_security_secret_surfaces_error() {
        let dir = tempdir().expect("tempdir");
        let store = EnvSecretsManager::new(dir.path().to_path_buf()).expect("store");

        let err = SecurityConfig::from_store(&store);
        assert!(matches!(err, Err(SecurityError::MissingSecret { .. })));
    }
}
