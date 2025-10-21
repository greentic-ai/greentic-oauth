pub mod csrf;
pub mod discovery;
pub mod jwe;
pub mod jws;
pub mod pkce;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use std::fs;
use thiserror::Error;

pub use csrf::CsrfKey;
pub use discovery::{DiscoverySigner, JwsSignature};
pub use jwe::JweVault;
pub use jws::JwsService;

/// Collection of security primitives required for the broker to operate.
#[allow(dead_code)]
pub struct SecurityConfig {
    pub jws: JwsService,
    pub jwe: JweVault,
    pub csrf: CsrfKey,
    pub discovery: Option<DiscoverySigner>,
}

impl SecurityConfig {
    /// Load all security primitives from the expected environment variables.
    pub fn from_env() -> Result<Self, SecurityError> {
        let jws_secret = std::env::var("OAUTH_JWS_ED25519_SECRET_BASE64")
            .map_err(|_| SecurityError::MissingEnv("OAUTH_JWS_ED25519_SECRET_BASE64"))?;
        let jws = JwsService::from_base64_secret(&jws_secret)?;

        let jwe_key_b64 = std::env::var("OAUTH_JWE_AES256_GCM_KEY_BASE64")
            .map_err(|_| SecurityError::MissingEnv("OAUTH_JWE_AES256_GCM_KEY_BASE64"))?;
        let jwe_key = BASE64_STANDARD
            .decode(jwe_key_b64.as_bytes())
            .map_err(|err| SecurityError::Encoding(err.to_string()))?;

        let jwe = JweVault::from_key_bytes(&jwe_key)?;
        let csrf = CsrfKey::new(&jwe_key)?;

        let discovery = load_discovery_signer()?;

        Ok(Self {
            jws,
            jwe,
            csrf,
            discovery,
        })
    }
}

fn load_discovery_signer() -> Result<Option<DiscoverySigner>, SecurityError> {
    if let Ok(inline) = std::env::var("OAUTH_DISCOVERY_JWK") {
        if inline.trim().is_empty() {
            return Ok(None);
        }
        let signer = DiscoverySigner::from_jwk_str(&inline)?;
        return Ok(Some(signer));
    }

    if let Ok(path) = std::env::var("OAUTH_DISCOVERY_JWK_FILE") {
        let contents = fs::read_to_string(path)?;
        if contents.trim().is_empty() {
            return Ok(None);
        }
        let signer = DiscoverySigner::from_jwk_str(&contents)?;
        return Ok(Some(signer));
    }

    Ok(None)
}

/// Error surface for security helpers.
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("missing environment variable {0}")]
    MissingEnv(&'static str),
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
