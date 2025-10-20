use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

use super::SecurityError;

type HmacSha256 = Hmac<Sha256>;

/// Shared CSRF state/nonce helper backed by an HMAC secret.
#[derive(Clone)]
pub struct CsrfKey {
    key: Vec<u8>,
}

impl fmt::Debug for CsrfKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CsrfKey").finish_non_exhaustive()
    }
}

impl CsrfKey {
    /// Create a new CSRF helper using the provided raw key bytes.
    pub fn new(key: &[u8]) -> Result<Self, SecurityError> {
        if key.len() < 32 {
            return Err(SecurityError::InvalidKey(
                "OAUTH_JWE_AES256_GCM_KEY_BASE64 (requires >= 32 bytes)",
            ));
        }
        Ok(Self { key: key.to_vec() })
    }

    /// Generate a signed state token that can be round-tripped.
    pub fn generate_state(&self) -> Result<String, SecurityError> {
        self.generate_random_token("state")
    }

    /// Verify a state token, returning the original value when valid.
    pub fn verify_state(&self, token: &str) -> Result<String, SecurityError> {
        self.verify_token("state", token)
    }

    /// Generate a signed nonce token.
    pub fn generate_nonce(&self) -> Result<String, SecurityError> {
        self.generate_random_token("nonce")
    }

    /// Verify a nonce token, returning the original value when valid.
    pub fn verify_nonce(&self, token: &str) -> Result<String, SecurityError> {
        self.verify_token("nonce", token)
    }

    /// Sign an arbitrary payload value and return a tamper-evident token.
    pub fn seal(&self, prefix: &str, payload: &str) -> Result<String, SecurityError> {
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signature = self.sign(prefix, &encoded)?;
        Ok(format!("{prefix}.{encoded}.{signature}"))
    }

    /// Verify a previously sealed payload and return the original value.
    pub fn open(&self, prefix: &str, token: &str) -> Result<String, SecurityError> {
        let encoded = self.verify_token(prefix, token)?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| {
            SecurityError::Encoding(format!("{prefix} payload is not valid base64"))
        })?;
        String::from_utf8(bytes)
            .map_err(|_| SecurityError::Encoding(format!("{prefix} payload is not valid utf-8")))
    }

    fn generate_random_token(&self, prefix: &str) -> Result<String, SecurityError> {
        let mut entropy = [0u8; 16];
        OsRng.fill_bytes(&mut entropy);
        let value = URL_SAFE_NO_PAD.encode(entropy);
        let signature = self.sign(prefix, &value)?;
        Ok(format!("{prefix}.{value}.{signature}"))
    }

    fn verify_token(&self, prefix: &str, token: &str) -> Result<String, SecurityError> {
        let mut segments = token.split('.');
        let seg_prefix = segments.next().ok_or_else(|| {
            SecurityError::Encoding(format!("{prefix} token missing prefix segment"))
        })?;
        let value = segments.next().ok_or_else(|| {
            SecurityError::Encoding(format!("{prefix} token missing value segment"))
        })?;
        let sig = segments.next().ok_or_else(|| {
            SecurityError::Encoding(format!("{prefix} token missing signature segment"))
        })?;

        if seg_prefix != prefix {
            return Err(SecurityError::Encoding(format!(
                "{prefix} token prefix mismatch"
            )));
        }

        if segments.next().is_some() {
            return Err(SecurityError::Encoding(format!(
                "{prefix} token contains extra segments"
            )));
        }

        let signature_bytes = URL_SAFE_NO_PAD.decode(sig.as_bytes()).map_err(|_| {
            SecurityError::Encoding(format!("{prefix} signature is not valid base64"))
        })?;

        let mut mac = HmacSha256::new_from_slice(&self.key)?;
        mac.update(prefix.as_bytes());
        mac.update(b".");
        mac.update(value.as_bytes());
        mac.verify_slice(&signature_bytes)
            .map_err(|_| SecurityError::Crypto(format!("{prefix} token signature mismatch")))?;

        Ok(value.to_string())
    }

    fn sign(&self, prefix: &str, value: &str) -> Result<String, SecurityError> {
        let mut mac = HmacSha256::new_from_slice(&self.key)?;
        mac.update(prefix.as_bytes());
        mac.update(b".");
        mac.update(value.as_bytes());
        let signature = mac.finalize().into_bytes();
        Ok(URL_SAFE_NO_PAD.encode(signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        vec![3u8; 32]
    }

    #[test]
    fn state_roundtrip() {
        let csrf = CsrfKey::new(&key()).expect("key");
        let token = csrf.generate_state().expect("generate");
        let original = csrf.verify_state(&token).expect("verify");
        assert!(!original.is_empty());
    }

    #[test]
    fn tampered_state_fails() {
        let csrf = CsrfKey::new(&key()).expect("key");
        let mut token = csrf.generate_state().expect("generate");
        token.push_str("xyz");
        let err = csrf.verify_state(&token).unwrap_err();
        assert!(matches!(
            err,
            SecurityError::Crypto(_) | SecurityError::Encoding(_)
        ));
    }

    #[test]
    fn nonce_roundtrip() {
        let csrf = CsrfKey::new(&key()).expect("key");
        let token = csrf.generate_nonce().expect("generate");
        let original = csrf.verify_nonce(&token).expect("verify");
        assert!(!original.is_empty());
    }

    #[test]
    fn seal_and_open_payload() {
        let csrf = CsrfKey::new(&key()).expect("key");
        let token = csrf.seal("state", "{\"foo\":1}").expect("seal");
        let payload = csrf.open("state", &token).expect("open");
        assert_eq!(payload, "{\"foo\":1}");
    }
}
