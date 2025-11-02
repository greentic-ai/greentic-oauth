#![allow(
    deprecated,
    reason = "aes-gcm currently re-exports generic-array 0.x constructors"
)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::TryRngCore;

use aes_gcm::aead::generic_array::{typenum::U12, typenum::U16, GenericArray};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use greentic_oauth_core::TokenSet;

use super::SecurityError;

const PROTECTED_HEADER_B64: &str = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoiSldUIn0";

/// AES-256-GCM backed JWE helper for token sets.
pub struct JweVault {
    cipher: Aes256Gcm,
}

impl JweVault {
    /// Construct a vault from raw AES-256 key material.
    pub fn from_key_bytes(key: &[u8]) -> Result<Self, SecurityError> {
        if key.len() != 32 {
            return Err(SecurityError::InvalidKey(
                "OAUTH_JWE_AES256_GCM_KEY_BASE64 (requires 32 bytes)",
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| {
            SecurityError::InvalidKey("OAUTH_JWE_AES256_GCM_KEY_BASE64 (requires 32 bytes)")
        })?;
        Ok(Self { cipher })
    }

    /// Encrypt a token set into a compact JWE representation.
    pub fn encrypt(&self, token_set: &TokenSet) -> Result<String, SecurityError> {
        let mut nonce_bytes = [0u8; 12];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut nonce_bytes)
            .expect("os entropy source unavailable");
        let nonce: GenericArray<u8, U12> = GenericArray::clone_from_slice(&nonce_bytes);

        let mut buffer = serde_json::to_vec(token_set)?;
        let tag = self.cipher.encrypt_in_place_detached(
            &nonce,
            PROTECTED_HEADER_B64.as_bytes(),
            &mut buffer,
        )?;

        let iv_b64 = URL_SAFE_NO_PAD.encode(nonce_bytes);
        let ciphertext_b64 = URL_SAFE_NO_PAD.encode(&buffer);
        let tag_b64 = URL_SAFE_NO_PAD.encode(tag);

        Ok(format!(
            "{PROTECTED_HEADER_B64}..{iv_b64}.{ciphertext_b64}.{tag_b64}"
        ))
    }

    /// Decrypt a compact JWE representation back into the token set.
    pub fn decrypt(&self, token: &str) -> Result<TokenSet, SecurityError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 5 {
            return Err(SecurityError::Encoding(
                "JWE must contain five segments".to_string(),
            ));
        }

        let header = parts[0];
        let encrypted_key = parts[1];
        let iv = parts[2];
        let ciphertext = parts[3];
        let tag = parts[4];

        if header != PROTECTED_HEADER_B64 {
            return Err(SecurityError::Encoding(
                "JWE header does not match expected dir/A256GCM header".to_string(),
            ));
        }

        if !encrypted_key.is_empty() {
            return Err(SecurityError::Encoding(
                "JWE encrypted key segment must be empty for dir algorithm".to_string(),
            ));
        }

        let mut iv_bytes = [0u8; 12];
        let decoded_iv = URL_SAFE_NO_PAD.decode(iv.as_bytes())?;
        if decoded_iv.len() != iv_bytes.len() {
            return Err(SecurityError::Encoding(
                "JWE IV must be 12 bytes".to_string(),
            ));
        }
        iv_bytes.copy_from_slice(&decoded_iv);
        let nonce: GenericArray<u8, U12> = GenericArray::clone_from_slice(&iv_bytes);

        let mut ciphertext_bytes = URL_SAFE_NO_PAD.decode(ciphertext.as_bytes())?;
        let tag_bytes = URL_SAFE_NO_PAD.decode(tag.as_bytes())?;
        if tag_bytes.len() != 16 {
            return Err(SecurityError::Encoding(
                "JWE authentication tag must be 16 bytes".to_string(),
            ));
        }
        let tag: GenericArray<u8, U16> = GenericArray::clone_from_slice(&tag_bytes);

        self.cipher.decrypt_in_place_detached(
            &nonce,
            PROTECTED_HEADER_B64.as_bytes(),
            &mut ciphertext_bytes,
            &tag,
        )?;

        let tokens: TokenSet = serde_json::from_slice(&ciphertext_bytes)?;
        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        vec![4u8; 32]
    }

    fn token_set() -> TokenSet {
        TokenSet {
            access_token: "access".into(),
            expires_in: Some(3600),
            refresh_token: Some("refresh".into()),
            token_type: Some("Bearer".into()),
            scopes: vec!["read".into()],
        }
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let vault = JweVault::from_key_bytes(&key()).expect("vault");
        let token = vault.encrypt(&token_set()).expect("encrypt");
        let parsed = vault.decrypt(&token).expect("decrypt");
        assert_eq!(token_set(), parsed);
    }

    #[test]
    fn tampered_tag_rejected() {
        let vault = JweVault::from_key_bytes(&key()).expect("vault");
        let mut token = vault.encrypt(&token_set()).expect("encrypt");
        token.push('x');
        let err = vault.decrypt(&token).unwrap_err();
        assert!(matches!(
            err,
            SecurityError::Encoding(_) | SecurityError::Crypto(_)
        ));
    }
}
