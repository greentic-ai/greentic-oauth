use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use oauth_core::TokenHandleClaims;
use std::convert::TryInto;

use super::SecurityError;

const PROTECTED_HEADER_B64: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";

/// JWS helpers for signing and verifying token handle claims.
pub struct JwsService {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl JwsService {
    /// Create a signer/verifier pair from a base64 encoded Ed25519 secret key.
    pub fn from_base64_secret(secret_b64: &str) -> Result<Self, SecurityError> {
        let bytes = BASE64_STANDARD.decode(secret_b64.as_bytes())?;
        if bytes.len() != 32 && bytes.len() != 64 {
            return Err(SecurityError::InvalidKey(
                "OAUTH_JWS_ED25519_SECRET_BASE64 (expected 32 or 64 bytes)",
            ));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes[..32]);
        let signing = SigningKey::from_bytes(&secret);
        let verifying = signing.verifying_key();
        Ok(Self { signing, verifying })
    }

    /// Produce a compact JWS string for the provided claims.
    pub fn sign(&self, claims: &TokenHandleClaims) -> Result<String, SecurityError> {
        let payload = serde_json::to_vec(claims)?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        let signing_input = format!("{PROTECTED_HEADER_B64}.{payload_b64}");
        let signature = self.signing.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        Ok(format!("{signing_input}.{signature_b64}"))
    }

    /// Parse and verify a JWS string, yielding the embedded claims.
    pub fn verify(&self, token: &str) -> Result<TokenHandleClaims, SecurityError> {
        let mut segments = token.split('.');
        let header = segments
            .next()
            .ok_or_else(|| SecurityError::Encoding("JWS missing header segment".to_string()))?;
        let payload = segments
            .next()
            .ok_or_else(|| SecurityError::Encoding("JWS missing payload segment".to_string()))?;
        let signature = segments
            .next()
            .ok_or_else(|| SecurityError::Encoding("JWS missing signature segment".to_string()))?;

        if segments.next().is_some() {
            return Err(SecurityError::Encoding(
                "JWS contained unexpected trailing segments".to_string(),
            ));
        }

        if header != PROTECTED_HEADER_B64 {
            return Err(SecurityError::Encoding(
                "JWS header does not match expected EdDSA header".to_string(),
            ));
        }

        let signing_input = format!("{header}.{payload}");
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload.as_bytes())?;
        let claims: TokenHandleClaims = serde_json::from_slice(&payload_bytes)?;

        let signature_bytes = URL_SAFE_NO_PAD.decode(signature.as_bytes())?;
        let signature_array: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SecurityError::Encoding("JWS signature must be 64 bytes".to_string()))?;
        let signature = Signature::from_bytes(&signature_array);

        self.verifying
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|err| SecurityError::Crypto(err.to_string()))?;

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oauth_core::{OwnerKind, TenantCtx};

    fn sample_signer() -> JwsService {
        let secret = BASE64_STANDARD.encode([1u8; 32]).to_string();
        JwsService::from_base64_secret(&secret).expect("signer")
    }

    fn claims() -> TokenHandleClaims {
        TokenHandleClaims {
            provider: "example".into(),
            subject: "user:42".into(),
            owner: OwnerKind::User {
                subject: "user:42".into(),
            },
            tenant: TenantCtx {
                env: "prod".into(),
                tenant: "acme".into(),
                team: Some("devs".into()),
            },
            scopes: vec!["read".into(), "write".into()],
            issued_at: 1_700_000_000,
            expires_at: 1_700_003_600,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let jws = sample_signer();
        let token = jws.sign(&claims()).expect("sign");
        let parsed = jws.verify(&token).expect("verify");
        assert_eq!(claims(), parsed);
    }

    #[test]
    fn invalid_header_rejected() {
        let jws = sample_signer();
        let mut token = jws.sign(&claims()).expect("sign");
        token.replace_range(0..1, "X");
        let err = jws.verify(&token).unwrap_err();
        assert!(matches!(err, SecurityError::Encoding(_)));
    }
}
