use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::ProviderId;

/// Default lifetime applied to newly created state tokens.
pub const DEFAULT_STATE_TTL: Duration = Duration::from_secs(300);

/// Claims embedded into the secure state token.
#[cfg_attr(feature = "schemas", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateClaims {
    pub tenant: String,
    pub team: Option<String>,
    pub provider: String,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    pub iat: u64,
    pub exp: u64,
}

impl StateClaims {
    /// Construct claims with the provided context and TTL.
    pub fn new(
        tenant: impl Into<String>,
        team: Option<String>,
        provider: &ProviderId,
        nonce: impl Into<String>,
        redirect_to: Option<String>,
        ttl: Duration,
    ) -> Self {
        let issued_at = current_epoch();
        let expires_at = issued_at.saturating_add(ttl.as_secs());
        Self {
            tenant: tenant.into(),
            team,
            provider: provider.as_str().to_owned(),
            nonce: nonce.into(),
            redirect_to,
            iat: issued_at,
            exp: expires_at,
        }
    }
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("state token error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

/// Sign the provided claims using HS256.
pub fn sign_state(claims: &StateClaims, secret: &[u8]) -> Result<String, StateError> {
    let header = Header::new(Algorithm::HS256);
    encode(&header, claims, &EncodingKey::from_secret(secret)).map_err(StateError::from)
}

/// Verify the state token and return the embedded claims.
pub fn verify_state(token: &str, secret: &[u8]) -> Result<StateClaims, StateError> {
    let validation = Validation::new(Algorithm::HS256);
    decode::<StateClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|data| data.claims)
        .map_err(StateError::from)
}

fn current_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProviderId;

    #[test]
    fn sign_and_verify_roundtrip() {
        let claims = StateClaims::new(
            "acme",
            Some("platform".into()),
            &ProviderId::Google,
            "nonce-123",
            Some("https://app.example.com/callback".into()),
            DEFAULT_STATE_TTL,
        );
        let secret = b"super-secret-key";
        let token = sign_state(&claims, secret).expect("sign");
        let decoded = verify_state(&token, secret).expect("verify");
        assert_eq!(claims.tenant, decoded.tenant);
        assert_eq!(claims.team, decoded.team);
        assert_eq!(claims.provider, decoded.provider);
        assert_eq!(claims.nonce, decoded.nonce);
        assert_eq!(claims.redirect_to, decoded.redirect_to);
    }

    #[test]
    fn rejects_tampered_token() {
        let claims = StateClaims::new(
            "acme",
            None,
            &ProviderId::Google,
            "nonce",
            None,
            DEFAULT_STATE_TTL,
        );
        let secret = b"secret";
        let mut token = sign_state(&claims, secret).expect("sign");
        token.push('a');
        assert!(verify_state(&token, secret).is_err());
    }
}
