use std::{
    collections::HashMap,
    sync::OnceLock,
    time::{Duration, Instant},
};

use chrono::{TimeZone, Utc};
use greentic_oauth_core::{OAuthError, ValidatedClaims};
use greentic_types::{EnvId, TeamId, TenantCtx, TenantId, UserId};
use jsonwebtoken::{
    DecodingKey, Validation, decode, decode_header,
    errors::ErrorKind as JwtErrorKind,
    jwk::{Jwk, JwkSet},
};
use reqwest::Url;
use serde::Deserialize;

/// Configuration for bearer token validation.
#[derive(Clone, Debug)]
pub struct TokenValidationConfig {
    pub jwks_url: Url,
    pub issuer: String,
    pub audience: String,
    pub required_scopes: Vec<String>,
    pub cache_ttl: Duration,
    pub env: Option<String>,
}

impl TokenValidationConfig {
    pub fn new(jwks_url: Url, issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            jwks_url,
            issuer: issuer.into(),
            audience: audience.into(),
            required_scopes: Vec::new(),
            cache_ttl: Duration::from_secs(300),
            env: None,
        }
    }

    pub fn with_required_scopes(mut self, scopes: Vec<String>) -> Self {
        self.required_scopes = scopes;
        self
    }

    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    pub fn with_env(mut self, env: impl Into<String>) -> Self {
        self.env = Some(env.into());
        self
    }
}

/// Validate a bearer token using JWKS-backed signature verification and basic claim checks.
pub async fn validate_bearer_token(
    token: &str,
    cfg: &TokenValidationConfig,
) -> Result<(ValidatedClaims, TenantCtx), OAuthError> {
    let header = decode_header(token).map_err(map_jwt_error)?;
    let jwks = load_jwks(cfg).await?;
    let jwk = select_jwk(&jwks, header.kid.as_deref())?;
    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|err| OAuthError::Other(format!("failed to build decoding key: {err}")))?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(std::slice::from_ref(&cfg.audience));
    validation.set_issuer(std::slice::from_ref(&cfg.issuer));
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);

    let token_data =
        decode::<RawClaims>(token, &decoding_key, &validation).map_err(map_jwt_error)?;
    let claims = token_data.claims;

    let tenant_id = claims
        .tenant_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| OAuthError::MissingClaim("tenant_id".into()))?;
    let user_id = claims
        .user_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| OAuthError::MissingClaim("user_id".into()))?;

    let issuer = claims.iss.clone().unwrap_or_else(|| cfg.issuer.clone());
    let audience = claims
        .aud
        .first()
        .cloned()
        .or_else(|| Some(cfg.audience.clone()))
        .ok_or_else(|| OAuthError::MissingClaim("aud".into()))?;

    let env = claims
        .env
        .clone()
        .or_else(|| cfg.env.clone())
        .ok_or_else(|| OAuthError::MissingClaim("env".into()))?;

    let expires_at = claims
        .exp
        .and_then(|ts| Utc.timestamp_opt(ts as i64, 0).single());
    let scopes = extract_scopes(&claims);

    if !cfg.required_scopes.is_empty() && !cfg.required_scopes.iter().all(|s| scopes.contains(s)) {
        return Err(OAuthError::InvalidScope);
    }

    let tenant_ctx = build_tenant_ctx(
        env,
        tenant_id.clone(),
        claims.team_id.clone(),
        user_id.clone(),
    )?;

    let validated = ValidatedClaims {
        tenant_id,
        user_id,
        team_id: claims.team_id,
        scopes,
        issuer,
        audience,
        expires_at,
        subject: claims.sub,
    };

    Ok((validated, tenant_ctx))
}

fn build_tenant_ctx(
    env: String,
    tenant: String,
    team: Option<String>,
    user: String,
) -> Result<TenantCtx, OAuthError> {
    let env_id = EnvId::try_from(env.as_str())
        .map_err(|err| OAuthError::Other(format!("invalid env id: {err}")))?;
    let tenant_id = TenantId::try_from(tenant.as_str())
        .map_err(|err| OAuthError::Other(format!("invalid tenant id: {err}")))?;
    let mut ctx = TenantCtx::new(env_id, tenant_id);

    if let Some(team) = team {
        let team_id = TeamId::try_from(team.as_str())
            .map_err(|err| OAuthError::Other(format!("invalid team id: {err}")))?;
        ctx = ctx.with_team(Some(team_id));
    }

    let user_id = UserId::try_from(user.as_str())
        .map_err(|err| OAuthError::Other(format!("invalid user id: {err}")))?;

    Ok(ctx.with_user(Some(user_id)))
}

fn extract_scopes(claims: &RawClaims) -> Vec<String> {
    let mut scopes: Vec<String> = claims.scopes.clone().unwrap_or_default();
    if let Some(scope_str) = claims.scope.as_deref() {
        for scope in scope_str.split_whitespace() {
            if !scope.is_empty() && !scopes.contains(&scope.to_string()) {
                scopes.push(scope.to_string());
            }
        }
    }
    scopes
}

fn select_jwk<'a>(jwks: &'a JwkSet, kid: Option<&str>) -> Result<&'a Jwk, OAuthError> {
    if let Some(kid) = kid
        && let Some(key) = jwks.find(kid)
    {
        return Ok(key);
    }
    jwks.keys
        .first()
        .ok_or_else(|| OAuthError::Other("jwks set is empty".into()))
}

fn map_jwt_error(err: jsonwebtoken::errors::Error) -> OAuthError {
    match err.kind() {
        JwtErrorKind::ExpiredSignature => OAuthError::ExpiredToken,
        JwtErrorKind::InvalidAudience => OAuthError::InvalidAudience,
        JwtErrorKind::InvalidIssuer => OAuthError::InvalidIssuer,
        JwtErrorKind::InvalidSignature => OAuthError::InvalidSignature,
        JwtErrorKind::MissingRequiredClaim(claim) => OAuthError::MissingClaim(claim.to_string()),
        JwtErrorKind::InvalidAlgorithm => OAuthError::Other("invalid algorithm".into()),
        JwtErrorKind::InvalidToken => OAuthError::Unauthorized,
        other => OAuthError::Other(format!("{other:?}")),
    }
}

async fn load_jwks(cfg: &TokenValidationConfig) -> Result<JwkSet, OAuthError> {
    let cache_key = CacheKey::new(cfg);
    if let Some(cached) = try_cached(&cache_key) {
        return Ok(cached);
    }

    let resp = reqwest::get(cfg.jwks_url.clone())
        .await
        .map_err(|err| OAuthError::Transport(err.to_string()))?;

    if !resp.status().is_success() {
        return Err(OAuthError::Transport(format!(
            "jwks fetch failed with status {}",
            resp.status()
        )));
    }

    let jwks: JwkSet = resp
        .json()
        .await
        .map_err(|err| OAuthError::Other(format!("invalid jwks response: {err}")))?;

    update_cache(cache_key, jwks.clone(), cfg.cache_ttl);
    Ok(jwks)
}

fn try_cached(cache_key: &CacheKey) -> Option<JwkSet> {
    JWKS_CACHE
        .get_or_init(Default::default)
        .lock()
        .ok()
        .and_then(|mut map| {
            let expired = {
                map.get(cache_key).and_then(|entry| {
                    if entry.expires_at > Instant::now() {
                        Some(entry.jwks.clone())
                    } else {
                        None
                    }
                })
            };

            if expired.is_none() {
                map.remove(cache_key);
            }

            expired
        })
}

fn update_cache(cache_key: CacheKey, jwks: JwkSet, ttl: Duration) {
    if let Ok(mut map) = JWKS_CACHE.get_or_init(Default::default).lock() {
        map.insert(
            cache_key,
            CachedJwks {
                jwks,
                expires_at: Instant::now() + ttl,
            },
        );
    }
}

static JWKS_CACHE: OnceLock<std::sync::Mutex<HashMap<CacheKey, CachedJwks>>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct CacheKey {
    issuer: String,
    jwks: String,
}

impl CacheKey {
    fn new(cfg: &TokenValidationConfig) -> Self {
        Self {
            issuer: cfg.issuer.clone(),
            jwks: cfg.jwks_url.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct CachedJwks {
    jwks: JwkSet,
    expires_at: Instant,
}

#[derive(Debug, Deserialize)]
struct RawClaims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default, deserialize_with = "deserialize_audience")]
    aud: Vec<String>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    env: Option<String>,
}

fn deserialize_audience<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Aud {
        Single(String),
        Many(Vec<String>),
    }

    match Aud::deserialize(deserializer)? {
        Aud::Single(aud) => Ok(vec![aud]),
        Aud::Many(list) => Ok(list),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use std::time::Duration;

    fn sample_jwks(secret: &str, kid: &str) -> serde_json::Value {
        serde_json::json!({
            "keys": [
                {
                    "kty": "oct",
                    "alg": "HS256",
                    "kid": kid,
                    "k": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret.as_bytes())
                }
            ]
        })
    }

    fn build_token(secret: &str, kid: &str, exp: u64) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_string());
        let claims = serde_json::json!({
            "iss": "https://issuer.example.com",
            "aud": "api://aud",
            "exp": exp,
            "tenant_id": "tenant-123",
            "user_id": "user-456",
            "team_id": "team-1",
            "scope": "read write",
            "env": "dev"
        });
        jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("sign token")
    }

    fn cached_config(
        jwks_url: &str,
        issuer: &str,
        audience: &str,
        kid: &str,
        secret: &str,
        ttl: Duration,
    ) -> TokenValidationConfig {
        let cfg = TokenValidationConfig::new(
            jwks_url.parse().unwrap(),
            issuer.to_string(),
            audience.to_string(),
        )
        .with_cache_ttl(ttl);
        let jwks: JwkSet = serde_json::from_value(sample_jwks(secret, kid)).unwrap();
        update_cache(CacheKey::new(&cfg), jwks, ttl);
        cfg
    }

    #[tokio::test]
    async fn validates_and_builds_context() {
        let secret = "super-secret-key";
        let kid = "kid1";
        let now = Utc::now().timestamp() as u64 + 600;

        let token = build_token(secret, kid, now);
        let cfg = cached_config(
            "https://issuer.example.com/jwks1",
            "https://issuer.example.com",
            "api://aud",
            kid,
            secret,
            Duration::from_secs(300),
        );

        let (claims, ctx) = validate_bearer_token(&token, &cfg)
            .await
            .expect("validated");

        assert_eq!(claims.tenant_id, "tenant-123");
        assert_eq!(claims.user_id, "user-456");
        assert_eq!(claims.team_id.as_deref(), Some("team-1"));
        assert!(claims.scopes.contains(&"read".to_string()));
        assert_eq!(ctx.env.as_str(), "dev");
        assert_eq!(ctx.tenant.as_str(), "tenant-123");
        assert_eq!(ctx.user.as_ref().map(|u| u.as_str()), Some("user-456"));
    }

    #[tokio::test]
    async fn rejects_missing_scope() {
        let secret = "super-secret-key";
        let kid = "kid2";
        let now = Utc::now().timestamp() as u64 + 600;

        let token = build_token(secret, kid, now);
        let cfg = cached_config(
            "https://issuer.example.com/jwks2",
            "https://issuer.example.com",
            "api://aud",
            kid,
            secret,
            Duration::from_secs(300),
        )
        .with_required_scopes(vec!["admin".into()]);

        let err = validate_bearer_token(&token, &cfg)
            .await
            .expect_err("missing scope");
        assert!(matches!(err, OAuthError::InvalidScope));
    }

    #[tokio::test]
    async fn caches_jwks_between_calls() {
        let secret = "super-secret-key";
        let kid = "kid3";
        let now = Utc::now().timestamp() as u64 + 600;

        let token = build_token(secret, kid, now);
        let cfg = cached_config(
            "https://issuer.example.com/jwks3",
            "https://issuer.example.com",
            "api://aud",
            kid,
            secret,
            Duration::from_secs(60),
        );

        let _ = validate_bearer_token(&token, &cfg)
            .await
            .expect("first call");

        let _ = validate_bearer_token(&token, &cfg).await.expect("cached");
    }
}
