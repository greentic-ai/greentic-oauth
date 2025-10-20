use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use oauth_core::{provider::Provider, TokenHandleClaims, TokenSet};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, Method, Response,
};
use serde::{Deserialize, Serialize};

use crate::{
    http::{error::AppError, SharedContext},
    storage::{
        index::ConnectionKey,
        secrets_manager::{SecretPath, SecretsManager},
    },
};

const REFRESH_WINDOW_SECS: u64 = 300;
const DEFAULT_TTL_SECS: u64 = 3600;

/// Envelope persisted in secret storage containing encrypted token data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub ciphertext: String,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl StoredToken {
    pub fn new(ciphertext: String, expires_at: Option<u64>) -> Self {
        Self {
            ciphertext,
            expires_at,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct SignedFetchOptions {
    pub token_handle: String,
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SignedFetchOutcome {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

pub async fn resolve_access_token<S>(
    ctx: &SharedContext<S>,
    token_handle: &str,
    force_refresh: bool,
) -> Result<AccessTokenResponse, AppError>
where
    S: SecretsManager + 'static,
{
    let claims = ctx.security.jws.verify(token_handle)?;
    let provider = ctx.providers.get(&claims.provider).ok_or_else(|| {
        AppError::not_found(format!("provider `{}` not registered", claims.provider))
    })?;

    let key = ConnectionKey::from_owner(
        claims.tenant.env.clone(),
        claims.tenant.tenant.clone(),
        claims.tenant.team.clone(),
        &claims.owner,
        claims.subject.clone(),
    );
    let connection = ctx
        .index
        .get(&claims.provider, &key)
        .ok_or_else(|| AppError::not_found("connection not found"))?;

    let secret_path = SecretPath::new(connection.path)?;
    let mut stored = ctx
        .secrets
        .get_json::<StoredToken>(&secret_path)?
        .ok_or_else(|| AppError::not_found("token payload missing"))?;
    let mut token_set = ctx.security.jwe.decrypt(&stored.ciphertext)?;

    let now = now_epoch_seconds();
    let mut expires_at = stored
        .expires_at
        .or(Some(claims.expires_at))
        .unwrap_or(claims.expires_at);

    let needs_refresh = force_refresh || expires_at.saturating_sub(now) <= REFRESH_WINDOW_SECS;

    if needs_refresh {
        if let Some(refresh_token) = token_set.refresh_token.clone() {
            let mut refreshed = refresh_provider_token(provider.as_ref(), &claims, &refresh_token)?;
            if refreshed.refresh_token.is_none() {
                refreshed.refresh_token = Some(refresh_token);
            }
            expires_at = refreshed
                .expires_in
                .map(|ttl| now.saturating_add(ttl))
                .unwrap_or_else(|| now.saturating_add(DEFAULT_TTL_SECS));
            token_set = refreshed;
            let ciphertext = ctx.security.jwe.encrypt(&token_set)?;
            stored.ciphertext = ciphertext;
            stored.expires_at = Some(expires_at);
            ctx.secrets.put_json(&secret_path, &stored)?;
        } else if stored.expires_at.is_none() {
            stored.expires_at = Some(expires_at);
            ctx.secrets.put_json(&secret_path, &stored)?;
        }
    } else if stored.expires_at.is_none() {
        stored.expires_at = Some(expires_at);
        ctx.secrets.put_json(&secret_path, &stored)?;
    }

    Ok(AccessTokenResponse {
        access_token: token_set.access_token,
        expires_at,
    })
}

fn refresh_provider_token(
    provider: &dyn Provider,
    claims: &TokenHandleClaims,
    refresh_token: &str,
) -> Result<TokenSet, AppError> {
    provider
        .refresh(claims, refresh_token)
        .map_err(AppError::from)
}

pub async fn perform_signed_fetch<S>(
    ctx: &SharedContext<S>,
    opts: SignedFetchOptions,
) -> Result<SignedFetchOutcome, AppError>
where
    S: SecretsManager + 'static,
{
    let client = Client::new();
    let mut token = resolve_access_token(ctx, &opts.token_handle, false).await?;
    let mut response = dispatch_request(&client, &opts, &token.access_token).await?;

    if response.status().as_u16() == 401 {
        token = resolve_access_token(ctx, &opts.token_handle, true).await?;
        response = dispatch_request(&client, &opts, &token.access_token).await?;
    }

    let status = response.status().as_u16();
    let headers = flatten_headers(response.headers());
    let body = response
        .bytes()
        .await
        .map_err(|err| AppError::internal(err.to_string()))?;

    Ok(SignedFetchOutcome {
        status,
        headers,
        body: body.to_vec(),
    })
}

async fn dispatch_request(
    client: &Client,
    opts: &SignedFetchOptions,
    access_token: &str,
) -> Result<Response, AppError> {
    let mut request = client
        .request(opts.method.clone(), &opts.url)
        .bearer_auth(access_token);

    for (name, value) in &opts.headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| AppError::bad_request(format!("invalid header name `{name}`")))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| AppError::bad_request(format!("invalid header value for `{name}`")))?;
        request = request.header(header_name, header_value);
    }

    if let Some(body) = &opts.body {
        request = request.body(body.clone());
    }

    request
        .send()
        .await
        .map_err(|err| AppError::internal(err.to_string()))
}

fn flatten_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let name = name.as_str().to_string();
            let value = value.to_str().map(|s| s.to_string()).unwrap_or_else(|_| {
                let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
                format!("base64:{encoded}")
            });
            (name, value)
        })
        .collect()
}
