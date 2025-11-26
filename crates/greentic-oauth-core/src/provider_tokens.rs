use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use dashmap::DashMap;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use greentic_types::TenantCtx;

const DEFAULT_EXPIRY_SECS: i64 = 3600;
const EXPIRY_SKEW_SECS: i64 = 30;

/// OAuth access token material returned for a provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl ProviderToken {
    fn is_valid(&self, now: OffsetDateTime) -> bool {
        self.expires_at - Duration::seconds(EXPIRY_SKEW_SECS) > now
    }
}

/// Supported OAuth flow kinds for provider components.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOAuthFlow {
    ClientCredentials,
    AuthorizationCode,
    DeviceCode,
    #[serde(other)]
    Other,
}

impl ProviderOAuthFlow {
    fn as_str(&self) -> &str {
        match self {
            ProviderOAuthFlow::ClientCredentials => "client_credentials",
            ProviderOAuthFlow::AuthorizationCode => "authorization_code",
            ProviderOAuthFlow::DeviceCode => "device_code",
            ProviderOAuthFlow::Other => "other",
        }
    }
}

/// Provider OAuth client configuration pulled from secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderOAuthClientConfig {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub default_scopes: Vec<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub flow: Option<ProviderOAuthFlow>,
    #[serde(default)]
    pub extra_params: Option<BTreeMap<String, String>>,
}

impl ProviderOAuthClientConfig {
    fn flow_kind(&self) -> ProviderOAuthFlow {
        self.flow
            .clone()
            .unwrap_or(ProviderOAuthFlow::ClientCredentials)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderTokenError {
    #[error("provider `{provider}` config missing {missing}")]
    MissingConfig { provider: String, missing: String },
    #[error("unsupported oauth flow `{0}`")]
    UnsupportedFlow(String),
    #[error("token endpoint returned {status}: {body}")]
    TokenEndpoint { status: u16, body: String },
    #[error("invalid token response: {0}")]
    InvalidResponse(String),
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("secrets backend error: {0}")]
    Secrets(String),
}

#[async_trait]
pub trait ProviderSecretStore: Send + Sync {
    async fn load_client_config(
        &self,
        tenant_ctx: &TenantCtx,
        provider_id: &str,
    ) -> Result<ProviderOAuthClientConfig, ProviderTokenError>;

    async fn load_refresh_token(
        &self,
        _tenant_ctx: &TenantCtx,
        _provider_id: &str,
    ) -> Result<Option<String>, ProviderTokenError> {
        Ok(None)
    }
}

/// Service that resolves and caches provider access tokens.
pub struct ProviderTokenService<S> {
    secrets: S,
    http_client: Client,
    cache: Arc<DashMap<CacheKey, ProviderToken>>,
}

impl<S> ProviderTokenService<S>
where
    S: ProviderSecretStore,
{
    pub fn new(secrets: S) -> Self {
        Self::with_client(secrets, Client::new())
    }

    pub fn with_client(secrets: S, http_client: Client) -> Self {
        Self {
            secrets,
            http_client,
            cache: Arc::new(DashMap::new()),
        }
    }

    pub async fn get_provider_access_token(
        &self,
        tenant_ctx: &TenantCtx,
        provider_id: &str,
        scopes: &[String],
    ) -> Result<ProviderToken, ProviderTokenError> {
        let config = self
            .secrets
            .load_client_config(tenant_ctx, provider_id)
            .await?;
        let resolved_scopes = if scopes.is_empty() {
            config.default_scopes.clone()
        } else {
            scopes.to_vec()
        };
        let cache_key = CacheKey::new(tenant_ctx, provider_id, &resolved_scopes);

        if let Some(entry) = self.cache.get(&cache_key)
            && entry.is_valid(OffsetDateTime::now_utc())
        {
            return Ok(entry.clone());
        }

        let flow = config.flow_kind();
        let token = match flow {
            ProviderOAuthFlow::ClientCredentials => {
                self.exchange_client_credentials(tenant_ctx, provider_id, &config, &resolved_scopes)
                    .await?
            }
            _ => {
                return Err(ProviderTokenError::UnsupportedFlow(
                    flow.as_str().to_string(),
                ));
            }
        };

        self.cache.insert(cache_key, token.clone());
        Ok(token)
    }

    async fn exchange_client_credentials(
        &self,
        tenant_ctx: &TenantCtx,
        provider_id: &str,
        config: &ProviderOAuthClientConfig,
        scopes: &[String],
    ) -> Result<ProviderToken, ProviderTokenError> {
        if config.token_url.is_empty() {
            return Err(ProviderTokenError::MissingConfig {
                provider: provider_id.to_string(),
                missing: "token_url".into(),
            });
        }
        if config.client_id.is_empty() || config.client_secret.is_empty() {
            return Err(ProviderTokenError::MissingConfig {
                provider: provider_id.to_string(),
                missing: "client_id/client_secret".into(),
            });
        }

        let scope_value = scopes.join(" ");
        let mut form: Vec<(String, String)> = vec![
            ("grant_type".to_string(), "client_credentials".to_string()),
            ("client_id".to_string(), config.client_id.clone()),
            ("client_secret".to_string(), config.client_secret.clone()),
        ];
        if !scope_value.is_empty() {
            form.push(("scope".to_string(), scope_value));
        }
        if let Some(audience) = &config.audience {
            form.push(("audience".to_string(), audience.clone()));
        }
        if let Some(extra) = &config.extra_params {
            form.extend(extra.iter().map(|(k, v)| (k.clone(), v.clone())));
        }

        let response = self
            .http_client
            .post(&config.token_url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&form)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(ProviderTokenError::TokenEndpoint {
                status: status.as_u16(),
                body,
            });
        }

        let payload: ClientCredentialsResponse = serde_json::from_str(&body)
            .map_err(|err| ProviderTokenError::InvalidResponse(err.to_string()))?;
        let now = OffsetDateTime::now_utc();
        let expires_in = payload.expires_in.unwrap_or(DEFAULT_EXPIRY_SECS);
        let expires_at = now
            .checked_add(Duration::seconds(expires_in.max(1)))
            .unwrap_or(now);

        let granted_scopes = if let Some(scope) = payload.scope {
            let parsed: Vec<String> = scope.split_whitespace().map(|s| s.to_string()).collect();
            normalize_scopes(&parsed)
        } else {
            normalize_scopes(scopes)
        };

        if payload.access_token.is_empty() {
            return Err(ProviderTokenError::InvalidResponse(
                "missing access_token in token response".into(),
            ));
        }

        let refresh_token = match payload.refresh_token {
            Some(value) => Some(value),
            None => {
                self.secrets
                    .load_refresh_token(tenant_ctx, provider_id)
                    .await?
            }
        };

        Ok(ProviderToken {
            access_token: payload.access_token,
            token_type: payload.token_type.unwrap_or_else(|| "Bearer".to_string()),
            expires_at,
            refresh_token,
            id_token: payload.id_token,
            scopes: granted_scopes,
        })
    }
}

/// Secrets path for provider client credentials.
pub fn client_credentials_path(tenant_ctx: &TenantCtx, provider_id: &str) -> String {
    format!(
        "oauth/{}/{}/client",
        provider_id,
        tenant_ctx.tenant_id.as_str()
    )
}

/// Secrets path for provider refresh tokens (if present).
pub fn refresh_token_path(tenant_ctx: &TenantCtx, provider_id: &str) -> String {
    format!(
        "oauth/{}/{}/refresh-token",
        provider_id,
        tenant_ctx.tenant_id.as_str()
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct CacheKey {
    env: String,
    tenant: String,
    team: Option<String>,
    provider: String,
    scopes: Vec<String>,
}

impl CacheKey {
    fn new(tenant_ctx: &TenantCtx, provider: &str, scopes: &[String]) -> Self {
        Self {
            env: tenant_ctx.env.to_string(),
            tenant: tenant_ctx.tenant_id.to_string(),
            team: tenant_ctx
                .team
                .as_ref()
                .or(tenant_ctx.team_id.as_ref())
                .map(|team: &greentic_types::TeamId| team.as_str().to_string()),
            provider: provider.to_owned(),
            scopes: normalize_scopes(scopes),
        }
    }
}

fn normalize_scopes(scopes: &[String]) -> Vec<String> {
    let mut normalized = scopes.to_vec();
    normalized.sort();
    normalized.dedup();
    normalized
}

#[derive(Debug, Deserialize)]
struct ClientCredentialsResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}
