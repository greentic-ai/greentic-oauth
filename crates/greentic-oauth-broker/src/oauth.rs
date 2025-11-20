use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::providers::ProviderMap;
use anyhow::{Context, Result, anyhow};
use greentic_oauth_core::provider::{ProviderError, ProviderErrorKind};
use greentic_oauth_core::types::{
    OwnerKind, TenantCtx, TokenHandleClaims, TokenSet as CoreTokenSet,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ureq::Agent;
use url::Url;

/// OAuth token bundle used by the host-facing broker.
///
/// This stays generic: provider-specific details live in `extra`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(default)]
    pub extra: Value,
}

impl TokenSet {
    fn is_expired(&self, now: u64) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

pub trait TokenStore: Send + Sync {
    fn save_token(
        &self,
        tenant: &TenantCtx,
        provider_id: &str,
        subject: &str,
        token: &TokenSet,
    ) -> Result<()>;
    fn load_token(
        &self,
        tenant: &TenantCtx,
        provider_id: &str,
        subject: &str,
    ) -> Result<Option<TokenSet>>;
}

type TokenKey = (String, String, String, String, String);

#[derive(Default)]
pub struct InMemoryTokenStore {
    inner: Mutex<HashMap<TokenKey, TokenSet>>,
}

impl InMemoryTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TokenStore for InMemoryTokenStore {
    fn save_token(
        &self,
        tenant: &TenantCtx,
        provider_id: &str,
        subject: &str,
        token: &TokenSet,
    ) -> Result<()> {
        let key: TokenKey = (
            tenant.env.clone(),
            tenant.tenant.clone(),
            tenant.team.clone().unwrap_or_default(),
            provider_id.to_owned(),
            subject.to_owned(),
        );
        let mut inner = self.inner.lock().expect("token store poisoned");
        inner.insert(key, token.clone());
        Ok(())
    }

    fn load_token(
        &self,
        tenant: &TenantCtx,
        provider_id: &str,
        subject: &str,
    ) -> Result<Option<TokenSet>> {
        let key = (
            tenant.env.clone(),
            tenant.tenant.clone(),
            tenant.team.clone().unwrap_or_default(),
            provider_id.to_owned(),
            subject.to_owned(),
        );
        let inner = self.inner.lock().expect("token store poisoned");
        Ok(inner.get(&key).cloned())
    }
}

pub trait SecretsManager: Send + Sync {
    fn get_secret(&self, key: &str) -> Result<Option<String>>;
}

pub trait ConfigManager: Send + Sync {
    fn get(&self, key: &str) -> Option<String>;
}

#[derive(Debug)]
pub struct ConsentRequest<'a> {
    pub tenant: &'a TenantCtx,
    pub provider_id: &'a str,
    pub subject: &'a str,
    pub client_id: &'a str,
    pub scopes: &'a [String],
    pub redirect_uri: &'a str,
    pub extra: Value,
}

#[derive(Debug)]
pub struct ExchangeRequest<'a> {
    pub tenant: &'a TenantCtx,
    pub provider_id: &'a str,
    pub subject: &'a str,
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
    pub code: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: &'a [String],
}

#[derive(Debug)]
pub struct RefreshRequest<'a> {
    pub tenant: &'a TenantCtx,
    pub provider_id: &'a str,
    pub subject: &'a str,
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
    pub refresh_token: &'a str,
    pub scopes: &'a [String],
}

pub trait OAuthProvider: Send + Sync {
    fn provider_id(&self) -> &str;
    fn auth_url(&self) -> &str;
    fn token_url(&self) -> &str;
    fn default_scopes(&self) -> Vec<String> {
        Vec::new()
    }

    fn build_consent_url(&self, req: &ConsentRequest<'_>) -> Result<String> {
        let mut url = Url::parse(self.auth_url())
            .with_context(|| format!("invalid auth_url for provider {}", self.provider_id()))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("response_type", "code");
            pairs.append_pair("client_id", req.client_id);
            pairs.append_pair("redirect_uri", req.redirect_uri);
            if !req.scopes.is_empty() {
                pairs.append_pair("scope", &req.scopes.join(" "));
            }
            // Optional extra parameters are treated as a flat object of string values.
            if let Value::Object(map) = &req.extra {
                for (k, v) in map {
                    if let Some(val) = v.as_str() {
                        pairs.append_pair(k, val);
                    } else {
                        pairs.append_pair(k, &v.to_string());
                    }
                }
            }
        }
        Ok(url.into())
    }

    fn exchange_code(&self, req: &ExchangeRequest<'_>, http: &Client) -> Result<TokenSet>;

    fn refresh_token(&self, _req: &RefreshRequest<'_>, _http: &Client) -> Result<Option<TokenSet>> {
        Ok(None)
    }
}

/// Adapter that reuses existing `Provider` implementations without changing their behaviour.
pub struct LegacyProviderAdapter {
    id: String,
    inner: Arc<dyn greentic_oauth_core::provider::Provider>,
}

impl LegacyProviderAdapter {
    pub fn new(
        id: impl Into<String>,
        inner: Arc<dyn greentic_oauth_core::provider::Provider>,
    ) -> Self {
        Self {
            id: id.into(),
            inner,
        }
    }

    fn claims(&self, req: &ConsentRequest<'_>, scopes: &[String]) -> TokenHandleClaims {
        let issued = now_secs();
        TokenHandleClaims {
            provider: self.id.clone(),
            subject: req.subject.to_string(),
            owner: OwnerKind::User {
                subject: req.subject.to_string(),
            },
            tenant: req.tenant.clone(),
            scopes: scopes.to_vec(),
            issued_at: issued,
            expires_at: issued,
        }
    }
}

impl OAuthProvider for LegacyProviderAdapter {
    fn provider_id(&self) -> &str {
        &self.id
    }

    fn auth_url(&self) -> &str {
        self.inner.auth_url()
    }

    fn token_url(&self) -> &str {
        self.inner.token_url()
    }

    fn build_consent_url(&self, req: &ConsentRequest<'_>) -> Result<String> {
        // Reuse existing build_authorize_redirect behaviour.
        let mut extra_params = None;
        if let Value::Object(map) = &req.extra {
            let mut flat = std::collections::BTreeMap::new();
            for (k, v) in map {
                if let Some(val) = v.as_str() {
                    flat.insert(k.clone(), val.to_string());
                }
            }
            if !flat.is_empty() {
                extra_params = Some(flat);
            }
        }
        let flow_req = greentic_oauth_core::types::OAuthFlowRequest {
            tenant: req.tenant.clone(),
            owner: OwnerKind::User {
                subject: req.subject.to_string(),
            },
            redirect_uri: req.redirect_uri.to_string(),
            state: None,
            scopes: req.scopes.to_vec(),
            code_challenge: None,
            code_challenge_method: None,
            extra_params,
        };
        let result = self.inner.build_authorize_redirect(&flow_req)?;
        Url::parse(&result.redirect_url)
            .map(|u| u.to_string())
            .context("provider returned invalid redirect url")
    }

    fn exchange_code(&self, req: &ExchangeRequest<'_>, _http: &Client) -> Result<TokenSet> {
        let scopes = req.scopes.to_vec();
        let claims = self.claims(
            &ConsentRequest {
                tenant: req.tenant,
                provider_id: req.provider_id,
                subject: req.subject,
                client_id: req.client_id,
                scopes: req.scopes,
                redirect_uri: req.redirect_uri,
                extra: Value::Null,
            },
            &scopes,
        );
        let token = self.inner.exchange_code(&claims, req.code, None)?;
        Ok(convert_token(token))
    }

    fn refresh_token(&self, req: &RefreshRequest<'_>, _http: &Client) -> Result<Option<TokenSet>> {
        let scopes = req.scopes.to_vec();
        let claims = self.claims(
            &ConsentRequest {
                tenant: req.tenant,
                provider_id: req.provider_id,
                subject: req.subject,
                client_id: req.client_id,
                scopes: req.scopes,
                redirect_uri: "",
                extra: Value::Null,
            },
            &scopes,
        );
        let refreshed = self.inner.refresh(&claims, req.refresh_token)?;
        Ok(Some(convert_token(refreshed)))
    }
}

pub struct OAuthBroker<S, C, T> {
    secrets: Arc<S>,
    config: Arc<C>,
    tokens: Arc<T>,
    providers: HashMap<String, Arc<dyn OAuthProvider>>,
    http: Client,
}

impl<S, C, T> fmt::Debug for OAuthBroker<S, C, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthBroker")
            .field("providers", &self.providers.keys().collect::<HashSet<_>>())
            .finish()
    }
}

impl<S, C, T> OAuthBroker<S, C, T>
where
    S: SecretsManager + 'static,
    C: ConfigManager + 'static,
    T: TokenStore + 'static,
{
    pub fn new(
        secrets: Arc<S>,
        config: Arc<C>,
        tokens: Arc<T>,
        providers: Vec<Arc<dyn OAuthProvider>>,
    ) -> Self {
        let providers = providers
            .into_iter()
            .map(|p| (p.provider_id().to_owned(), p))
            .collect();
        Self {
            secrets,
            config,
            tokens,
            providers,
            http: Client::new(),
        }
    }

    pub fn register_provider(&mut self, provider: Arc<dyn OAuthProvider>) {
        self.providers
            .insert(provider.provider_id().to_owned(), provider);
    }

    pub fn from_legacy_providers(
        secrets: Arc<S>,
        config: Arc<C>,
        tokens: Arc<T>,
        legacy: &ProviderMap,
    ) -> Self {
        let providers: Vec<Arc<dyn OAuthProvider>> = legacy
            .iter()
            .map(|(id, provider)| {
                Arc::new(LegacyProviderAdapter::new(id.clone(), provider.clone()))
                    as Arc<dyn OAuthProvider>
            })
            .collect();
        Self::new(secrets, config, tokens, providers)
    }

    pub fn get_consent_url(
        &self,
        tenant: &TenantCtx,
        provider_id: &str,
        subject: &str,
        scopes: &[String],
        redirect_path: &str,
        extra_json: &str,
    ) -> Result<String> {
        let provider = self.provider(provider_id)?;
        let client_id_key = client_id_key(provider_id);
        let client_id = self.secrets.get_secret(&client_id_key)?.unwrap_or_default();
        let redirect_uri = self.build_redirect_url(tenant, redirect_path)?;
        let requested_scopes = if scopes.is_empty() {
            provider.default_scopes()
        } else {
            scopes.to_vec()
        };
        let extra: Value = if extra_json.is_empty() {
            Value::Object(Default::default())
        } else {
            serde_json::from_str(extra_json).context("invalid extra_json payload")?
        };
        let consent = ConsentRequest {
            tenant,
            provider_id,
            subject,
            client_id: &client_id,
            scopes: &requested_scopes,
            redirect_uri: &redirect_uri,
            extra,
        };
        provider.build_consent_url(&consent)
    }

    pub fn exchange_code(
        &self,
        tenant: &TenantCtx,
        provider_id: &str,
        subject: &str,
        code: &str,
        redirect_path: &str,
        scopes: &[String],
    ) -> Result<TokenSet> {
        let provider = self.provider(provider_id)?;
        let client_id_key = client_id_key(provider_id);
        let client_secret_key = client_secret_key(provider_id);
        let client_id = self.secrets.get_secret(&client_id_key)?.unwrap_or_default();
        let client_secret = self.secrets.get_secret(&client_secret_key)?;
        let redirect_uri = self.build_redirect_url(tenant, redirect_path)?;
        let requested_scopes = if scopes.is_empty() {
            provider.default_scopes()
        } else {
            scopes.to_vec()
        };
        let req = ExchangeRequest {
            tenant,
            provider_id,
            subject,
            client_id: &client_id,
            client_secret: client_secret.as_deref(),
            code,
            redirect_uri: &redirect_uri,
            scopes: &requested_scopes,
        };
        let token = provider.exchange_code(&req, &self.http)?;
        self.tokens
            .save_token(tenant, provider_id, subject, &token)
            .context("persisting exchanged token")?;
        Ok(token)
    }

    pub fn get_token(
        &self,
        tenant: &TenantCtx,
        provider_id: &str,
        subject: &str,
        scopes: &[String],
    ) -> Result<Option<TokenSet>> {
        let provider = self.provider(provider_id)?;
        let now = now_secs();
        if let Some(token) = self.tokens.load_token(tenant, provider_id, subject)? {
            if !token.is_expired(now) {
                return Ok(Some(token));
            }
            if let Some(refresh) = token.refresh_token.clone() {
                let client_id_key = client_id_key(provider_id);
                let client_secret_key = client_secret_key(provider_id);
                let client_id = self.secrets.get_secret(&client_id_key)?.unwrap_or_default();
                let client_secret = self.secrets.get_secret(&client_secret_key)?;
                let refresh_req = RefreshRequest {
                    tenant,
                    provider_id,
                    subject,
                    client_id: &client_id,
                    client_secret: client_secret.as_deref(),
                    refresh_token: &refresh,
                    scopes,
                };
                if let Some(refreshed) = provider.refresh_token(&refresh_req, &self.http)? {
                    self.tokens
                        .save_token(tenant, provider_id, subject, &refreshed)
                        .context("persisting refreshed token")?;
                    return Ok(Some(refreshed));
                }
            }
        }
        Ok(None)
    }

    pub fn build_redirect_url(&self, tenant: &TenantCtx, redirect_path: &str) -> Result<String> {
        let tenant_key = format!("OAUTH_BASE_URL_{}", uppercase_key_token(&tenant.tenant));
        let base = self
            .config
            .get(&tenant_key)
            .or_else(|| self.config.get("OAUTH_BASE_URL"))
            .ok_or_else(|| anyhow!("missing OAUTH_BASE_URL configuration"))?;
        let mut base_url = Url::parse(&base).context("invalid OAUTH_BASE_URL")?;
        let path = redirect_path.strip_prefix('/').unwrap_or(redirect_path);
        let joined = format!("{}/{}", base_url.path().trim_end_matches('/'), path);
        base_url.set_path(&joined);
        Ok(base_url.to_string())
    }

    fn provider(&self, provider_id: &str) -> Result<&Arc<dyn OAuthProvider>> {
        self.providers
            .get(provider_id)
            .ok_or_else(|| anyhow!("unknown provider {}", provider_id))
    }
}

pub struct DummyProvider;

impl OAuthProvider for DummyProvider {
    fn provider_id(&self) -> &str {
        "dummy"
    }

    fn auth_url(&self) -> &str {
        "https://dummy.auth/authorize"
    }

    fn token_url(&self) -> &str {
        "https://dummy.auth/token"
    }

    fn default_scopes(&self) -> Vec<String> {
        vec!["profile".to_string()]
    }

    fn exchange_code(&self, req: &ExchangeRequest<'_>, _http: &Client) -> Result<TokenSet> {
        let exp = now_secs().saturating_add(3600);
        Ok(TokenSet {
            access_token: format!("token:{}:{}", req.provider_id, req.code),
            refresh_token: Some("refresh-dummy".to_string()),
            expires_at: Some(exp),
            token_type: Some("Bearer".to_string()),
            extra: Value::Null,
        })
    }

    fn refresh_token(&self, _req: &RefreshRequest<'_>, _http: &Client) -> Result<Option<TokenSet>> {
        let exp = now_secs().saturating_add(3600);
        Ok(Some(TokenSet {
            access_token: "token:refreshed".to_string(),
            refresh_token: Some("refresh-dummy".to_string()),
            expires_at: Some(exp),
            token_type: Some("Bearer".to_string()),
            extra: Value::Null,
        }))
    }
}

pub struct GenericOidcProvider {
    provider_id: String,
    auth_url: String,
    token_url: String,
    default_scopes: Vec<String>,
    agent: Agent,
}

impl GenericOidcProvider {
    pub fn new(
        provider_id: impl Into<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        default_scopes: impl Into<Vec<String>>,
    ) -> Result<Self> {
        let provider_id = provider_id.into();
        let auth_url = auth_url.into();
        let token_url = token_url.into();
        // validate early
        Url::parse(&auth_url)
            .with_context(|| format!("invalid auth url for provider {}", provider_id))?;
        Url::parse(&token_url)
            .with_context(|| format!("invalid token url for provider {}", provider_id))?;
        Ok(Self {
            provider_id,
            auth_url,
            token_url,
            default_scopes: default_scopes.into(),
            agent: Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into(),
        })
    }

    pub fn from_config(provider_id: &str, config: &dyn ConfigManager) -> Result<Option<Self>> {
        let upper = uppercase_key_token(provider_id);
        let auth_key = format!("OAUTH_{}_AUTH_URL", upper);
        let token_key = format!("OAUTH_{}_TOKEN_URL", upper);
        let scopes_key = format!("OAUTH_{}_SCOPES", upper);

        let auth_url = match config.get(&auth_key) {
            Some(v) => v,
            None => return Ok(None),
        };
        let token_url = config
            .get(&token_key)
            .ok_or_else(|| anyhow!("missing {}", token_key))?;
        let scopes = config
            .get(&scopes_key)
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_else(Vec::new);
        Self::new(provider_id.to_owned(), auth_url, token_url, scopes).map(Some)
    }
}

impl OAuthProvider for GenericOidcProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn auth_url(&self) -> &str {
        &self.auth_url
    }

    fn token_url(&self) -> &str {
        &self.token_url
    }

    fn default_scopes(&self) -> Vec<String> {
        self.default_scopes.clone()
    }

    fn exchange_code(&self, req: &ExchangeRequest<'_>, _http: &Client) -> Result<TokenSet> {
        let mut form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), req.code.to_string()),
            ("redirect_uri".to_string(), req.redirect_uri.to_string()),
            ("client_id".to_string(), req.client_id.to_string()),
        ];
        if let Some(secret) = req.client_secret {
            form.push(("client_secret".to_string(), secret.to_string()));
        }
        if !req.scopes.is_empty() {
            form.push(("scope".to_string(), req.scopes.join(" ")));
        }
        let mut response = self
            .agent
            .post(self.token_url())
            .send_form(form.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .map_err(|err| ProviderError::new(ProviderErrorKind::Transport, err.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            let status_code = status.as_u16();
            let reason = status.canonical_reason().unwrap_or("token endpoint error");
            let body = response
                .body_mut()
                .read_to_string()
                .unwrap_or_else(|_| String::new());
            return Err(ProviderError::new(
                ProviderErrorKind::Authorization,
                format!("token endpoint returned {status_code} {reason}: {body}"),
            )
            .into());
        }

        let body: Value = response.body_mut().read_json().map_err(|err| {
            ProviderError::new(ProviderErrorKind::InvalidResponse, err.to_string())
        })?;
        let access_token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("token response missing access_token"))?
            .to_string();
        let refresh_token = body
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let token_type = body
            .get("token_type")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let expires_at = body
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .map(|ttl| now_secs().saturating_add(ttl));

        Ok(TokenSet {
            access_token,
            refresh_token,
            expires_at,
            token_type,
            extra: body,
        })
    }
}

/// Lightweight adapter that mirrors the greentic:oauth-broker WIT world.
///
/// Errors are logged and returned as empty strings to match the WIT contract.
pub struct BrokerHost<S, C, T> {
    broker: Arc<OAuthBroker<S, C, T>>,
    tenant: TenantCtx,
}

impl<S, C, T> BrokerHost<S, C, T> {
    pub fn new(broker: Arc<OAuthBroker<S, C, T>>, tenant: TenantCtx) -> Self {
        Self { broker, tenant }
    }
}

impl<S, C, T> BrokerHost<S, C, T>
where
    S: SecretsManager + 'static,
    C: ConfigManager + 'static,
    T: TokenStore + 'static,
{
    pub fn get_consent_url(
        &self,
        provider_id: String,
        subject: String,
        scopes: Vec<String>,
        redirect_path: String,
        extra_json: String,
    ) -> String {
        self.broker
            .get_consent_url(
                &self.tenant,
                &provider_id,
                &subject,
                &scopes,
                &redirect_path,
                &extra_json,
            )
            .unwrap_or_else(|err| {
                tracing::warn!(provider_id, "get_consent_url failed: {err:#}");
                String::new()
            })
    }

    pub fn exchange_code(
        &self,
        provider_id: String,
        subject: String,
        code: String,
        redirect_path: String,
        scopes: Vec<String>,
    ) -> String {
        match self.broker.exchange_code(
            &self.tenant,
            &provider_id,
            &subject,
            &code,
            &redirect_path,
            &scopes,
        ) {
            Ok(token) => serde_json::to_string(&token).unwrap_or_default(),
            Err(err) => {
                tracing::warn!(provider_id, "exchange_code failed: {err:#}");
                String::new()
            }
        }
    }

    pub fn get_token(&self, provider_id: String, subject: String, scopes: Vec<String>) -> String {
        match self
            .broker
            .get_token(&self.tenant, &provider_id, &subject, &scopes)
        {
            Ok(Some(token)) => serde_json::to_string(&token).unwrap_or_default(),
            Ok(None) => String::new(),
            Err(err) => {
                tracing::warn!(provider_id, "get_token failed: {err:#}");
                String::new()
            }
        }
    }
}

fn uppercase_key_token(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn client_id_key(provider_id: &str) -> String {
    format!("OAUTH_{}_CLIENT_ID", uppercase_key_token(provider_id))
}

fn client_secret_key(provider_id: &str) -> String {
    format!("OAUTH_{}_CLIENT_SECRET", uppercase_key_token(provider_id))
}

fn convert_token(token: CoreTokenSet) -> TokenSet {
    let expires_at = token.expires_in.map(|ttl| now_secs().saturating_add(ttl));
    let extra = serde_json::to_value(&token).unwrap_or(Value::Null);
    TokenSet {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at,
        token_type: token.token_type,
        extra,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct StubSecrets {
        map: Mutex<HashMap<String, String>>,
    }

    impl StubSecrets {
        fn with(self, key: &str, value: &str) -> Self {
            self.map
                .lock()
                .unwrap()
                .insert(key.to_owned(), value.to_owned());
            self
        }
    }

    impl SecretsManager for StubSecrets {
        fn get_secret(&self, key: &str) -> Result<Option<String>> {
            Ok(self.map.lock().unwrap().get(key).cloned())
        }
    }

    #[derive(Default)]
    struct StubConfig {
        map: Mutex<HashMap<String, String>>,
    }

    impl StubConfig {
        fn with(self, key: &str, value: &str) -> Self {
            self.map
                .lock()
                .unwrap()
                .insert(key.to_owned(), value.to_owned());
            self
        }
    }

    impl ConfigManager for StubConfig {
        fn get(&self, key: &str) -> Option<String> {
            self.map.lock().unwrap().get(key).cloned()
        }
    }

    #[test]
    fn in_memory_store_round_trips() {
        let store = InMemoryTokenStore::new();
        let tenant = TenantCtx {
            env: "dev".into(),
            tenant: "acme".into(),
            team: None,
        };
        let token = TokenSet {
            access_token: "a".into(),
            refresh_token: Some("r".into()),
            expires_at: Some(123),
            token_type: Some("Bearer".into()),
            extra: Value::Null,
        };
        store.save_token(&tenant, "p", "s", &token).unwrap();
        let loaded = store.load_token(&tenant, "p", "s").unwrap().unwrap();
        assert_eq!(token, loaded);
    }

    #[test]
    fn builds_redirect_url_with_tenant_override() {
        let secrets = Arc::new(StubSecrets::default());
        let config = Arc::new(
            StubConfig::default()
                .with("OAUTH_BASE_URL", "https://global.example")
                .with("OAUTH_BASE_URL_ACME", "https://acme.example/base"),
        );
        let tokens = Arc::new(InMemoryTokenStore::new());
        let broker = OAuthBroker::new(secrets, config, tokens, vec![Arc::new(DummyProvider)]);
        let url = broker
            .build_redirect_url(
                &TenantCtx {
                    env: "dev".into(),
                    tenant: "acme".into(),
                    team: None,
                },
                "/oauth/callback",
            )
            .expect("redirect url");
        assert_eq!(url, "https://acme.example/base/oauth/callback");
    }

    #[test]
    fn consent_url_uses_defaults_and_extra() {
        let secrets = Arc::new(StubSecrets::default().with("OAUTH_DUMMY_CLIENT_ID", "client"));
        let config =
            Arc::new(StubConfig::default().with("OAUTH_BASE_URL", "https://global.example"));
        let tokens = Arc::new(InMemoryTokenStore::new());
        let broker = OAuthBroker::new(secrets, config, tokens, vec![Arc::new(DummyProvider)]);
        let url = broker
            .get_consent_url(
                &TenantCtx {
                    env: "dev".into(),
                    tenant: "tenant-1".into(),
                    team: None,
                },
                "dummy",
                "subj",
                &[],
                "/cb",
                r#"{"prompt":"consent"}"#,
            )
            .expect("consent url");
        let parsed = Url::parse(&url).unwrap();
        let pairs: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("prompt"), Some(&"consent".to_string()));
        assert_eq!(pairs.get("scope"), Some(&"profile".to_string()));
        assert_eq!(
            pairs.get("redirect_uri"),
            Some(&"https://global.example/cb".to_string())
        );
    }

    #[test]
    fn uses_refresh_to_extend_token() {
        let secrets = Arc::new(
            StubSecrets::default()
                .with("OAUTH_DUMMY_CLIENT_ID", "client")
                .with("OAUTH_DUMMY_CLIENT_SECRET", "secret"),
        );
        let config =
            Arc::new(StubConfig::default().with("OAUTH_BASE_URL", "https://global.example"));
        let tokens = Arc::new(InMemoryTokenStore::new());
        let broker = OAuthBroker::new(
            secrets,
            config,
            Arc::clone(&tokens),
            vec![Arc::new(DummyProvider)],
        );
        let tenant_ctx = TenantCtx {
            env: "dev".into(),
            tenant: "tenant".into(),
            team: None,
        };
        let expired = TokenSet {
            access_token: "old".into(),
            refresh_token: Some("refresh-dummy".into()),
            expires_at: Some(0),
            token_type: Some("Bearer".into()),
            extra: Value::Null,
        };
        tokens
            .save_token(&tenant_ctx, "dummy", "user1", &expired)
            .unwrap();
        let token = broker
            .get_token(&tenant_ctx, "dummy", "user1", &[])
            .expect("get token")
            .expect("token present");
        assert_eq!(token.access_token, "token:refreshed");
    }

    #[test]
    fn broker_host_marshals_json() {
        let secrets = Arc::new(StubSecrets::default().with("OAUTH_DUMMY_CLIENT_ID", "client"));
        let config =
            Arc::new(StubConfig::default().with("OAUTH_BASE_URL", "https://global.example"));
        let tokens = Arc::new(InMemoryTokenStore::new());
        let broker = Arc::new(OAuthBroker::new(
            secrets,
            config,
            Arc::clone(&tokens),
            vec![Arc::new(DummyProvider)],
        ));
        let host = BrokerHost::new(
            broker,
            TenantCtx {
                env: "dev".into(),
                tenant: "acme".into(),
                team: None,
            },
        );
        let consent = host.get_consent_url(
            "dummy".into(),
            "subject-1".into(),
            vec![],
            "/cb".into(),
            String::new(),
        );
        assert!(consent.contains("dummy.auth/authorize"));

        let exchanged = host.exchange_code(
            "dummy".into(),
            "subject-1".into(),
            "code-123".into(),
            "/cb".into(),
            vec![],
        );
        let token: TokenSet = serde_json::from_str(&exchanged).expect("token json");
        assert_eq!(token.access_token, "token:dummy:code-123");

        let fetched_json = host.get_token("dummy".into(), "subject-1".into(), vec![]);
        let fetched: TokenSet = serde_json::from_str(&fetched_json).expect("token json");
        assert_eq!(fetched.access_token, token.access_token);
    }
}
