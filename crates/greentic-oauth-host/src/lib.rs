//! Host bindings for `greentic:oauth-broker@1.0.0`.
//!
//! Exposes a helper for wiring the OAuth broker world into a Wasmtime linker
//! and a concrete host implementation backed by the broker service. See
//! README.md for runner-side integration notes.

use std::collections::HashMap;
use std::marker::PhantomData;

use anyhow::{Context, Result, anyhow};
use greentic_oauth_sdk::{Client, ClientConfig, InitiateAuthRequest, OwnerKind, SdkError};
use serde::Serialize;
use serde_json::Value;
use tokio::runtime::Handle;
use wasmtime::component::{HasData, Linker};

mod bindings {
    wasmtime::component::bindgen!({
        path: "../../crates/oauth-wit",
        interfaces: "
            import greentic:oauth-broker/brokerapi@1.0.0;
        ",
        include_generated_code_from_file: true,
    });
}

/// Minimal configuration needed to reach the broker.
#[derive(Clone, Debug, Default)]
pub struct OAuthBrokerConfig {
    /// Base URL for broker HTTP endpoints.
    pub http_base_url: String,
    /// NATS URL used to communicate with the broker.
    pub nats_url: String,
    /// Optional default provider identifier to use when calls omit one.
    pub default_provider: Option<String>,
    /// Optional team scope.
    pub team: Option<String>,
}

impl OAuthBrokerConfig {
    pub fn new(http_base_url: impl Into<String>, nats_url: impl Into<String>) -> Self {
        Self {
            http_base_url: http_base_url.into(),
            nats_url: nats_url.into(),
            default_provider: None,
            team: None,
        }
    }

    pub fn with_default_provider(mut self, provider: impl Into<String>) -> Self {
        self.default_provider = Some(provider.into());
        self
    }

    pub fn with_team(mut self, team: impl Into<String>) -> Self {
        self.team = Some(team.into());
        self
    }
}

/// Context the runner host must expose to the OAuth broker bindings.
pub trait OAuthHostContext {
    fn tenant_id(&self) -> &str;
    fn env(&self) -> &str;
    fn oauth_broker_host(&mut self) -> &mut OAuthBrokerHost;
    fn oauth_config(&self) -> Option<&OAuthBrokerConfig>;
}

/// Convenience context that can be stored in `Store<T>` for simple setups.
#[derive(Default)]
pub struct InMemoryOAuthContext {
    pub tenant_id: String,
    pub env: String,
    pub oauth_config: Option<OAuthBrokerConfig>,
    pub host: OAuthBrokerHost,
}

impl InMemoryOAuthContext {
    pub fn new(
        tenant_id: impl Into<String>,
        env: impl Into<String>,
        cfg: OAuthBrokerConfig,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            env: env.into(),
            oauth_config: Some(cfg.clone()),
            host: OAuthBrokerHost::new(cfg),
        }
    }
}

impl OAuthHostContext for InMemoryOAuthContext {
    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    fn env(&self) -> &str {
        &self.env
    }

    fn oauth_broker_host(&mut self) -> &mut OAuthBrokerHost {
        &mut self.host
    }

    fn oauth_config(&self) -> Option<&OAuthBrokerConfig> {
        self.oauth_config.as_ref()
    }
}

/// Host-side implementation of the broker world.
#[derive(Clone, Default)]
pub struct OAuthBrokerHost {
    cfg: Option<OAuthBrokerConfig>,
    tenant: Option<String>,
    env: Option<String>,
    clients: HashMap<String, Client>,
}

impl OAuthBrokerHost {
    pub fn new(cfg: OAuthBrokerConfig) -> Self {
        Self {
            cfg: Some(cfg),
            tenant: None,
            env: None,
            clients: HashMap::new(),
        }
    }

    pub fn set_config(&mut self, cfg: Option<OAuthBrokerConfig>) {
        self.cfg = cfg;
        self.clients.clear();
    }

    fn with_context(&mut self, tenant: String, env: String) {
        self.tenant = Some(tenant);
        self.env = Some(env);
    }

    fn block<F, T>(&self, fut: F) -> Result<T>
    where
        F: std::future::Future<Output = Result<T, SdkError>> + Send + 'static,
        T: Send + 'static,
    {
        let handle = Handle::try_current().context(
            "oauth broker host requires a running Tokio runtime; \
             ensure host calls happen inside a Tokio context",
        )?;
        handle.block_on(fut).map_err(anyhow::Error::from)
    }

    fn provider_for_call(&self, provider_id: &str) -> Result<String> {
        if !provider_id.is_empty() {
            return Ok(provider_id.to_string());
        }
        self.cfg
            .as_ref()
            .and_then(|cfg| cfg.default_provider.clone())
            .ok_or_else(|| anyhow!("provider_id missing and no default_provider configured"))
    }

    fn to_client_config(&self, provider_id: &str) -> Result<ClientConfig> {
        let tenant = self
            .tenant
            .clone()
            .ok_or_else(|| anyhow!("tenant_id missing in host context"))?;
        let env = self
            .env
            .clone()
            .ok_or_else(|| anyhow!("env missing in host context"))?;
        let cfg = self
            .cfg
            .as_ref()
            .ok_or_else(|| anyhow!("oauth broker config missing from context"))?;
        Ok(ClientConfig {
            http_base_url: cfg.http_base_url.clone(),
            nats_url: cfg.nats_url.clone(),
            env,
            tenant,
            provider: provider_id.to_string(),
            team: cfg.team.clone(),
        })
    }

    fn client_for_provider(&mut self, provider_id: &str) -> Result<Client> {
        let provider = self.provider_for_call(provider_id)?;
        if let Some(existing) = self.clients.get(&provider) {
            return Ok(existing.clone());
        }
        let config = self.to_client_config(&provider)?;
        let client = self.block(async move { Client::connect(config).await })?;
        self.clients.insert(provider.clone(), client.clone());
        Ok(client)
    }

    fn log_error(&self, operation: &str, err: &anyhow::Error) {
        let tenant = self.tenant.as_deref().unwrap_or("<unknown>");
        let env = self.env.as_deref().unwrap_or("<unknown>");
        let provider = self
            .cfg
            .as_ref()
            .and_then(|c| c.default_provider.as_deref())
            .unwrap_or("<unspecified>");
        tracing::warn!(
            operation = operation,
            tenant,
            env,
            provider,
            error = ?err,
            "oauth broker host call failed"
        );
    }
}

#[derive(Clone, Debug, Serialize)]
struct TokenSet {
    access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<String>,
    #[serde(default)]
    extra: Value,
}

impl bindings::greentic::oauth_broker::brokerapi::Host for OAuthBrokerHost {
    fn getconsenturl(
        &mut self,
        provider_id: String,
        subject: String,
        scopes: Vec<String>,
        redirect_path: String,
        _extra_json: String,
    ) -> String {
        let make_request = || -> Result<_> {
            let client = self.client_for_provider(&provider_id)?;
            let request = InitiateAuthRequest {
                owner_kind: OwnerKind::User,
                owner_id: subject,
                flow_id: provider_id.clone(),
                scopes,
                redirect_uri: Some(redirect_path),
                visibility: None,
            };
            let resp = self.block(async move { client.initiate_auth(request).await })?;
            Ok(resp.redirect_url)
        };

        match make_request() {
            Ok(url) => url,
            Err(err) => {
                self.log_error("get_consent_url", &err);
                String::new()
            }
        }
    }

    fn exchangecode(
        &mut self,
        provider_id: String,
        _subject: String,
        code: String,
        _redirect_path: String,
    ) -> String {
        let fetch = || -> Result<_> {
            let client = self.client_for_provider(&provider_id)?;
            let token = self.block(async move { client.get_access_token(&code, true).await })?;
            let json = TokenSet {
                access_token: token.access_token,
                refresh_token: None,
                expires_at: Some(token.expires_at),
                token_type: None,
                extra: Value::Null,
            };
            serde_json::to_string(&json).context("serialize token set")
        };

        match fetch() {
            Ok(json) => json,
            Err(err) => {
                self.log_error("exchange_code", &err);
                String::new()
            }
        }
    }

    fn gettoken(&mut self, provider_id: String, subject: String, _scopes: Vec<String>) -> String {
        let fetch = || -> Result<_> {
            let client = self.client_for_provider(&provider_id)?;
            let token =
                self.block(async move { client.get_access_token(&subject, false).await })?;
            let json = TokenSet {
                access_token: token.access_token,
                refresh_token: None,
                expires_at: Some(token.expires_at),
                token_type: None,
                extra: Value::Null,
            };
            serde_json::to_string(&json).context("serialize token set")
        };

        match fetch() {
            Ok(json) => json,
            Err(err) => {
                self.log_error("get_token", &err);
                String::new()
            }
        }
    }
}

struct BrokerHostFromContext<T>(PhantomData<T>);

impl<T: 'static> HasData for BrokerHostFromContext<T> {
    type Data<'a> = &'a mut OAuthBrokerHost;
}

fn project_host<T: OAuthHostContext>(ctx: &mut T) -> &mut OAuthBrokerHost {
    let tenant = ctx.tenant_id().to_owned();
    let env = ctx.env().to_owned();
    let cfg = ctx.oauth_config().cloned();
    let host = ctx.oauth_broker_host();
    host.set_config(cfg);
    host.with_context(tenant, env);
    host
}

/// Add the OAuth broker world to a Wasmtime linker.
pub fn add_oauth_broker_to_linker<T>(linker: &mut Linker<T>) -> Result<()>
where
    T: OAuthHostContext + Send + Sync + 'static,
{
    bindings::greentic::oauth_broker::brokerapi::add_to_linker::<T, BrokerHostFromContext<T>>(
        linker,
        project_host::<T>,
    )
    .context("failed to add greentic:oauth-broker bindings to linker")
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime::Engine;

    #[test]
    fn adds_broker_to_linker() {
        let mut linker: Linker<InMemoryOAuthContext> = Linker::new(&Engine::default());
        let cfg = OAuthBrokerConfig::new("https://broker.example", "nats://localhost:4222")
            .with_default_provider("test-provider");
        let mut ctx = InMemoryOAuthContext::new("tenant-123", "dev", cfg.clone());

        add_oauth_broker_to_linker(&mut linker).expect("linker wiring succeeds");
        let host = project_host(&mut ctx);
        let provider = host
            .cfg
            .as_ref()
            .and_then(|c| c.default_provider.as_deref());
        assert_eq!(provider, Some("test-provider"));
    }

    #[test]
    fn adds_broker_to_linker_without_config() {
        let mut linker: Linker<InMemoryOAuthContext> = Linker::new(&Engine::default());
        let mut ctx = InMemoryOAuthContext {
            tenant_id: "tenant-456".into(),
            env: "staging".into(),
            oauth_config: None,
            host: OAuthBrokerHost::default(),
        };

        add_oauth_broker_to_linker(&mut linker).expect("linker wiring succeeds without config");
        let host = project_host(&mut ctx);
        assert!(host.cfg.is_none(), "host should reflect absence of config");
    }
}
