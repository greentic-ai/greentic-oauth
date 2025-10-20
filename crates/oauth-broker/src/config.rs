use std::{env, sync::Arc};

use url::Url;

use oauth_core::provider::{Provider, ProviderError};

use crate::providers::{
    generic_oidc::GenericOidcProvider,
    microsoft::{MicrosoftProvider, TenantMode},
    ProviderMap,
};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    MissingEnv(&'static str),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),
}

#[derive(Default)]
pub struct ProviderRegistry {
    providers: ProviderMap,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        let mut registry = Self::new();

        if let Some(provider) = build_microsoft_from_env()? {
            registry
                .providers
                .insert("microsoft".into(), Arc::new(provider));
        }

        if let Some(provider) = build_generic_oidc_from_env()? {
            registry
                .providers
                .insert("generic_oidc".into(), Arc::new(provider));
        }

        if registry.providers.is_empty() {
            return Err(ConfigError::InvalidConfig(
                "no providers configured".to_string(),
            ));
        }

        Ok(registry)
    }

    pub fn insert(
        &mut self,
        id: impl Into<String>,
        provider: Arc<dyn Provider>,
    ) -> Option<Arc<dyn Provider>> {
        self.providers.insert(id.into(), provider)
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Provider>> {
        self.providers.get(id).cloned()
    }

    pub fn all(&self) -> &ProviderMap {
        &self.providers
    }
}

fn build_microsoft_from_env() -> Result<Option<MicrosoftProvider>, ConfigError> {
    let client_id = match env::var("MSGRAPH_CLIENT_ID") {
        Ok(value) if !value.is_empty() => value,
        _ => return Ok(None),
    };
    let client_secret = env::var("MSGRAPH_CLIENT_SECRET")
        .map_err(|_| ConfigError::MissingEnv("MSGRAPH_CLIENT_SECRET"))?;
    let tenant_mode_raw = env::var("MSGRAPH_TENANT_MODE").unwrap_or_else(|_| "multi".to_string());
    let tenant_mode = TenantMode::from_env(&tenant_mode_raw)?;
    let redirect_uri = env::var("MSGRAPH_REDIRECT_URI")
        .map_err(|_| ConfigError::MissingEnv("MSGRAPH_REDIRECT_URI"))?;

    let provider = MicrosoftProvider::new(client_id, client_secret, tenant_mode, redirect_uri)?;
    Ok(Some(provider))
}

fn build_generic_oidc_from_env() -> Result<Option<GenericOidcProvider>, ConfigError> {
    let client_id = match env::var("OIDC_CLIENT_ID") {
        Ok(value) if !value.is_empty() => value,
        _ => return Ok(None),
    };
    let client_secret = env::var("OIDC_CLIENT_SECRET")
        .map_err(|_| ConfigError::MissingEnv("OIDC_CLIENT_SECRET"))?;
    let auth_url =
        env::var("OIDC_AUTH_URL").map_err(|_| ConfigError::MissingEnv("OIDC_AUTH_URL"))?;
    let token_url =
        env::var("OIDC_TOKEN_URL").map_err(|_| ConfigError::MissingEnv("OIDC_TOKEN_URL"))?;
    let redirect_uri =
        env::var("OIDC_REDIRECT_URI").map_err(|_| ConfigError::MissingEnv("OIDC_REDIRECT_URI"))?;
    let default_scopes = env::var("OIDC_DEFAULT_SCOPES")
        .unwrap_or_else(|_| "openid profile".to_string())
        .split_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    let provider = GenericOidcProvider::new(
        client_id,
        client_secret,
        auth_url,
        token_url,
        redirect_uri,
        default_scopes,
    )?;

    Ok(Some(provider))
}

#[derive(Clone)]
pub struct RedirectGuard {
    allowed: Vec<Url>,
}

impl RedirectGuard {
    pub fn from_env() -> Result<Self, ConfigError> {
        let raw = env::var("OAUTH_REDIRECT_WHITELIST").unwrap_or_default();
        if raw.trim().is_empty() {
            return Ok(Self {
                allowed: Vec::new(),
            });
        }

        let mut allowed = Vec::new();
        for entry in raw.split(',') {
            let candidate = entry.trim();
            if candidate.is_empty() {
                continue;
            }
            let url = Url::parse(candidate).map_err(|_| {
                ConfigError::InvalidConfig(format!("invalid redirect whitelist url `{candidate}`"))
            })?;
            allowed.push(url);
        }

        Ok(Self { allowed })
    }

    pub fn from_list(urls: Vec<String>) -> Result<Self, ConfigError> {
        let mut allowed = Vec::new();
        for value in urls {
            let url = Url::parse(&value).map_err(|_| {
                ConfigError::InvalidConfig(format!("invalid redirect whitelist url `{value}`"))
            })?;
            allowed.push(url);
        }
        Ok(Self { allowed })
    }

    pub fn is_allowed(&self, candidate: &str) -> bool {
        if self.allowed.is_empty() {
            return false;
        }

        if let Ok(url) = Url::parse(candidate) {
            self.allowed
                .iter()
                .any(|allowed| url.as_str().starts_with(allowed.as_str()))
        } else {
            false
        }
    }
}
