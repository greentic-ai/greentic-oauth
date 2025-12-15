use std::{env, sync::Arc};

use url::Url;

use crate::storage::secrets_manager::{SecretPath, SecretsManager, StorageError};
use greentic_oauth_core::provider::{Provider, ProviderError};

use crate::providers::{
    ProviderMap,
    generic_oidc::GenericOidcProvider,
    microsoft::{MicrosoftProvider, TenantMode},
};

const SECRET_MICROSOFT_CLIENT_SECRET: &str = "oauth/providers/microsoft/client-secret";
const SECRET_OIDC_CLIENT_SECRET: &str = "oauth/providers/generic-oidc/client-secret";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    MissingEnv(&'static str),
    #[error("missing secret {key} at {path}")]
    MissingSecret { key: &'static str, path: String },
    #[error("secrets backend error: {0}")]
    Secrets(String),
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

    pub fn from_store<S: SecretsManager>(secrets: &S) -> Result<Self, ConfigError> {
        let mut registry = Self::new();

        if let Some(provider) = build_microsoft_from_store(secrets)? {
            registry
                .providers
                .insert("microsoft".into(), Arc::new(provider));
        }

        if let Some(provider) = build_generic_oidc_from_store(secrets)? {
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

fn build_microsoft_from_store<S: SecretsManager>(
    secrets: &S,
) -> Result<Option<MicrosoftProvider>, ConfigError> {
    let client_id = match env::var("MSGRAPH_CLIENT_ID") {
        Ok(value) if !value.is_empty() => value,
        _ => return Ok(None),
    };
    let client_secret = read_required_secret(
        secrets,
        SECRET_MICROSOFT_CLIENT_SECRET,
        "MSGRAPH_CLIENT_SECRET",
    )?;
    let tenant_mode_raw = env::var("MSGRAPH_TENANT_MODE").unwrap_or_else(|_| "multi".to_string());
    let tenant_mode = TenantMode::from_env(&tenant_mode_raw)?;
    let redirect_uri = env::var("MSGRAPH_REDIRECT_URI")
        .map_err(|_| ConfigError::MissingEnv("MSGRAPH_REDIRECT_URI"))?;

    let default_scopes_raw = env::var("MSGRAPH_DEFAULT_SCOPES")
        .unwrap_or_else(|_| "offline_access openid profile".into());
    let default_scopes = parse_scopes(&default_scopes_raw);
    let resource_audience = env::var("MSGRAPH_RESOURCE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let provider = MicrosoftProvider::new(
        client_id,
        client_secret,
        tenant_mode,
        redirect_uri,
        default_scopes,
        resource_audience,
    )?;
    Ok(Some(provider))
}

fn build_generic_oidc_from_store<S: SecretsManager>(
    secrets: &S,
) -> Result<Option<GenericOidcProvider>, ConfigError> {
    let client_id = match env::var("OIDC_CLIENT_ID") {
        Ok(value) if !value.is_empty() => value,
        _ => return Ok(None),
    };
    let client_secret =
        read_required_secret(secrets, SECRET_OIDC_CLIENT_SECRET, "OIDC_CLIENT_SECRET")?;
    let auth_url =
        env::var("OIDC_AUTH_URL").map_err(|_| ConfigError::MissingEnv("OIDC_AUTH_URL"))?;
    let token_url =
        env::var("OIDC_TOKEN_URL").map_err(|_| ConfigError::MissingEnv("OIDC_TOKEN_URL"))?;
    let redirect_uri =
        env::var("OIDC_REDIRECT_URI").map_err(|_| ConfigError::MissingEnv("OIDC_REDIRECT_URI"))?;
    let default_scopes =
        parse_scopes(&env::var("OIDC_DEFAULT_SCOPES").unwrap_or_else(|_| "openid profile".into()));

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

fn parse_scopes(value: &str) -> Vec<String> {
    value
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{EnvSecretsManager, secrets_manager::SecretPath};
    use std::env;
    use tempfile::tempdir;

    #[test]
    fn loads_provider_secrets_from_store() {
        let dir = tempdir().expect("tempdir");
        let store = EnvSecretsManager::new(dir.path().to_path_buf()).expect("store");
        store
            .put_json(
                &SecretPath::new(SECRET_MICROSOFT_CLIENT_SECRET).unwrap(),
                &"micro-secret".to_string(),
            )
            .unwrap();

        unsafe {
            env::set_var("MSGRAPH_CLIENT_ID", "client-id");
            env::set_var("MSGRAPH_REDIRECT_URI", "https://example.test/callback");
        }

        let registry = ProviderRegistry::from_store(&store).expect("provider registry");
        assert!(registry.get("microsoft").is_some());

        unsafe {
            env::remove_var("MSGRAPH_CLIENT_ID");
            env::remove_var("MSGRAPH_REDIRECT_URI");
        }
    }

    #[test]
    fn missing_provider_secret_surfaces_error() {
        let dir = tempdir().expect("tempdir");
        let store = EnvSecretsManager::new(dir.path().to_path_buf()).expect("store");

        unsafe {
            env::set_var("MSGRAPH_CLIENT_ID", "client-id");
            env::set_var("MSGRAPH_REDIRECT_URI", "https://example.test/callback");
        }

        let err = ProviderRegistry::from_store(&store);
        assert!(matches!(err, Err(ConfigError::MissingSecret { .. })));

        unsafe {
            env::remove_var("MSGRAPH_CLIENT_ID");
            env::remove_var("MSGRAPH_REDIRECT_URI");
        }
    }
}

fn read_required_secret<S: SecretsManager>(
    secrets: &S,
    path: &str,
    label: &'static str,
) -> Result<String, ConfigError> {
    let path =
        SecretPath::new(path.to_string()).map_err(|err| ConfigError::Secrets(err.to_string()))?;
    match secrets.get_json::<String>(&path) {
        Ok(Some(value)) => Ok(value),
        Ok(None) | Err(StorageError::NotFound(_)) => Err(ConfigError::MissingSecret {
            key: label,
            path: path.as_str().to_string(),
        }),
        Err(StorageError::InvalidPath(reason)) => Err(ConfigError::Secrets(reason)),
        Err(StorageError::Io(err)) => Err(ConfigError::Secrets(err.to_string())),
        Err(StorageError::Serialization(err)) => Err(ConfigError::Secrets(err.to_string())),
        Err(StorageError::Encoding(err)) => Err(ConfigError::Secrets(err)),
        Err(StorageError::Unsupported(reason)) => Err(ConfigError::Secrets(reason.to_string())),
    }
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
