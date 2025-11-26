use async_trait::async_trait;
use greentic_oauth_core::{
    ProviderOAuthClientConfig, ProviderSecretStore, ProviderTokenError, ProviderTokenService,
    client_credentials_path, refresh_token_path,
};
use greentic_types::TenantCtx;

use crate::storage::secrets_manager::{SecretPath, SecretsManager, StorageError};

/// ProviderSecretStore backed by the broker's SecretsManager implementation.
pub struct SecretsProviderStore<S> {
    secrets: S,
}

impl<S> SecretsProviderStore<S> {
    pub fn new(secrets: S) -> Self {
        Self { secrets }
    }
}

#[async_trait]
impl<S> ProviderSecretStore for SecretsProviderStore<S>
where
    S: SecretsManager + Send + Sync,
{
    async fn load_client_config(
        &self,
        tenant_ctx: &TenantCtx,
        provider_id: &str,
    ) -> Result<ProviderOAuthClientConfig, ProviderTokenError> {
        let path = SecretPath::new(client_credentials_path(tenant_ctx, provider_id))
            .map_err(|err| ProviderTokenError::Secrets(err.to_string()))?;
        self.secrets
            .get_json::<ProviderOAuthClientConfig>(&path)
            .map_err(map_storage_error)?
            .ok_or(ProviderTokenError::MissingConfig {
                provider: provider_id.to_owned(),
                missing: "client config".to_string(),
            })
    }

    async fn load_refresh_token(
        &self,
        tenant_ctx: &TenantCtx,
        provider_id: &str,
    ) -> Result<Option<String>, ProviderTokenError> {
        let path = SecretPath::new(refresh_token_path(tenant_ctx, provider_id))
            .map_err(|err| ProviderTokenError::Secrets(err.to_string()))?;
        self.secrets
            .get_json::<String>(&path)
            .map_err(map_storage_error)
    }
}

/// Construct a ProviderTokenService using the broker secrets backend.
pub fn provider_token_service<S>(secrets: S) -> ProviderTokenService<SecretsProviderStore<S>>
where
    S: SecretsManager + Send + Sync,
{
    ProviderTokenService::new(SecretsProviderStore::new(secrets))
}

fn map_storage_error(err: StorageError) -> ProviderTokenError {
    ProviderTokenError::Secrets(err.to_string())
}
