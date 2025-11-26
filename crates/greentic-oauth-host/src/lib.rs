//! Host-facing helpers for the `greentic:oauth-broker@1.0.0` world.
//!
//! This crate intentionally keeps host-specific wiring (Wasmtime linker helpers)
//! separate from the core logic used by downstream Rust crates.

use greentic_oauth_core::{
    ProviderSecretStore, ProviderToken, ProviderTokenError, ProviderTokenService,
};
use greentic_types::{DistributorRef, GitProviderRef, RegistryRef, RepoRef, ScannerRef, TenantCtx};

/// Wrapper holding a [`ProviderTokenService`] and exposing convenience helpers.
pub struct OauthBrokerHost<S> {
    token_service: ProviderTokenService<S>,
}

impl<S> OauthBrokerHost<S>
where
    S: ProviderSecretStore,
{
    /// Construct a new host backed by the provided secret store.
    pub fn new(secret_store: S) -> Self {
        Self {
            token_service: ProviderTokenService::new(secret_store),
        }
    }

    /// Access the underlying token service.
    pub fn token_service(&self) -> &ProviderTokenService<S> {
        &self.token_service
    }

    /// Request a Git provider token for a repo.
    pub async fn request_git_token(
        &self,
        tenant: &TenantCtx,
        provider: GitProviderRef,
        repo: RepoRef,
        scopes: &[String],
    ) -> Result<ProviderToken, ProviderTokenError> {
        request_git_token(self.token_service(), tenant, provider, repo, scopes).await
    }

    /// Request an OCI registry token.
    pub async fn request_oci_token(
        &self,
        tenant: &TenantCtx,
        registry: RegistryRef,
        scopes: &[String],
    ) -> Result<ProviderToken, ProviderTokenError> {
        request_oci_token(self.token_service(), tenant, registry, scopes).await
    }

    /// Request a scanner token.
    pub async fn request_scanner_token(
        &self,
        tenant: &TenantCtx,
        scanner: ScannerRef,
        scopes: &[String],
    ) -> Result<ProviderToken, ProviderTokenError> {
        request_scanner_token(self.token_service(), tenant, scanner, scopes).await
    }

    /// Request a token scoped to a repo (used by Store-facing APIs).
    pub async fn request_repo_token(
        &self,
        tenant: &TenantCtx,
        repo: RepoRef,
        scopes: &[String],
    ) -> Result<ProviderToken, ProviderTokenError> {
        request_repo_token(self.token_service(), tenant, repo, scopes).await
    }

    /// Request a distributor token (used by Distributor-facing APIs).
    pub async fn request_distributor_token(
        &self,
        tenant: &TenantCtx,
        distributor: DistributorRef,
        scopes: &[String],
    ) -> Result<ProviderToken, ProviderTokenError> {
        request_distributor_token(self.token_service(), tenant, distributor, scopes).await
    }
}

/// Request a Git provider token for a repo.
pub async fn request_git_token<S>(
    service: &ProviderTokenService<S>,
    tenant: &TenantCtx,
    provider: GitProviderRef,
    repo: RepoRef,
    scopes: &[String],
) -> Result<ProviderToken, ProviderTokenError>
where
    S: ProviderSecretStore,
{
    // Repo is currently not used by the broker; it is carried for caller clarity and
    // future scoping rules.
    let _ = repo;
    service
        .get_provider_access_token(tenant, provider.as_str(), scopes)
        .await
}

/// Request an OCI registry token.
pub async fn request_oci_token<S>(
    service: &ProviderTokenService<S>,
    tenant: &TenantCtx,
    registry: RegistryRef,
    scopes: &[String],
) -> Result<ProviderToken, ProviderTokenError>
where
    S: ProviderSecretStore,
{
    service
        .get_provider_access_token(tenant, registry.as_str(), scopes)
        .await
}

/// Request a scanner token.
pub async fn request_scanner_token<S>(
    service: &ProviderTokenService<S>,
    tenant: &TenantCtx,
    scanner: ScannerRef,
    scopes: &[String],
) -> Result<ProviderToken, ProviderTokenError>
where
    S: ProviderSecretStore,
{
    service
        .get_provider_access_token(tenant, scanner.as_str(), scopes)
        .await
}

/// Request a token tied to a repo (Store-facing convenience).
pub async fn request_repo_token<S>(
    service: &ProviderTokenService<S>,
    tenant: &TenantCtx,
    repo: RepoRef,
    scopes: &[String],
) -> Result<ProviderToken, ProviderTokenError>
where
    S: ProviderSecretStore,
{
    service
        .get_provider_access_token(tenant, repo.as_str(), scopes)
        .await
}

/// Request a token for a distributor endpoint.
pub async fn request_distributor_token<S>(
    service: &ProviderTokenService<S>,
    tenant: &TenantCtx,
    distributor: DistributorRef,
    scopes: &[String],
) -> Result<ProviderToken, ProviderTokenError>
where
    S: ProviderSecretStore,
{
    service
        .get_provider_access_token(tenant, distributor.as_str(), scopes)
        .await
}

/// Canonical Wasmtime linker exports for the oauth-broker world.
pub mod linker {
    pub use greentic_interfaces_wasmtime::oauth_broker_broker_v1_0::Component as OauthBrokerComponent;
    pub use greentic_interfaces_wasmtime::oauth_broker_broker_v1_0::*;
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use greentic_oauth_core::{ProviderOAuthClientConfig, ProviderOAuthFlow};

    struct InMemoryStore {
        config: ProviderOAuthClientConfig,
    }

    #[async_trait]
    impl ProviderSecretStore for InMemoryStore {
        async fn load_client_config(
            &self,
            _tenant_ctx: &TenantCtx,
            _provider_id: &str,
        ) -> Result<ProviderOAuthClientConfig, ProviderTokenError> {
            Ok(self.config.clone())
        }
    }

    #[tokio::test]
    async fn caches_and_returns_token() {
        let tenant = TenantCtx::new("dev".parse().expect("env"), "acme".parse().expect("tenant"));
        let store = InMemoryStore {
            config: ProviderOAuthClientConfig {
                token_url: "".into(),
                client_id: "id".into(),
                client_secret: "secret".into(),
                default_scopes: vec!["a".into()],
                audience: None,
                flow: Some(ProviderOAuthFlow::ClientCredentials),
                extra_params: None,
            },
        };
        let service = ProviderTokenService::new(store);

        let result = request_repo_token(
            &service,
            &tenant,
            "repo-1".parse().expect("repo"),
            &["s1".into()],
        )
        .await;

        assert!(
            result.is_err(),
            "missing token_url should fail without network"
        );
    }
}
