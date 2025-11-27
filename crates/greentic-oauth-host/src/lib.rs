//! Host-facing helpers for the `greentic:oauth-broker@1.0.0` world.
//!
//! This crate intentionally keeps host-specific wiring (Wasmtime linker helpers)
//! separate from the core logic used by downstream Rust crates.

use async_trait::async_trait;
use greentic_oauth_core::{AccessToken, OAuthResult};
use greentic_types::{DistributorRef, GitProviderRef, RegistryRef, RepoRef, ScannerRef, TenantCtx};

/// Wrapper holding an OAuth broker client and exposing convenience helpers.
pub struct OauthBrokerHost<B> {
    broker: B,
}

impl<B> OauthBrokerHost<B> {
    /// Construct a new host backed by the provided broker implementation.
    pub fn new(broker: B) -> Self {
        Self { broker }
    }

    /// Access the underlying broker.
    pub fn broker(&self) -> &B {
        &self.broker
    }
}

impl<B> OauthBrokerHost<B>
where
    B: OAuthBroker + Send + Sync,
{
    /// Request a Git provider token for a repo.
    pub async fn request_git_token(
        &self,
        tenant: &TenantCtx,
        provider: GitProviderRef,
        repo: RepoRef,
        scopes: &[String],
    ) -> OAuthResult<AccessToken> {
        request_git_token(&self.broker, tenant, provider, repo, scopes).await
    }

    /// Request an OCI registry token.
    pub async fn request_oci_token(
        &self,
        tenant: &TenantCtx,
        registry: RegistryRef,
        scopes: &[String],
    ) -> OAuthResult<AccessToken> {
        request_oci_token(&self.broker, tenant, registry, scopes).await
    }

    /// Request a scanner token.
    pub async fn request_scanner_token(
        &self,
        tenant: &TenantCtx,
        scanner: ScannerRef,
        scopes: &[String],
    ) -> OAuthResult<AccessToken> {
        request_scanner_token(&self.broker, tenant, scanner, scopes).await
    }

    /// Request a token scoped to a repo (used by Store-facing APIs).
    pub async fn request_repo_token(
        &self,
        tenant: &TenantCtx,
        repo: RepoRef,
        scopes: &[String],
    ) -> OAuthResult<AccessToken> {
        request_repo_token(&self.broker, tenant, repo, scopes).await
    }

    /// Request a distributor token (used by Distributor-facing APIs).
    pub async fn request_distributor_token(
        &self,
        tenant: &TenantCtx,
        distributor: DistributorRef,
        scopes: &[String],
    ) -> OAuthResult<AccessToken> {
        request_distributor_token(&self.broker, tenant, distributor, scopes).await
    }
}

/// Trait abstracting broker communication for testability.
#[async_trait]
pub trait OAuthBroker {
    async fn request_token(
        &self,
        tenant: &TenantCtx,
        resource: &str,
        scopes: &[String],
    ) -> OAuthResult<AccessToken>;
}

/// Request a Git provider token for a repo.
pub async fn request_git_token<B>(
    broker: &B,
    tenant: &TenantCtx,
    provider: GitProviderRef,
    repo: RepoRef,
    scopes: &[String],
) -> OAuthResult<AccessToken>
where
    B: OAuthBroker + ?Sized,
{
    // Repo is currently not used by the broker; it is carried for caller clarity and
    // future scoping rules.
    let _ = repo;
    broker
        .request_token(tenant, provider.as_str(), scopes)
        .await
}

/// Request an OCI registry token.
pub async fn request_oci_token<B>(
    broker: &B,
    tenant: &TenantCtx,
    registry: RegistryRef,
    scopes: &[String],
) -> OAuthResult<AccessToken>
where
    B: OAuthBroker + ?Sized,
{
    broker
        .request_token(tenant, registry.as_str(), scopes)
        .await
}

/// Request a scanner token.
pub async fn request_scanner_token<B>(
    broker: &B,
    tenant: &TenantCtx,
    scanner: ScannerRef,
    scopes: &[String],
) -> OAuthResult<AccessToken>
where
    B: OAuthBroker + ?Sized,
{
    broker.request_token(tenant, scanner.as_str(), scopes).await
}

/// Request a token tied to a repo (Store-facing convenience).
pub async fn request_repo_token<B>(
    broker: &B,
    tenant: &TenantCtx,
    repo: RepoRef,
    scopes: &[String],
) -> OAuthResult<AccessToken>
where
    B: OAuthBroker + ?Sized,
{
    broker.request_token(tenant, repo.as_str(), scopes).await
}

/// Request a token for a distributor endpoint.
pub async fn request_distributor_token<B>(
    broker: &B,
    tenant: &TenantCtx,
    distributor: DistributorRef,
    scopes: &[String],
) -> OAuthResult<AccessToken>
where
    B: OAuthBroker + ?Sized,
{
    broker
        .request_token(tenant, distributor.as_str(), scopes)
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
    use greentic_oauth_core::OAuthError;
    use std::sync::Mutex;

    #[tokio::test]
    async fn maps_broker_error_and_propagates_tenant() {
        let tenant =
            TenantCtx::new("dev".parse().unwrap(), "acme".parse().unwrap()).with_team(None);
        let tracker = Mutex::new(None);
        let scopes_tracker = Mutex::new(None);
        let broker = MockBroker {
            captured: &tracker,
            captured_scopes: &scopes_tracker,
            error: OAuthError::Broker("boom".into()),
        };

        let err = request_git_token(
            &broker,
            &tenant,
            "git".parse().unwrap(),
            "repo".parse().unwrap(),
            &[],
        )
        .await
        .expect_err("should surface broker error");

        match err {
            OAuthError::Broker(msg) => {
                assert!(
                    msg.contains("boom"),
                    "expected broker error message, got {msg}"
                );
            }
            other => panic!("unexpected error mapping: {other:?}"),
        }

        let seen = tracker.lock().unwrap().clone().expect("tenant captured");
        assert_eq!(seen, tenant, "TenantCtx must propagate to broker impl");
        let seen_scopes = scopes_tracker.lock().unwrap().clone().unwrap_or_default();
        assert_eq!(seen_scopes, Vec::<String>::new(), "scopes forwarded");
    }

    struct MockBroker<'a> {
        captured: &'a Mutex<Option<TenantCtx>>,
        captured_scopes: &'a Mutex<Option<Vec<String>>>,
        error: OAuthError,
    }

    #[async_trait]
    impl OAuthBroker for MockBroker<'_> {
        async fn request_token(
            &self,
            tenant: &TenantCtx,
            resource: &str,
            scopes: &[String],
        ) -> OAuthResult<AccessToken> {
            *self.captured.lock().unwrap() = Some(tenant.clone());
            let _ = resource;
            *self.captured_scopes.lock().unwrap() = Some(scopes.to_vec());
            Err(self.error.clone())
        }
    }
}
