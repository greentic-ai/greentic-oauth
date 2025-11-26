use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use futures_util::future::FutureExt;
use greentic_oauth_core::{
    ProviderOAuthClientConfig, ProviderOAuthFlow, ProviderSecretStore, ProviderTokenError,
    ProviderTokenService, TenantCtx,
};
use greentic_types::{EnvId, TenantId};
use time::OffsetDateTime;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};

async fn try_start_mock() -> Option<MockServer> {
    let fut = MockServer::start();
    let fut = std::panic::AssertUnwindSafe(fut);
    fut.catch_unwind().await.ok()
}

#[derive(Clone, Default)]
struct InMemorySecrets {
    configs: Arc<Mutex<HashMap<String, ProviderOAuthClientConfig>>>,
}

impl InMemorySecrets {
    fn insert(&self, provider_id: &str, config: ProviderOAuthClientConfig) {
        let mut guard = self.configs.lock().expect("config lock");
        guard.insert(provider_id.to_owned(), config);
    }
}

#[async_trait]
impl ProviderSecretStore for InMemorySecrets {
    async fn load_client_config(
        &self,
        _tenant_ctx: &TenantCtx,
        provider_id: &str,
    ) -> Result<ProviderOAuthClientConfig, ProviderTokenError> {
        let guard = self.configs.lock().expect("config lock");
        guard
            .get(provider_id)
            .cloned()
            .ok_or_else(|| ProviderTokenError::MissingConfig {
                provider: provider_id.to_owned(),
                missing: "client config".into(),
            })
    }
}

fn tenant_ctx() -> TenantCtx {
    TenantCtx::new(
        EnvId::try_from("dev").expect("env"),
        TenantId::try_from("acme").expect("tenant"),
    )
}

#[tokio::test]
async fn client_credentials_roundtrip() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!("skipping client_credentials_roundtrip: mock server unavailable");
            return;
        }
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("scope=custom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "abc",
            "token_type": "Bearer",
            "expires_in": 120,
            "scope": "custom email.read"
        })))
        .mount(&server)
        .await;

    let secrets = InMemorySecrets::default();
    secrets.insert(
        "msgraph-email",
        ProviderOAuthClientConfig {
            token_url: format!("{}/token", server.uri()),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec!["email.read".into()],
            audience: None,
            flow: None,
            extra_params: None,
        },
    );

    let service = ProviderTokenService::new(secrets);
    let token = service
        .get_provider_access_token(&tenant_ctx(), "msgraph-email", &[String::from("custom")])
        .await
        .expect("token");

    assert_eq!(token.access_token, "abc");
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.scopes, vec!["custom", "email.read"]);
    assert!(token.expires_at > OffsetDateTime::now_utc());
}

#[tokio::test]
async fn reuses_cached_token_until_expired() {
    let server = match try_start_mock().await {
        Some(srv) => srv,
        None => {
            eprintln!("skipping reuses_cached_token_until_expired: mock server unavailable");
            return;
        }
    };
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "cached",
            "token_type": "Bearer",
            "expires_in": 600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let secrets = InMemorySecrets::default();
    secrets.insert(
        "slack-bot",
        ProviderOAuthClientConfig {
            token_url: format!("{}/token", server.uri()),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec![],
            audience: None,
            flow: None,
            extra_params: None,
        },
    );

    let service = ProviderTokenService::new(secrets);
    let first = service
        .get_provider_access_token(&tenant_ctx(), "slack-bot", &[])
        .await
        .expect("token");
    let second = service
        .get_provider_access_token(&tenant_ctx(), "slack-bot", &[])
        .await
        .expect("token");

    assert_eq!(first.access_token, second.access_token);
    server.verify().await;
}

#[tokio::test]
async fn unsupported_flow_is_rejected() {
    let secrets = InMemorySecrets::default();
    secrets.insert(
        "teams-channel-webhook",
        ProviderOAuthClientConfig {
            token_url: "https://auth.example/token".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            default_scopes: vec!["scope.a".into()],
            audience: None,
            flow: Some(ProviderOAuthFlow::AuthorizationCode),
            extra_params: None,
        },
    );

    let service = ProviderTokenService::new(secrets);
    let err = service
        .get_provider_access_token(&tenant_ctx(), "teams-channel-webhook", &[])
        .await
        .expect_err("should reject flow");

    assert!(matches!(err, ProviderTokenError::UnsupportedFlow(_)));
}

#[tokio::test]
async fn missing_config_surfaces_error() {
    let secrets = InMemorySecrets::default();
    let service = ProviderTokenService::new(secrets);
    let err = service
        .get_provider_access_token(&tenant_ctx(), "missing", &[])
        .await
        .expect_err("missing config");

    assert!(matches!(err, ProviderTokenError::MissingConfig { .. }));
}
