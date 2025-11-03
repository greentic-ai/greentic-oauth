use std::{path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{Response, StatusCode},
};
use greentic_oauth_broker::{
    config::{ProviderRegistry, RedirectGuard},
    events::{NoopPublisher, SharedPublisher},
    http::{
        AppContext, SharedContext,
        handlers::discovery::{
            FlowBlueprintRequest, ScopedProviderPath, ScopedQuery, get_requirements,
            get_scoped_provider, list_providers, post_blueprint,
        },
    },
    providers::manifest::ProviderCatalog,
    rate_limit::RateLimiter,
    security::{
        SecurityConfig, csrf::CsrfKey, discovery::DiscoverySigner, jwe::JweVault, jws::JwsService,
    },
    storage::{StorageIndex, env::EnvSecretsManager},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::tempdir;

fn config_root_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../configs")
}

fn providers_root() -> PathBuf {
    config_root_path().join("providers")
}

fn discovery_signer() -> DiscoverySigner {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;

    let secret = [9u8; 32];
    let signing = Ed25519SigningKey::from_bytes(&secret);
    let secret_b64 = URL_SAFE_NO_PAD.encode(secret);
    let public_b64 = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": "manifest-test",
        "d": secret_b64,
        "x": public_b64,
        "alg": "EdDSA",
    });
    DiscoverySigner::from_jwk_value(jwk).expect("discovery signer")
}

fn security_config() -> SecurityConfig {
    let jws = JwsService::from_base64_secret("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
        .expect("jws");
    let jwe = JweVault::from_key_bytes(&[4u8; 32]).expect("jwe");
    let csrf = CsrfKey::new(&[5u8; 32]).expect("csrf");
    SecurityConfig {
        jws,
        jwe,
        csrf,
        discovery: Some(discovery_signer()),
    }
}

fn test_context() -> SharedContext<EnvSecretsManager> {
    let providers = Arc::new(ProviderRegistry::new());
    let security = Arc::new(security_config());
    let secrets_dir = tempdir().expect("tempdir");
    let secrets =
        Arc::new(EnvSecretsManager::new(secrets_dir.path().to_path_buf()).expect("secrets"));
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(RedirectGuard::from_list(vec![]).expect("redirect guard"));
    let rate_limiter = Arc::new(RateLimiter::new(100, Duration::from_secs(60)));
    let config_root = Arc::new(config_root_path());
    let provider_catalog = Arc::new(ProviderCatalog::load(&providers_root()).expect("catalog"));
    let publisher: SharedPublisher = Arc::new(NoopPublisher);

    Arc::new(AppContext {
        providers,
        security,
        secrets,
        index,
        redirect_guard,
        publisher,
        rate_limiter,
        config_root,
        provider_catalog,
    })
}

async fn response_json(response: Response<Body>) -> Value {
    let (parts, body) = response.into_parts();
    assert_eq!(parts.status, StatusCode::OK, "unexpected status");
    let bytes = body.collect().await.expect("body bytes").to_bytes();
    serde_json::from_slice(&bytes).expect("json body")
}

#[tokio::test]
async fn catalog_lists_manifest_providers() {
    let ctx = test_context();
    let response = list_providers::<EnvSecretsManager>(State(ctx.clone()))
        .await
        .expect("providers");
    let providers = response_json(response).await;

    let array = providers.as_array().expect("providers array");
    assert!(
        array.iter().any(|item| {
            item.get("id") == Some(&Value::String("microsoft-graph".into()))
                && item.get("label") == Some(&Value::String("Microsoft Graph".into()))
                && item.get("version") == Some(&Value::String("1".into()))
        }),
        "graph manifest present"
    );
    assert!(
        array.iter().any(|item| {
            item.get("id") == Some(&Value::String("oidc-generic".into()))
                && item.get("label") == Some(&Value::String("Generic OIDC".into()))
                && item.get("version") == Some(&Value::String("1".into()))
        }),
        "oidc manifest present"
    );
}

#[tokio::test]
async fn scoped_manifest_substitutes_tenant_placeholders() {
    let ctx = test_context();
    let response = get_scoped_provider::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "microsoft-graph".to_string(),
        }),
        Query(ScopedQuery {
            team: Some("platform".to_string()),
            user: Some("ops@example.com".to_string()),
        }),
        State(ctx.clone()),
    )
    .await
    .expect("descriptor");

    let descriptor = response_json(response).await;
    let manifest = descriptor
        .get("manifest")
        .and_then(|value| value.as_object())
        .expect("manifest object");

    let secrets = manifest
        .get("secrets")
        .and_then(|value| value.as_object())
        .expect("secrets");
    assert_eq!(
        secrets.get("client_id_key"),
        Some(&Value::String(
            "tenants/acme/oauth/msgraph/client_id".into()
        ))
    );
    assert_eq!(
        secrets.get("client_secret_key"),
        Some(&Value::String(
            "tenants/acme/oauth/msgraph/client_secret".into()
        ))
    );

    let extra = secrets
        .get("extra")
        .and_then(|value| value.as_object())
        .expect("extra secrets");
    assert_eq!(
        extra.get("azure_tenant_id_key"),
        Some(&Value::String(
            "tenants/acme/oauth/msgraph/tenant_id".into()
        ))
    );
}

#[tokio::test]
async fn blueprint_expands_template_inputs() {
    let ctx = test_context();
    let redirect_uri = "https://app.example.com/callback";
    let scopes = vec!["openid".to_string(), "email".to_string()];
    let state = "sso-state".to_string();

    let response = post_blueprint::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "oidc-generic".to_string(),
        }),
        State(ctx.clone()),
        Json(FlowBlueprintRequest {
            grant_type: "authorization_code".to_string(),
            team: Some("security".to_string()),
            user: None,
            redirect_uri: Some(redirect_uri.to_string()),
            scopes: Some(scopes.clone()),
            state: Some(state.clone()),
        }),
    )
    .await
    .expect("blueprint");

    let blueprint = response_json(response).await;
    let auth_url = blueprint
        .get("auth_url_example")
        .and_then(|value| value.as_str())
        .expect("auth url");

    let encode =
        |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    assert!(
        auth_url.contains(&encode(redirect_uri)),
        "redirect uri encoded"
    );
    assert!(
        auth_url.contains(&encode(&scopes.join(" "))),
        "scopes encoded"
    );
    assert!(auth_url.contains(&encode(&state)), "state encoded");
}

#[tokio::test]
async fn requirements_surface_manifest_secrets() {
    let ctx = test_context();
    let response = get_requirements::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "oidc-generic".to_string(),
        }),
        Query(ScopedQuery {
            team: None,
            user: Some("owner@example.com".to_string()),
        }),
        State(ctx.clone()),
    )
    .await
    .expect("requirements");

    let requirements = response_json(response).await;
    let secrets = requirements
        .get("secrets")
        .and_then(|value| value.as_object())
        .expect("secrets object");

    assert_eq!(
        secrets.get("client_id_key"),
        Some(&Value::String("tenants/acme/oauth/oidc/client_id".into()))
    );
    assert_eq!(
        secrets.get("client_secret_key"),
        Some(&Value::String(
            "tenants/acme/oauth/oidc/client_secret".into()
        ))
    );

    let grant_paths = requirements
        .get("grant_paths")
        .and_then(|value| value.as_array())
        .expect("grant paths");
    assert!(!grant_paths.is_empty(), "grant paths present");
}
