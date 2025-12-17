use std::{path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Response, StatusCode, header},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use greentic_oauth_broker::{
    admin::{AdminRegistry, consent::AdminConsentStore},
    auth::AuthSessionStore,
    config::{ProviderRegistry, RedirectGuard},
    discovery::{ProviderDescriptor, load_provider_descriptor},
    events::{NoopPublisher, SharedPublisher},
    http::{
        AppContext, SharedContext,
        handlers::discovery::{
            FlowBlueprintRequest, ScopedProviderPath, ScopedQuery, get_jwks, get_requirements,
            get_scoped_provider, post_blueprint,
        },
        handlers::well_known,
    },
    providers::manifest::ProviderCatalog,
    rate_limit::RateLimiter,
    security::{
        SecurityConfig, csrf::CsrfKey, discovery::DiscoverySigner, jwe::JweVault, jws::JwsService,
    },
    storage::{StorageIndex, env::EnvSecretsManager},
};
use http_body_util::BodyExt;
use jsonschema::{Validator, validator_for};
use rand::{TryRngCore, rngs::OsRng};
use serde_json::{Value, json};
use tempfile::tempdir;
use url::Url;

static PROVIDER_SCHEMA: &str =
    include_str!("../../../static/schemas/provider-descriptor.schema.json");
static REQUIREMENTS_SCHEMA: &str =
    include_str!("../../../static/schemas/config-requirements.schema.json");
static BLUEPRINT_SCHEMA: &str = include_str!("../../../static/schemas/flow-blueprint.schema.json");
static GRAPH_REQUIREMENTS_EXAMPLE: &str =
    include_str!("../../../static/examples/microsoft-graph.requirements.json");
static SLACK_REQUIREMENTS_EXAMPLE: &str =
    include_str!("../../../static/examples/slack.requirements.json");
static GRAPH_BLUEPRINT_EXAMPLE: &str =
    include_str!("../../../static/examples/microsoft-graph.blueprint.json");

fn config_root_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../configs")
}

fn compile(schema_str: &str) -> Validator {
    let schema_json: Value = serde_json::from_str(schema_str).expect("schema json");
    validator_for(&schema_json).expect("valid schema")
}

fn validate(schema: &Validator, data: &Value) {
    let errors: Vec<_> = schema
        .iter_errors(data)
        .map(|err| format!("{err}"))
        .collect();
    if !errors.is_empty() {
        let formatted = errors.join("\n");
        panic!("schema validation failed:\n{formatted}\nDocument: {data}");
    }
}

fn random_bytes() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut key)
        .expect("os entropy source unavailable");
    key
}

fn security_config() -> SecurityConfig {
    let jws = JwsService::from_base64_secret("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
        .expect("jws");
    let jwe_key = random_bytes();
    let csrf_key = random_bytes();
    let jwe = JweVault::from_key_bytes(&jwe_key).expect("jwe");
    let csrf = CsrfKey::new(&csrf_key).expect("csrf");
    let discovery = Some(discovery_signer());
    SecurityConfig {
        jws,
        jwe,
        csrf,
        discovery,
    }
}

fn discovery_signer() -> DiscoverySigner {
    let secret = [7u8; 32];
    let signing = Ed25519SigningKey::from_bytes(&secret);
    let secret_b64 = URL_SAFE_NO_PAD.encode(secret);
    let public_b64 = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": "test-discovery",
        "d": secret_b64,
        "x": public_b64,
        "alg": "EdDSA",
    });
    DiscoverySigner::from_jwk_value(jwk).expect("discovery signer")
}

fn test_context() -> SharedContext<EnvSecretsManager> {
    let providers = Arc::new(ProviderRegistry::new());
    let security = Arc::new(security_config());
    let secrets_dir = tempdir().expect("tempdir");
    let secrets =
        Arc::new(EnvSecretsManager::new(secrets_dir.path().to_path_buf()).expect("secrets"));
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(RedirectGuard::from_list(vec![]).expect("redirect guard"));
    let publisher: SharedPublisher = Arc::new(NoopPublisher);
    let rate_limiter = Arc::new(RateLimiter::new(100, Duration::from_secs(60)));
    let config_root_path = config_root_path();
    let provider_catalog =
        Arc::new(ProviderCatalog::load(&config_root_path.join("providers")).expect("catalog"));
    let config_root = Arc::new(config_root_path);

    let sessions = Arc::new(AuthSessionStore::new(Duration::from_secs(900)));
    let oauth_base_url = Arc::new(Url::parse("https://broker.example.com/").unwrap());
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
        allow_insecure: true,
        allow_extra_params: true,
        enable_test_endpoints: false,
        sessions,
        oauth_base_url: Some(oauth_base_url),
        admin_registry: Arc::new(AdminRegistry::default()),
        admin_consent: Arc::new(AdminConsentStore::new(Duration::from_secs(600))),
        token_http_client: reqwest::Client::new(),
    })
}

async fn response_json(response: Response<Body>) -> (Value, HeaderMap) {
    let (parts, body) = response.into_parts();
    assert_eq!(parts.status, StatusCode::OK, "unexpected status");
    let bytes = body.collect().await.expect("body bytes").to_bytes();
    let value: Value = serde_json::from_slice(&bytes).expect("json body");
    (value, parts.headers)
}

fn assert_spec_headers(headers: &HeaderMap) {
    let cache_control = headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .expect("cache control");
    assert_eq!(cache_control, "max-age=60");
    let spec_version = headers
        .get("x-spec-version")
        .and_then(|v| v.to_str().ok())
        .expect("spec version");
    assert_eq!(spec_version, "1.0");
    assert!(headers.get(header::ETAG).is_some(), "etag missing");
}

#[tokio::test]
async fn provider_descriptors_match_schema() {
    let provider_schema = compile(PROVIDER_SCHEMA);

    let root = config_root_path();

    let microsoft: ProviderDescriptor = load_provider_descriptor(
        &root,
        "microsoft-graph",
        Some("acme"),
        Some("platform"),
        None,
    )
    .expect("descriptor");
    let microsoft_json = serde_json::to_value(&microsoft).unwrap();
    validate(&provider_schema, &microsoft_json);

    let slack: ProviderDescriptor =
        load_provider_descriptor(&root, "slack", None, None, None).expect("descriptor");
    let slack_json = serde_json::to_value(&slack).unwrap();
    validate(&provider_schema, &slack_json);
}

#[tokio::test]
async fn requirements_match_schema_and_examples() {
    let ctx = test_context();
    let requirements_schema = compile(REQUIREMENTS_SCHEMA);

    let response = get_requirements::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "microsoft-graph".to_string(),
        }),
        Query(ScopedQuery {
            team: Some("ops".to_string()),
            user: Some("alice@example.com".to_string()),
        }),
        State(ctx.clone()),
    )
    .await
    .expect("requirements");
    let (graph_json, headers) = response_json(response).await;
    assert_spec_headers(&headers);
    validate(&requirements_schema, &graph_json);

    let example_graph: Value = serde_json::from_str(GRAPH_REQUIREMENTS_EXAMPLE).unwrap();
    validate(&requirements_schema, &example_graph);
    assert_eq!(
        graph_json, example_graph,
        "graph example matches runtime output"
    );

    let response = get_requirements::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "slack".to_string(),
        }),
        Query(ScopedQuery {
            team: None,
            user: None,
        }),
        State(ctx.clone()),
    )
    .await
    .expect("requirements");
    let (slack_json, headers) = response_json(response).await;
    assert_spec_headers(&headers);
    validate(&requirements_schema, &slack_json);

    let example_slack: Value = serde_json::from_str(SLACK_REQUIREMENTS_EXAMPLE).unwrap();
    validate(&requirements_schema, &example_slack);
    assert_eq!(
        slack_json, example_slack,
        "slack example matches runtime output"
    );
}

#[tokio::test]
async fn blueprint_matches_schema() {
    let ctx = test_context();
    let blueprint_schema = compile(BLUEPRINT_SCHEMA);

    let response = post_blueprint::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "microsoft-graph".to_string(),
        }),
        State(ctx.clone()),
        Json(FlowBlueprintRequest {
            grant_type: "authorization_code".to_string(),
            team: Some("ops".to_string()),
            user: Some("alice@example.com".to_string()),
            redirect_uri: None,
            scopes: None,
            state: None,
        }),
    )
    .await
    .expect("blueprint");
    let (blueprint_json, headers) = response_json(response).await;
    assert_spec_headers(&headers);
    validate(&blueprint_schema, &blueprint_json);

    let example_blueprint: Value = serde_json::from_str(GRAPH_BLUEPRINT_EXAMPLE).unwrap();
    validate(&blueprint_schema, &example_blueprint);
}

#[tokio::test]
async fn descriptor_signature_matches_payload() {
    let ctx = test_context();

    let response = get_scoped_provider::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "microsoft-graph".to_string(),
        }),
        Query(ScopedQuery {
            team: Some("ops".to_string()),
            user: Some("alice@example.com".to_string()),
        }),
        State(ctx.clone()),
    )
    .await
    .expect("descriptor");

    let (mut descriptor, headers) = response_json(response).await;
    assert_spec_headers(&headers);

    let signature = descriptor
        .get("signature")
        .and_then(|value| value.as_object())
        .cloned()
        .expect("signature object");
    let payload_b64 = signature
        .get("payload")
        .and_then(|v| v.as_str())
        .expect("payload");
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .expect("payload decode");
    let payload_value: Value = serde_json::from_slice(&payload_bytes).expect("payload json");

    descriptor
        .as_object_mut()
        .expect("descriptor object")
        .remove("signature");
    assert_eq!(descriptor, payload_value, "payload matches descriptor");

    let signer = ctx.security.discovery.as_ref().expect("signer").clone();
    let expected = signer.sign(&payload_bytes).expect("sign");
    assert_eq!(
        signature
            .get("protected")
            .and_then(|v| v.as_str())
            .expect("protected"),
        expected.protected
    );
    assert_eq!(
        signature
            .get("signature")
            .and_then(|v| v.as_str())
            .expect("signature"),
        expected.signature
    );
}

#[tokio::test]
async fn jwks_endpoint_returns_public_key() {
    let ctx = test_context();

    let response = get_jwks::<EnvSecretsManager>(State(ctx.clone()))
        .await
        .expect("jwks");
    let (jwks, headers) = response_json(response).await;
    assert_spec_headers(&headers);

    let keys = jwks
        .get("keys")
        .and_then(|value| value.as_array())
        .expect("keys array");
    assert_eq!(keys.len(), 1, "expected single discovery key");
    assert_eq!(
        keys[0].get("kid"),
        Some(&Value::String("test-discovery".into()))
    );
}

#[tokio::test]
async fn well_known_reports_signing_metadata() {
    let ctx = test_context();
    let response = well_known::document::<EnvSecretsManager>(State(ctx))
        .await
        .expect("well-known");
    let (doc, headers) = response_json(response).await;
    assert_spec_headers(&headers);

    assert_eq!(
        doc.get("service_name"),
        Some(&Value::String("greentic-oauth".into()))
    );
    assert_eq!(
        doc.get("providers_index"),
        Some(&Value::String(
            "{api_base}/oauth/discovery/providers".into()
        ))
    );
    let capabilities = doc
        .get("capabilities")
        .and_then(|value| value.as_object())
        .expect("capabilities object");
    assert_eq!(
        capabilities.get("grant_types"),
        Some(&json!([
            "authorization_code",
            "client_credentials",
            "device_code",
            "refresh_token"
        ]))
    );
    assert_eq!(
        capabilities.get("auth_methods"),
        Some(&json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt"
        ]))
    );
    assert_eq!(
        capabilities.get("features"),
        Some(&json!([
            "mcp",
            "wit",
            "nats-propagation",
            "webhook-callbacks"
        ]))
    );
    assert_eq!(
        doc.get("jwks_uri"),
        Some(&Value::String("{api_base}/.well-known/jwks.json".into()))
    );
    assert_eq!(
        doc.get("kid"),
        Some(&Value::String("test-discovery".into()))
    );
    assert_eq!(doc.get("metadata"), Some(&json!({ "owner": "greentic" })));
}

#[tokio::test]
#[ignore]
async fn dump_http_discovery_samples() {
    let ctx = test_context();
    let response = get_scoped_provider::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "microsoft-graph".to_string(),
        }),
        Query(ScopedQuery {
            team: Some("ops".to_string()),
            user: Some("alice@example.com".to_string()),
        }),
        State(ctx.clone()),
    )
    .await
    .expect("descriptor");
    let (descriptor, _) = response_json(response).await;
    println!(
        "http-graph-descriptor:\n{}",
        serde_json::to_string_pretty(&descriptor).unwrap()
    );

    let response = get_requirements::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "microsoft-graph".to_string(),
        }),
        Query(ScopedQuery {
            team: Some("ops".to_string()),
            user: Some("alice@example.com".to_string()),
        }),
        State(ctx.clone()),
    )
    .await
    .expect("requirements");
    let (requirements, _) = response_json(response).await;
    println!(
        "http-graph-requirements:\n{}",
        serde_json::to_string_pretty(&requirements).unwrap()
    );

    let response = post_blueprint::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "microsoft-graph".to_string(),
        }),
        State(ctx.clone()),
        Json(FlowBlueprintRequest {
            grant_type: "authorization_code".to_string(),
            team: Some("ops".to_string()),
            user: Some("alice@example.com".to_string()),
            redirect_uri: None,
            scopes: None,
            state: None,
        }),
    )
    .await
    .expect("blueprint");
    let (blueprint, _) = response_json(response).await;
    println!(
        "http-graph-blueprint:\n{}",
        serde_json::to_string_pretty(&blueprint).unwrap()
    );

    let response = get_scoped_provider::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "slack".to_string(),
        }),
        Query(ScopedQuery {
            team: None,
            user: None,
        }),
        State(ctx.clone()),
    )
    .await
    .expect("slack descriptor");
    let (slack_descriptor, _) = response_json(response).await;
    println!(
        "http-slack-descriptor:\n{}",
        serde_json::to_string_pretty(&slack_descriptor).unwrap()
    );

    let response = get_requirements::<EnvSecretsManager>(
        Path(ScopedProviderPath {
            tenant: "acme".to_string(),
            provider_id: "slack".to_string(),
        }),
        Query(ScopedQuery {
            team: None,
            user: None,
        }),
        State(ctx),
    )
    .await
    .expect("slack requirements");
    let (slack_requirements, _) = response_json(response).await;
    println!(
        "http-slack-requirements:\n{}",
        serde_json::to_string_pretty(&slack_requirements).unwrap()
    );
}
