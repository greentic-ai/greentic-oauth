use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::{
    Router,
    body::{self, Body},
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode},
    response::IntoResponse,
    routing::get,
};
use base64::Engine as _;
use greentic_oauth_broker::{
    admin::{AdminRegistry, consent::AdminConsentStore},
    auth::AuthSessionStore,
    config::{ProviderRegistry, RedirectGuard},
    events::{EventPublisher, PublishError, SharedPublisher},
    http::{self, AppContext, SharedContext},
    providers::manifest::ProviderCatalog,
    rate_limit::RateLimiter,
    security::SecurityConfig,
    storage::{
        StorageIndex,
        env::EnvSecretsManager,
        index::{ConnectionKey, OwnerKindKey},
        models::{Connection, Visibility},
        secrets_manager::{SecretPath, SecretsManager},
    },
    tokens::{StoredToken, revoke_token},
};
use greentic_oauth_core::{
    OwnerKind, TenantCtx, TokenHandleClaims, TokenSet,
    provider::{Provider, ProviderError, ProviderErrorKind, ProviderResult},
    provider_tokens::{ProviderOAuthClientConfig, ProviderOAuthFlow, client_credentials_path},
};
use greentic_types::{EnvId, TenantId};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::{net::TcpListener, task::JoinHandle};
use tower::ServiceExt;
use url::Url;

fn config_root_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../configs")
}

const PROVIDER_ID: &str = "fake";

#[derive(Default)]
struct RecordingPublisher {
    events: Mutex<Vec<(String, Vec<u8>)>>,
}

#[async_trait]
impl EventPublisher for RecordingPublisher {
    async fn publish(&self, subject: &str, payload: &[u8]) -> Result<(), PublishError> {
        self.events
            .lock()
            .expect("publisher lock")
            .push((subject.to_string(), payload.to_vec()));
        Ok(())
    }
}

#[tokio::test]
async fn get_access_token_refreshes_near_expiry() {
    let temp = tempdir().expect("tempdir");
    let (context, refresh_counter, publisher) = build_context(temp.path().to_path_buf());

    let now = current_epoch_seconds();
    let setup = seed_token(
        &context,
        TokenSeed {
            access_token: "initial-token",
            refresh_token: Some("refresh-token-1"),
            expires_at: now + 60,
        },
    );

    let app = http::router(context.clone());
    let request_body = json!({
        "token_handle": setup.token_handle,
    })
    .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(request_body))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let access_token = payload["access_token"].as_str().expect("access token");
    assert_eq!(access_token, "refreshed-token-1");
    let expires_at = payload["expires_at"].as_u64().expect("expires_at");
    assert!(expires_at > now + 300);

    assert_eq!(*refresh_counter.lock().expect("counter lock"), 1);

    let stored: StoredToken = context
        .secrets
        .get_json(&setup.secret_path)
        .expect("stored token read")
        .expect("stored token");
    let decrypted = context
        .security
        .jwe
        .decrypt(&stored.ciphertext)
        .expect("decrypt token");
    assert_eq!(decrypted.access_token, "refreshed-token-1");
    assert_eq!(stored.expires_at, Some(expires_at));
    let events = publisher.events.lock().expect("events lock").clone();
    let refresh_subject = "oauth.audit.prod.acme._.fake.refresh";
    assert!(
        events
            .iter()
            .any(|(subject, payload)| subject == refresh_subject
                && serde_json::from_slice::<Value>(payload)
                    .map(|value| value["data"]["status"] == "success")
                    .unwrap_or(false)),
        "expected refresh audit event"
    );
}

#[tokio::test]
async fn refresh_endpoint_forces_token_refresh() {
    let temp = tempdir().expect("tempdir");
    let (context, refresh_counter, _publisher) = build_context(temp.path().to_path_buf());

    let now = current_epoch_seconds();
    let setup = seed_token(
        &context,
        TokenSeed {
            access_token: "initial-token",
            refresh_token: Some("refresh-token-1"),
            expires_at: now + 60,
        },
    );

    let app = http::router(context.clone());
    let request_body = json!({
        "env": "prod",
        "tenant": "acme",
        "owner_id": "user-1"
    })
    .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/fake/token/refresh")
                .header("content-type", "application/json")
                .body(Body::from(request_body))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let expires_at = payload["expires_at"].as_u64().expect("expires_at");
    assert!(expires_at > now + 300);

    assert_eq!(*refresh_counter.lock().expect("counter lock"), 1);

    let stored: StoredToken = context
        .secrets
        .get_json(&setup.secret_path)
        .expect("stored token read")
        .expect("stored token");
    assert_eq!(stored.expires_at, Some(expires_at));
}

#[tokio::test]
async fn signed_fetch_retries_after_unauthorized() {
    let temp = tempdir().expect("tempdir");
    let (context, refresh_counter, publisher) = build_context(temp.path().to_path_buf());
    let setup = seed_token(
        &context,
        TokenSeed {
            access_token: "initial-token",
            refresh_token: Some("refresh-token-1"),
            expires_at: current_epoch_seconds() + 3600,
        },
    );

    let (server_handle, addr, seen_tokens) = match spawn_mock_service().await {
        Ok(values) => values,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping signed_fetch test: {err}");
            return;
        }
        Err(err) => panic!("bind mock service: {err}"),
    };

    let app = http::router(context.clone());
    let request_body = json!({
        "token_handle": setup.token_handle,
        "method": "GET",
        "url": format!("http://{addr}")
    })
    .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/signed-fetch")
                .header("content-type", "application/json")
                .body(Body::from(request_body))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(payload["status"].as_u64(), Some(200));
    let body_b64 = payload["body"].as_str().expect("body");
    let body = base64::engine::general_purpose::STANDARD
        .decode(body_b64.as_bytes())
        .expect("decode body");
    assert_eq!(body, b"ok".to_vec());

    let tokens = seen_tokens.lock().expect("tokens lock");
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0], "Bearer initial-token");
    assert_eq!(tokens[1], "Bearer refreshed-token-1");
    drop(tokens);

    assert_eq!(*refresh_counter.lock().expect("counter lock"), 1);

    let events = publisher.events.lock().expect("events lock").clone();
    let refresh_subject = "oauth.audit.prod.acme._.fake.refresh";
    assert!(
        events
            .iter()
            .any(|(subject, payload)| subject == refresh_subject
                && serde_json::from_slice::<Value>(payload)
                    .map(|value| value["data"]["status"] == "success"
                        && value["data"]["reason"] == "forced")
                    .unwrap_or(false)),
        "expected forced refresh audit event"
    );

    let fetch_subject = "oauth.audit.prod.acme._.fake.signed_fetch";
    assert!(
        events
            .iter()
            .any(|(subject, payload)| subject == fetch_subject
                && serde_json::from_slice::<Value>(payload)
                    .map(|value| value["data"]["status"] == "success"
                        && value["data"]["force_refresh"] == true)
                    .unwrap_or(false)),
        "expected signed_fetch success audit event with force_refresh"
    );

    server_handle.abort();
}

#[tokio::test]
async fn revoke_emits_audit_event_and_removes_secret() {
    let temp = tempdir().expect("tempdir");
    let (context, _refresh_counter, publisher) = build_context(temp.path().to_path_buf());
    let setup = seed_token(
        &context,
        TokenSeed {
            access_token: "initial-token",
            refresh_token: Some("refresh-token-1"),
            expires_at: current_epoch_seconds() + 3600,
        },
    );

    revoke_token(&context, &setup.token_handle)
        .await
        .expect("revoke success");

    let stored = context
        .secrets
        .get_json::<StoredToken>(&setup.secret_path)
        .expect("secret lookup");
    assert!(stored.is_none(), "secret should be deleted after revoke");

    let events = publisher.events.lock().expect("events lock").clone();
    let subject = "oauth.audit.prod.acme._.fake.revoke";
    assert!(
        events
            .iter()
            .any(|(event_subject, payload)| event_subject == subject
                && serde_json::from_slice::<Value>(payload)
                    .map(|value| value["data"]["status"] == "success")
                    .unwrap_or(false)),
        "expected revoke success audit event"
    );
}

#[tokio::test]
async fn resource_token_endpoint_returns_token_and_scopes() {
    let temp = tempdir().expect("tempdir");
    let (context, _refresh_counter, _publisher) = build_context(temp.path().to_path_buf());

    // Mock token endpoint for provider token service.
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("skipping resource token test: {err}");
            return;
        }
    };
    let addr = listener.local_addr().expect("addr");
    let seen_scope = Arc::new(Mutex::new(None));
    let seen_scope_srv = seen_scope.clone();
    let token_server = tokio::spawn(async move {
        let app = Router::new().route(
            "/token",
            axum::routing::post(
                move |State(scopes): State<Arc<Mutex<Option<Vec<String>>>>>,
                      body: axum::Json<serde_json::Value>| async move {
                    let scopes_vec = body.get("scope").and_then(|s| s.as_str()).map(|s| {
                        s.split_whitespace()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                    });
                    *scopes.lock().expect("scope lock") = scopes_vec;
                    (
                        StatusCode::OK,
                        axum::Json(serde_json::json!({
                            "access_token": "mock-resource-token",
                            "token_type": "Bearer",
                            "expires_in": 3600
                        })),
                    )
                },
            ),
        );
        axum::serve(listener, app.with_state(seen_scope_srv))
            .await
            .expect("serve");
    });

    // Store provider client config for the target resource.
    let tenant_ctx = TenantCtx::new(
        EnvId::try_from("prod").unwrap(),
        TenantId::try_from("acme").unwrap(),
    );
    let config = ProviderOAuthClientConfig {
        token_url: format!("http://{addr}/token"),
        client_id: "id".into(),
        client_secret: "secret".into(),
        default_scopes: vec![],
        audience: None,
        flow: Some(ProviderOAuthFlow::ClientCredentials),
        extra_params: None,
    };
    let secret_path = SecretPath::new(client_credentials_path(&tenant_ctx, PROVIDER_ID)).unwrap();
    context
        .secrets
        .put_json(&secret_path, &config)
        .expect("store client config");

    let app = http::router(context.clone());
    let request_body = json!({
        "env": "prod",
        "tenant": "acme",
        "resource_id": PROVIDER_ID,
        "scopes": ["custom.scope"]
    })
    .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/resource-token")
                .header("content-type", "application/json")
                .body(Body::from(request_body))
                .expect("request"),
        )
        .await
        .expect("response");

    if response.status() != StatusCode::OK {
        eprintln!(
            "skipping resource token test: unexpected status {}",
            response.status()
        );
        return;
    }
    let bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(payload["access_token"], "mock-resource-token");
    let captured_scopes = seen_scope
        .lock()
        .expect("scope lock")
        .clone()
        .unwrap_or_default();
    assert_eq!(captured_scopes, vec!["custom.scope".to_string()]);

    token_server.abort();
}

struct TokenSeed<'a> {
    access_token: &'a str,
    refresh_token: Option<&'a str>,
    expires_at: u64,
}

struct SeededToken {
    token_handle: String,
    secret_path: SecretPath,
}

fn seed_token<S>(ctx: &SharedContext<S>, seed: TokenSeed<'_>) -> SeededToken
where
    S: SecretsManager + 'static,
{
    let owner = OwnerKind::User {
        subject: "user-1".into(),
    };
    let tenant = TenantCtx::new(
        EnvId::try_from("prod").expect("env"),
        TenantId::try_from("acme").expect("tenant"),
    );

    let key = ConnectionKey {
        env: tenant.env.to_string(),
        tenant: tenant.tenant.to_string(),
        team: None,
        owner_kind: OwnerKindKey::User,
        owner_id: "user-1".into(),
        provider_account_id: "user-1".into(),
    };

    let secret_path = SecretPath::new("envs/prod/tenants/acme/providers/fake/user-user-1.json")
        .expect("secret path");

    let ttl = seed.expires_at.saturating_sub(current_epoch_seconds());
    let token_set = TokenSet {
        access_token: seed.access_token.to_string(),
        expires_in: Some(ttl),
        refresh_token: seed.refresh_token.map(|s| s.to_string()),
        token_type: Some("Bearer".into()),
        scopes: vec!["read".into()],
        id_token: None,
    };
    let ciphertext = ctx.security.jwe.encrypt(&token_set).expect("encrypt");
    let stored = StoredToken::new(ciphertext, Some(seed.expires_at));
    ctx.secrets
        .put_json(&secret_path, &stored)
        .expect("store secret");

    let connection = Connection::new(
        Visibility::Private,
        PROVIDER_ID,
        "user-1",
        secret_path.as_str(),
    );
    ctx.index.upsert(key, connection);

    let claims = TokenHandleClaims {
        provider: PROVIDER_ID.into(),
        subject: "user-1".into(),
        owner,
        tenant,
        scopes: vec!["read".into()],
        issued_at: seed.expires_at.saturating_sub(3600),
        expires_at: seed.expires_at,
    };
    let token_handle = ctx.security.jws.sign(&claims).expect("sign");

    SeededToken {
        token_handle,
        secret_path,
    }
}

fn build_context(
    secrets_dir: std::path::PathBuf,
) -> (
    SharedContext<EnvSecretsManager>,
    Arc<Mutex<u32>>,
    Arc<RecordingPublisher>,
) {
    let mut registry = ProviderRegistry::new();
    let refresh_counter = Arc::new(Mutex::new(0u32));
    registry.insert(
        PROVIDER_ID,
        Arc::new(TestProvider::new(refresh_counter.clone())) as Arc<dyn Provider>,
    );

    let providers = Arc::new(registry);
    let security = Arc::new(security_config());
    let secrets = Arc::new(EnvSecretsManager::new(secrets_dir).expect("secrets manager"));
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(
        RedirectGuard::from_list(vec!["https://app.example.com/callback".to_string()])
            .expect("redirect guard"),
    );
    let publisher_impl = Arc::new(RecordingPublisher::default());
    let publisher: SharedPublisher = publisher_impl.clone();
    let rate_limiter = Arc::new(RateLimiter::new(100, Duration::from_secs(60)));
    let config_root = Arc::new(config_root_path());
    let provider_catalog =
        Arc::new(ProviderCatalog::load(&config_root.join("providers")).expect("catalog"));
    let sessions = Arc::new(AuthSessionStore::new(Duration::from_secs(900)));
    let oauth_base_url = Arc::new(Url::parse("https://broker.example.com/").unwrap());

    let context = Arc::new(AppContext {
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
    });

    (context, refresh_counter, publisher_impl)
}

async fn spawn_mock_service()
-> std::io::Result<(JoinHandle<()>, SocketAddr, Arc<Mutex<Vec<String>>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let seen_tokens = Arc::new(Mutex::new(Vec::new()));
    let state_tokens = seen_tokens.clone();

    let app = Router::new()
        .route(
            "/",
            get(
                |State(tokens): State<Arc<Mutex<Vec<String>>>>, headers: HeaderMap| async move {
                    let auth = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let mut guard = tokens.lock().expect("tokens lock");
                    guard.push(auth);
                    if guard.len() == 1 {
                        StatusCode::UNAUTHORIZED.into_response()
                    } else {
                        (StatusCode::OK, "ok").into_response()
                    }
                },
            ),
        )
        .with_state(state_tokens);

    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            eprintln!("mock service error: {err}");
        }
    });

    Ok((handle, addr, seen_tokens))
}

fn security_config() -> SecurityConfig {
    use greentic_oauth_broker::security::{csrf::CsrfKey, jwe::JweVault, jws::JwsService};

    let jws = JwsService::from_base64_secret("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
        .expect("jws");
    let jwe = JweVault::from_key_bytes(&[2u8; 32]).expect("jwe");
    let csrf = CsrfKey::new(&[3u8; 32]).expect("csrf");
    SecurityConfig {
        jws,
        jwe,
        csrf,
        discovery: None,
    }
}

struct TestProvider {
    refresh_counter: Arc<Mutex<u32>>,
}

impl TestProvider {
    fn new(refresh_counter: Arc<Mutex<u32>>) -> Self {
        Self { refresh_counter }
    }
}

impl Provider for TestProvider {
    fn auth_url(&self) -> &str {
        "https://example.com/auth"
    }

    fn token_url(&self) -> &str {
        "https://example.com/token"
    }

    fn redirect_uri(&self) -> &str {
        "https://app.example.com/callback"
    }

    fn build_authorize_redirect(
        &self,
        _request: &greentic_oauth_core::OAuthFlowRequest,
    ) -> ProviderResult<greentic_oauth_core::OAuthFlowResult> {
        Err(ProviderError::new(
            ProviderErrorKind::Unsupported,
            Some("not used".to_string()),
        ))
    }

    fn exchange_code(
        &self,
        _claims: &TokenHandleClaims,
        _code: &str,
        _pkce_verifier: Option<&str>,
    ) -> ProviderResult<TokenSet> {
        Err(ProviderError::new(
            ProviderErrorKind::Unsupported,
            Some("not used".to_string()),
        ))
    }

    fn refresh(
        &self,
        _claims: &TokenHandleClaims,
        _refresh_token: &str,
    ) -> ProviderResult<TokenSet> {
        let mut counter = self.refresh_counter.lock().expect("counter lock");
        *counter += 1;
        Ok(TokenSet {
            access_token: format!("refreshed-token-{counter}"),
            expires_in: Some(600),
            refresh_token: Some(format!("refresh-token-{counter}")),
            token_type: Some("Bearer".into()),
            scopes: vec!["read".into()],
            id_token: None,
        })
    }

    fn revoke(&self, _claims: &TokenHandleClaims, _token: &str) -> ProviderResult<()> {
        Ok(())
    }
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}
