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
};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::{net::TcpListener, task::JoinHandle};
use tower::ServiceExt;

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
    let tenant = TenantCtx {
        env: "prod".into(),
        tenant: "acme".into(),
        team: None,
    };

    let key = ConnectionKey {
        env: tenant.env.clone(),
        tenant: tenant.tenant.clone(),
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

    fn exchange_code(&self, _claims: &TokenHandleClaims, _code: &str) -> ProviderResult<TokenSet> {
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
