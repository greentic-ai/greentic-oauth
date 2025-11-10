use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::body::{self, Body};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use hyper::{Method, Request};

use greentic_oauth_broker::{
    auth::AuthSessionStore,
    config::{ProviderRegistry, RedirectGuard},
    events::{EventPublisher, NoopPublisher, PublishError, SharedPublisher},
    http::{
        AppContext, SharedContext,
        handlers::{
            callback::{self, CallbackQuery},
            initiate::{self, StartPath, StartQuery},
            status::{self, StatusPath, StatusQuery},
        },
        state::FlowState,
    },
    providers::manifest::{ManifestContext, ProviderCatalog},
    rate_limit::RateLimiter,
    security::{SecurityConfig, csrf::CsrfKey, jwe::JweVault, jws::JwsService},
    storage::{
        StorageIndex, env::EnvSecretsManager, index::ConnectionKey, secrets_manager::SecretsManager,
    },
};
use greentic_oauth_core::{
    provider::{Provider, ProviderError, ProviderErrorKind, ProviderResult},
    types::{OAuthFlowRequest, OAuthFlowResult, OwnerKind, TokenHandleClaims, TokenSet},
};
use serde::Deserialize;
use tempfile::tempdir;
use tower::ServiceExt;
use url::Url;

fn config_root_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../configs")
}

#[derive(Default)]
struct TestPublisher {
    events: Mutex<Vec<(String, Vec<u8>)>>,
}

#[async_trait]
impl EventPublisher for TestPublisher {
    async fn publish(&self, subject: &str, payload: &[u8]) -> Result<(), PublishError> {
        self.events
            .lock()
            .expect("publisher lock")
            .push((subject.to_string(), payload.to_vec()));
        Ok(())
    }
}

struct FakeProvider {
    auth_url: String,
    token_url: String,
    redirect_uri: String,
    expected_code: String,
    response: TokenSet,
    requests: Mutex<Vec<OAuthFlowRequest>>,
}

impl FakeProvider {
    fn new() -> Self {
        Self {
            auth_url: "https://fake.provider/oauth/authorize".to_string(),
            token_url: "https://fake.provider/oauth/token".to_string(),
            redirect_uri: "https://broker.example.com/callback".to_string(),
            expected_code: "authcode".to_string(),
            response: TokenSet {
                access_token: "token-abc".to_string(),
                expires_in: Some(3600),
                refresh_token: Some("refresh-xyz".to_string()),
                token_type: Some("Bearer".to_string()),
                scopes: vec!["read".to_string(), "offline_access".to_string()],
                id_token: None,
            },
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl Provider for FakeProvider {
    fn auth_url(&self) -> &str {
        &self.auth_url
    }

    fn token_url(&self) -> &str {
        &self.token_url
    }

    fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    fn build_authorize_redirect(
        &self,
        request: &OAuthFlowRequest,
    ) -> ProviderResult<OAuthFlowResult> {
        self.requests
            .lock()
            .expect("request lock")
            .push(request.clone());

        let mut url = Url::parse(&self.auth_url).unwrap();
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(state) = &request.state {
                pairs.append_pair("state", state);
            }
            if let Some(challenge) = &request.code_challenge {
                pairs.append_pair("code_challenge", challenge);
            }
        }

        Ok(OAuthFlowResult {
            redirect_url: url.to_string(),
            state: request.state.clone(),
            scopes: request.scopes.clone(),
        })
    }

    fn exchange_code(
        &self,
        _claims: &TokenHandleClaims,
        code: &str,
        _pkce_verifier: Option<&str>,
    ) -> ProviderResult<TokenSet> {
        if code != self.expected_code {
            return Err(ProviderError::new(
                ProviderErrorKind::Authorization,
                "unexpected authorization code".to_string(),
            ));
        }
        Ok(self.response.clone())
    }

    fn refresh(
        &self,
        _claims: &TokenHandleClaims,
        _refresh_token: &str,
    ) -> ProviderResult<TokenSet> {
        Err(ProviderError::new(
            ProviderErrorKind::Unsupported,
            "not implemented".to_string(),
        ))
    }

    fn revoke(&self, _claims: &TokenHandleClaims, _token: &str) -> ProviderResult<()> {
        Ok(())
    }
}

fn security_config() -> SecurityConfig {
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

fn happy_path_context() -> (
    SharedContext<EnvSecretsManager>,
    Arc<TestPublisher>,
    Arc<SecurityConfig>,
) {
    let mut registry = ProviderRegistry::new();
    let fake_provider = Arc::new(FakeProvider::new());
    registry.insert("fake", fake_provider.clone() as Arc<dyn Provider>);
    let provider_registry = Arc::new(registry);

    let security = Arc::new(security_config());
    let secrets =
        Arc::new(EnvSecretsManager::new(tempdir().unwrap().path().to_path_buf()).unwrap());
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(
        RedirectGuard::from_list(vec!["https://app.example.com/success".to_string()]).unwrap(),
    );
    let publisher_impl = Arc::new(TestPublisher::default());
    let publisher: SharedPublisher = publisher_impl.clone() as SharedPublisher;
    let rate_limiter = Arc::new(RateLimiter::new(100, Duration::from_secs(60)));
    let config_root = Arc::new(config_root_path());
    let provider_catalog = Arc::new(ProviderCatalog::load(&config_root.join("providers")).unwrap());

    let context = build_context(
        provider_registry,
        security.clone(),
        secrets,
        index,
        redirect_guard,
        publisher,
        rate_limiter,
        config_root,
        provider_catalog,
        true,
        false,
    );

    (context, publisher_impl, security)
}

#[allow(clippy::too_many_arguments)]
fn build_context(
    provider_registry: Arc<ProviderRegistry>,
    security: Arc<SecurityConfig>,
    secrets: Arc<EnvSecretsManager>,
    index: Arc<StorageIndex>,
    redirect_guard: Arc<RedirectGuard>,
    publisher: SharedPublisher,
    rate_limiter: Arc<RateLimiter>,
    config_root: Arc<PathBuf>,
    provider_catalog: Arc<ProviderCatalog>,
    allow_insecure: bool,
    enable_test_endpoints: bool,
) -> SharedContext<EnvSecretsManager> {
    let sessions = Arc::new(AuthSessionStore::new(Duration::from_secs(900)));
    let oauth_base_url = Arc::new(Url::parse("https://broker.example.com/").unwrap());
    Arc::new(AppContext {
        providers: provider_registry,
        security,
        secrets,
        index,
        redirect_guard,
        publisher,
        rate_limiter,
        config_root,
        provider_catalog,
        allow_insecure,
        allow_extra_params: true,
        enable_test_endpoints,
        sessions,
        oauth_base_url: Some(oauth_base_url),
    })
}

#[tokio::test]
async fn start_to_callback_happy_path() {
    let (context, publisher_impl, security) = happy_path_context();
    let secrets = context.secrets.clone();
    let index = context.index.clone();

    let start_response = initiate::start::<EnvSecretsManager>(
        Path(StartPath {
            env: "prod".into(),
            tenant: "acme".into(),
            provider: "fake".into(),
        }),
        Query(StartQuery {
            team: Some("platform".into()),
            owner_kind: "user".into(),
            owner_id: "user-1".into(),
            flow_id: "flow-123".into(),
            scopes: Some("read,offline_access".into()),
            redirect_uri: Some("https://app.example.com/success".into()),
            visibility: Some("team".into()),
            preset: None,
            prompt: None,
            extra: BTreeMap::new(),
        }),
        HeaderMap::new(),
        State(context.clone()),
    )
    .await
    .expect("start")
    .into_response();

    assert_eq!(start_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = start_response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let redirect_url = Url::parse(&location).unwrap();
    let state_param = redirect_url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.to_string())
        .expect("state param");

    let callback_response = callback::complete::<EnvSecretsManager>(
        Query(CallbackQuery {
            code: Some("authcode".into()),
            state: Some(state_param.clone()),
            error: None,
        }),
        HeaderMap::new(),
        State(context.clone()),
    )
    .await
    .expect("callback")
    .into_response();

    assert_eq!(callback_response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        callback_response.headers().get("location").unwrap(),
        "https://app.example.com/success"
    );

    let state_payload = security
        .csrf
        .open("state", &state_param)
        .expect("state payload");
    let flow_state: FlowState = serde_json::from_str(&state_payload).unwrap();
    let secret_path = flow_state.secret_path().unwrap();

    let stored: StoredTokenEnvelope = secrets
        .get_json(&secret_path)
        .unwrap()
        .expect("stored secret");
    let decrypted = security.jwe.decrypt(&stored.ciphertext).unwrap();
    assert!(stored.expires_at.is_some());
    assert_eq!(decrypted.access_token, "token-abc");
    assert_eq!(decrypted.refresh_token.as_deref(), Some("refresh-xyz"));

    let owner = OwnerKind::User {
        subject: flow_state.owner_id.clone(),
    };
    let key = ConnectionKey::from_owner(
        flow_state.env.clone(),
        flow_state.tenant.clone(),
        flow_state.team.clone(),
        &owner,
        flow_state.owner_id.clone(),
    );
    let connection = index.get(&flow_state.provider, &key).expect("connection");
    assert_eq!(connection.path, secret_path.as_str());

    {
        let events = publisher_impl.events.lock().unwrap();
        assert_eq!(events.len(), 4);
        let mut events_map: HashMap<&str, &[u8]> = HashMap::new();
        for (subject, payload) in events.iter() {
            events_map.insert(subject.as_str(), payload.as_slice());
        }

        let started_subject = "oauth.audit.prod.acme.platform.fake.started";
        let started_payload = events_map
            .get(started_subject)
            .expect("started audit event present");
        let started_json: serde_json::Value =
            serde_json::from_slice(started_payload).expect("started payload");
        assert_eq!(started_json["action"], "started");
        assert_eq!(started_json["data"]["flow_id"], "flow-123");
        assert_eq!(started_json["data"]["owner_kind"], "user");

        let res_subject = "oauth.res.acme.prod.platform.fake.flow-123";
        let res_payload = events_map
            .get(res_subject)
            .expect("callback result event present");
        let event: CallbackEventPayload = serde_json::from_slice(res_payload).unwrap();
        assert_eq!(event.flow_id, "flow-123");
        assert_eq!(event.token_handle.provider, "fake");
        assert_eq!(event.token_handle.subject, flow_state.owner_id);
        assert_eq!(event.storage_path, secret_path.as_str());

        let success_subject = "oauth.audit.prod.acme.platform.fake.callback_success";
        let success_payload = events_map
            .get(success_subject)
            .expect("callback success audit event present");
        let success_json: serde_json::Value =
            serde_json::from_slice(success_payload).expect("success payload");
        assert_eq!(success_json["action"], "callback_success");
        assert_eq!(success_json["data"]["flow_id"], "flow-123");
        assert_eq!(success_json["data"]["storage_path"], secret_path.as_str());

        let auth_success_payload = events_map
            .get("auth.success")
            .expect("auth success event present");
        let auth_success: serde_json::Value =
            serde_json::from_slice(auth_success_payload).expect("auth success payload");
        assert_eq!(auth_success["tenant"], "acme");
        assert_eq!(auth_success["provider"], "fake");
        assert_eq!(auth_success["user"], flow_state.owner_id);
    }

    let status = status::get_status::<EnvSecretsManager>(
        Path(StatusPath {
            env: "prod".into(),
            tenant: "acme".into(),
            provider: "fake".into(),
        }),
        Query(StatusQuery {
            team: Some("platform".into()),
        }),
        State(context.clone()),
    )
    .await
    .expect("status");
    assert_eq!(status.0.len(), 1);
}

#[tokio::test]
async fn oauth_start_api_returns_session_url() {
    let (context, _publisher, _security) = happy_path_context();
    let app = greentic_oauth_broker::http::router(context.clone());

    let payload = serde_json::json!({
        "env": "prod",
        "tenant": "acme",
        "provider": "fake",
        "team": "platform",
        "owner_kind": "user",
        "owner_id": "user-1",
        "flow_id": "flow-api-1",
        "scopes": ["read"],
        "redirect_uri": "https://app.example.com/success",
        "visibility": "tenant"
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/start")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .expect("start response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let start: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let start_url = start
        .get("start_url")
        .and_then(|value| value.as_str())
        .expect("start_url");
    let parsed = Url::parse(start_url).expect("start url");
    assert!(
        parsed
            .as_str()
            .starts_with("https://broker.example.com/authorize/"),
        "start_url {start_url} should point to authorize route"
    );
    let session_id = parsed
        .path()
        .trim_start_matches('/')
        .trim_start_matches("authorize/")
        .to_string();
    assert!(
        !session_id.is_empty(),
        "session id should be part of the authorize path"
    );

    let authorize = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/authorize/{session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("authorize response");
    assert_eq!(authorize.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = authorize
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|value: &HeaderValue| value.to_str().ok())
        .expect("location header");
    assert!(
        location.starts_with("https://fake.provider"),
        "authorize redirect should target the provider"
    );
}

#[tokio::test]
async fn start_api_response_snapshot() {
    let (context, _publisher, _security) = happy_path_context();
    let app = greentic_oauth_broker::http::router(context.clone());
    let payload = serde_json::json!({
        "env": "prod",
        "tenant": "acme",
        "provider": "fake",
        "team": "platform",
        "owner_kind": "user",
        "owner_id": "user-1",
        "flow_id": "flow-snap",
        "redirect_uri": "https://app.example.com/success",
        "visibility": "tenant",
        "preset": "microsoft"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/start")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .expect("start response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    if let Some(url_value) = value.get_mut("start_url") {
        if let Some(url_str) = url_value.as_str() {
            assert!(url_str.starts_with("https://broker.example.com/authorize/"));
        }
        *url_value =
            serde_json::Value::String("https://broker.example.com/authorize/{session}".into());
    }
    insta::assert_json_snapshot!("oauth_start_response", value);
}

#[derive(Deserialize)]
struct StoredTokenEnvelope {
    ciphertext: String,
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct CallbackEventPayload {
    flow_id: String,
    token_handle: TokenHandleClaims,
    storage_path: String,
}

#[tokio::test]
async fn callback_state_validation_failure() {
    let mut registry = ProviderRegistry::new();
    let fake_provider = Arc::new(FakeProvider::new());
    registry.insert("fake", fake_provider.clone() as Arc<dyn Provider>);
    let provider_registry = Arc::new(registry);

    let security = Arc::new(security_config());
    let secrets =
        Arc::new(EnvSecretsManager::new(tempdir().unwrap().path().to_path_buf()).unwrap());
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(
        RedirectGuard::from_list(vec!["https://app.example.com/success".to_string()]).unwrap(),
    );
    let publisher_impl = Arc::new(TestPublisher::default());
    let publisher: SharedPublisher = publisher_impl.clone() as SharedPublisher;
    let rate_limiter = Arc::new(RateLimiter::new(100, Duration::from_secs(60)));
    let config_root = Arc::new(config_root_path());
    let provider_catalog = Arc::new(ProviderCatalog::load(&config_root.join("providers")).unwrap());

    let context = build_context(
        provider_registry,
        security.clone(),
        secrets,
        index,
        redirect_guard,
        publisher,
        rate_limiter,
        config_root.clone(),
        provider_catalog,
        true,
        false,
    );

    let response = callback::complete::<EnvSecretsManager>(
        Query(CallbackQuery {
            code: Some("authcode".into()),
            state: Some("invalid-state-token".into()),
            error: None,
        }),
        HeaderMap::new(),
        State(context.clone()),
    )
    .await;

    assert!(response.is_err());

    let events = publisher_impl.events.lock().unwrap();
    let error_subject = "oauth.audit.unknown.unknown._.unknown.callback_error";
    assert!(
        events.iter().any(|(subject, _)| subject == error_subject),
        "expected callback_error audit event"
    );
}

#[tokio::test]
async fn start_populates_scopes_from_manifest_when_missing() {
    let mut registry = ProviderRegistry::new();
    let mut provider = FakeProvider::new();
    provider.redirect_uri = "https://localhost:8080/callback".to_string();
    let custom_provider = Arc::new(provider);
    registry.insert(
        "microsoft-graph",
        custom_provider.clone() as Arc<dyn Provider>,
    );
    let provider_registry = Arc::new(registry);

    let security = Arc::new(security_config());
    let secrets =
        Arc::new(EnvSecretsManager::new(tempdir().unwrap().path().to_path_buf()).unwrap());
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(
        RedirectGuard::from_list(vec!["https://app.example.com/success".to_string()]).unwrap(),
    );
    let publisher: SharedPublisher = Arc::new(TestPublisher::default());
    let rate_limiter = Arc::new(RateLimiter::new(100, Duration::from_secs(60)));
    let config_root = Arc::new(config_root_path());
    let provider_catalog = Arc::new(ProviderCatalog::load(&config_root.join("providers")).unwrap());

    let context = build_context(
        provider_registry,
        security,
        secrets,
        index,
        redirect_guard,
        publisher,
        rate_limiter,
        config_root.clone(),
        provider_catalog.clone(),
        true,
        false,
    );

    initiate::start::<EnvSecretsManager>(
        Path(StartPath {
            env: "prod".into(),
            tenant: "acme".into(),
            provider: "microsoft-graph".into(),
        }),
        Query(StartQuery {
            team: None,
            owner_kind: "user".into(),
            owner_id: "user-1".into(),
            flow_id: "flow-001".into(),
            scopes: None,
            redirect_uri: Some("https://app.example.com/success".into()),
            visibility: None,
            preset: None,
            prompt: None,
            extra: BTreeMap::new(),
        }),
        HeaderMap::new(),
        State(context),
    )
    .await
    .expect("start request");

    let recorded = custom_provider.requests.lock().expect("requests lock");
    let captured = recorded.first().expect("request captured");
    let manifest_ctx = ManifestContext::new("acme", "microsoft-graph", None, None);
    let manifest_scopes = provider_catalog
        .resolve("microsoft-graph", &manifest_ctx)
        .expect("manifest")
        .scopes;
    assert_eq!(captured.scopes, manifest_scopes);
}

#[tokio::test]
async fn start_rate_limit_enforced() {
    let mut registry = ProviderRegistry::new();
    let fake_provider = Arc::new(FakeProvider::new());
    registry.insert("fake", fake_provider.clone() as Arc<dyn Provider>);
    let provider_registry = Arc::new(registry);

    let security = Arc::new(security_config());
    let secrets =
        Arc::new(EnvSecretsManager::new(tempdir().unwrap().path().to_path_buf()).unwrap());
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(
        RedirectGuard::from_list(vec!["https://app.example.com/success".to_string()]).unwrap(),
    );
    let publisher_impl = Arc::new(TestPublisher::default());
    let publisher: SharedPublisher = publisher_impl.clone() as SharedPublisher;
    let rate_limiter = Arc::new(RateLimiter::new(1, Duration::from_secs(60)));
    let config_root = Arc::new(config_root_path());
    let provider_catalog = Arc::new(ProviderCatalog::load(&config_root.join("providers")).unwrap());

    let context = build_context(
        provider_registry,
        security,
        secrets,
        index,
        redirect_guard,
        publisher,
        rate_limiter,
        config_root.clone(),
        provider_catalog,
        true,
        false,
    );

    initiate::start::<EnvSecretsManager>(
        Path(StartPath {
            env: "prod".into(),
            tenant: "acme".into(),
            provider: "fake".into(),
        }),
        Query(StartQuery {
            team: None,
            owner_kind: "user".into(),
            owner_id: "user-1".into(),
            flow_id: "flow-123".into(),
            scopes: None,
            redirect_uri: None,
            visibility: None,
            preset: None,
            prompt: None,
            extra: BTreeMap::new(),
        }),
        HeaderMap::new(),
        State(context.clone()),
    )
    .await
    .expect("first start under limit");

    let second = initiate::start::<EnvSecretsManager>(
        Path(StartPath {
            env: "prod".into(),
            tenant: "acme".into(),
            provider: "fake".into(),
        }),
        Query(StartQuery {
            team: None,
            owner_kind: "user".into(),
            owner_id: "user-1".into(),
            flow_id: "flow-124".into(),
            scopes: None,
            redirect_uri: None,
            visibility: None,
            preset: None,
            prompt: None,
            extra: BTreeMap::new(),
        }),
        HeaderMap::new(),
        State(context.clone()),
    )
    .await;

    let err = match second {
        Ok(_) => panic!("second start should be rate limited"),
        Err(err) => err,
    };
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    let events = publisher_impl.events.lock().unwrap();
    let started_subject = "oauth.audit.prod.acme._.fake.started";
    assert_eq!(
        events
            .iter()
            .filter(|(subject, _)| subject == started_subject)
            .count(),
        1,
        "only one started event expected"
    );
}

#[tokio::test]
async fn start_rejects_insecure_without_forwarded_proto() {
    let mut registry = ProviderRegistry::new();
    let fake_provider = Arc::new(FakeProvider::new());
    registry.insert("fake", fake_provider.clone() as Arc<dyn Provider>);
    let provider_registry = Arc::new(registry);

    let security = Arc::new(security_config());
    let secrets =
        Arc::new(EnvSecretsManager::new(tempdir().unwrap().path().to_path_buf()).unwrap());
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(
        RedirectGuard::from_list(vec!["https://app.example.com/success".to_string()]).unwrap(),
    );
    let publisher: SharedPublisher = Arc::new(TestPublisher::default());
    let rate_limiter = Arc::new(RateLimiter::new(100, Duration::from_secs(60)));
    let config_root = Arc::new(config_root_path());
    let provider_catalog = Arc::new(ProviderCatalog::load(&config_root.join("providers")).unwrap());

    let context = build_context(
        provider_registry,
        security,
        secrets,
        index,
        redirect_guard,
        publisher,
        rate_limiter,
        config_root.clone(),
        provider_catalog,
        false,
        false,
    );

    let insecure = initiate::start::<EnvSecretsManager>(
        Path(StartPath {
            env: "prod".into(),
            tenant: "acme".into(),
            provider: "fake".into(),
        }),
        Query(StartQuery {
            team: None,
            owner_kind: "user".into(),
            owner_id: "user-1".into(),
            flow_id: "flow-https".into(),
            scopes: None,
            redirect_uri: Some("https://app.example.com/success".into()),
            visibility: None,
            preset: None,
            prompt: None,
            extra: BTreeMap::new(),
        }),
        HeaderMap::new(),
        State(context.clone()),
    )
    .await;

    let status = match insecure {
        Ok(_) => panic!("plain http should be rejected"),
        Err(err) => err.into_response().status(),
    };
    assert_eq!(status, StatusCode::FORBIDDEN);

    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    initiate::start::<EnvSecretsManager>(
        Path(StartPath {
            env: "prod".into(),
            tenant: "acme".into(),
            provider: "fake".into(),
        }),
        Query(StartQuery {
            team: None,
            owner_kind: "user".into(),
            owner_id: "user-1".into(),
            flow_id: "flow-https".into(),
            scopes: None,
            redirect_uri: Some("https://app.example.com/success".into()),
            visibility: None,
            preset: None,
            prompt: None,
            extra: BTreeMap::new(),
        }),
        headers,
        State(context),
    )
    .await
    .expect("https proto should pass");
}

#[tokio::test]
async fn callback_rate_limit_enforced() {
    let mut registry = ProviderRegistry::new();
    let fake_provider = Arc::new(FakeProvider::new());
    registry.insert("fake", fake_provider.clone() as Arc<dyn Provider>);
    let provider_registry = Arc::new(registry);

    let security = Arc::new(security_config());
    let secrets =
        Arc::new(EnvSecretsManager::new(tempdir().unwrap().path().to_path_buf()).unwrap());
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(
        RedirectGuard::from_list(vec!["https://app.example.com/success".to_string()]).unwrap(),
    );
    let publisher_impl = Arc::new(TestPublisher::default());
    let publisher: SharedPublisher = publisher_impl.clone() as SharedPublisher;
    let rate_limiter = Arc::new(RateLimiter::new(2, Duration::from_secs(60)));
    let config_root = Arc::new(config_root_path());
    let provider_catalog = Arc::new(ProviderCatalog::load(&config_root.join("providers")).unwrap());

    let context = build_context(
        provider_registry,
        security.clone(),
        secrets,
        index,
        redirect_guard,
        publisher,
        rate_limiter.clone(),
        config_root.clone(),
        provider_catalog.clone(),
        true,
        false,
    );

    let start_response = initiate::start::<EnvSecretsManager>(
        Path(StartPath {
            env: "prod".into(),
            tenant: "acme".into(),
            provider: "fake".into(),
        }),
        Query(StartQuery {
            team: None,
            owner_kind: "user".into(),
            owner_id: "user-1".into(),
            flow_id: "flow-999".into(),
            scopes: None,
            redirect_uri: None,
            visibility: None,
            preset: None,
            prompt: None,
            extra: BTreeMap::new(),
        }),
        HeaderMap::new(),
        State(context.clone()),
    )
    .await
    .expect("start");

    let location = start_response
        .into_response()
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let state_param = Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .expect("state");

    callback::complete::<EnvSecretsManager>(
        Query(CallbackQuery {
            code: Some("authcode".into()),
            state: Some(state_param.clone()),
            error: None,
        }),
        HeaderMap::new(),
        State(context.clone()),
    )
    .await
    .expect("first callback");

    let second = callback::complete::<EnvSecretsManager>(
        Query(CallbackQuery {
            code: Some("authcode".into()),
            state: Some(state_param.clone()),
            error: None,
        }),
        HeaderMap::new(),
        State(context.clone()),
    )
    .await;

    let err = match second {
        Ok(_) => panic!("second callback should be rate limited"),
        Err(err) => err,
    };
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    let events = publisher_impl.events.lock().unwrap();
    let error_subject = "oauth.audit.prod.acme._.fake.callback_error";
    assert!(
        events
            .iter()
            .any(|(subject, payload)| subject == error_subject
                && serde_json::from_slice::<serde_json::Value>(payload)
                    .map(|value| value["data"]["reason"] == "rate_limited")
                    .unwrap_or(false)),
        "expected callback_error audit event with rate_limited reason"
    );
}

#[tokio::test]
async fn test_endpoints_disabled_return_404() {
    let temp = tempdir().expect("tempdir");
    let secrets_dir = temp.path().to_path_buf();
    let context = build_context(
        Arc::new(ProviderRegistry::new()),
        Arc::new(security_config()),
        Arc::new(EnvSecretsManager::new(secrets_dir.join("secrets")).unwrap()),
        Arc::new(StorageIndex::new()),
        Arc::new(RedirectGuard::from_env().unwrap()),
        Arc::new(NoopPublisher),
        Arc::new(RateLimiter::new(60, Duration::from_secs(60))),
        Arc::new(config_root_path()),
        Arc::new(ProviderCatalog::load(&config_root_path().join("providers")).unwrap()),
        true,
        false,
    );
    let router = greentic_oauth_broker::http::router(context);
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/_test/refresh")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_endpoints_refresh_and_signed_fetch() {
    let mut registry = ProviderRegistry::new();
    registry.insert(
        "fake".to_string(),
        Arc::new(FakeProvider::new()) as Arc<dyn Provider>,
    );

    let temp = tempdir().expect("tempdir");
    let secrets_dir = temp.path().to_path_buf();
    let context = build_context(
        Arc::new(registry),
        Arc::new(security_config()),
        Arc::new(EnvSecretsManager::new(secrets_dir.join("secrets")).unwrap()),
        Arc::new(StorageIndex::new()),
        Arc::new(RedirectGuard::from_env().unwrap()),
        Arc::new(NoopPublisher),
        Arc::new(RateLimiter::new(60, Duration::from_secs(60))),
        Arc::new(config_root_path()),
        Arc::new(ProviderCatalog::load(&config_root_path().join("providers")).unwrap()),
        true,
        true,
    );

    let router = greentic_oauth_broker::http::router(context);

    let refresh_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/_test/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "provider": "fake",
                        "client_id": "client",
                        "client_secret": "secret",
                        "refresh_token": "seed"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(refresh_response.status(), StatusCode::NOT_FOUND);

    let fetch_response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/_test/signed-fetch")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "access_token": "ignored",
                        "url": "https://example.com/resource"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(fetch_response.status(), StatusCode::NOT_FOUND);
}
