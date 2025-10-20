use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};

use oauth_broker::{
    config::{ProviderRegistry, RedirectGuard},
    events::{EventPublisher, PublishError, SharedPublisher},
    http::{
        handlers::{
            callback::{self, CallbackQuery},
            initiate::{self, StartPath, StartQuery},
            status::{self, StatusPath, StatusQuery},
        },
        state::FlowState,
        AppContext, SharedContext,
    },
    security::{csrf::CsrfKey, jwe::JweVault, jws::JwsService, SecurityConfig},
    storage::{
        env::EnvSecretsManager, index::ConnectionKey, secrets_manager::SecretsManager, StorageIndex,
    },
};
use oauth_core::{
    provider::{Provider, ProviderError, ProviderErrorKind, ProviderResult},
    types::{OAuthFlowRequest, OAuthFlowResult, OwnerKind, TokenHandleClaims, TokenSet},
};
use serde::Deserialize;
use tempfile::tempdir;
use url::Url;

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

    fn exchange_code(&self, _claims: &TokenHandleClaims, code: &str) -> ProviderResult<TokenSet> {
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
    let csrf = CsrfKey::new(&vec![3u8; 32]).expect("csrf");

    SecurityConfig { jws, jwe, csrf }
}

fn build_context(
    provider_registry: Arc<ProviderRegistry>,
    security: Arc<SecurityConfig>,
    secrets: Arc<EnvSecretsManager>,
    index: Arc<StorageIndex>,
    redirect_guard: Arc<RedirectGuard>,
    publisher: SharedPublisher,
) -> SharedContext<EnvSecretsManager> {
    Arc::new(AppContext {
        providers: provider_registry,
        security,
        secrets,
        index,
        redirect_guard,
        publisher,
    })
}

#[tokio::test]
async fn start_to_callback_happy_path() {
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

    let context = build_context(
        provider_registry,
        security.clone(),
        secrets.clone(),
        index.clone(),
        redirect_guard,
        publisher,
    );

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
        }),
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

    let events = publisher_impl.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "oauth.res.acme.prod.platform.fake.flow-123");

    let event: CallbackEventPayload = serde_json::from_slice(&events[0].1).unwrap();
    assert_eq!(event.flow_id, "flow-123");
    assert_eq!(event.token_handle.provider, "fake");
    assert_eq!(event.token_handle.subject, flow_state.owner_id);
    assert_eq!(event.storage_path, secret_path.as_str());

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

    let context = build_context(
        provider_registry,
        security.clone(),
        secrets,
        index,
        redirect_guard,
        publisher,
    );

    let response = callback::complete::<EnvSecretsManager>(
        Query(CallbackQuery {
            code: Some("authcode".into()),
            state: Some("invalid-state-token".into()),
            error: None,
        }),
        State(context.clone()),
    )
    .await;

    assert!(response.is_err());
}
