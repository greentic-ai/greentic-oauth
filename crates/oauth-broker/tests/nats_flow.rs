use std::{path::PathBuf, sync::Arc, time::Duration};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use greentic_oauth_broker::{
    config::{ProviderRegistry, RedirectGuard},
    events::SharedPublisher,
    http::{
        handlers::callback::{self, CallbackQuery},
        state::FlowState,
        AppContext, SharedContext,
    },
    nats::{self, NatsEventPublisher, NatsOptions},
    providers::manifest::ProviderCatalog,
    rate_limit::RateLimiter,
    security::{csrf::CsrfKey, jwe::JweVault, jws::JwsService, SecurityConfig},
    storage::{
        env::EnvSecretsManager, index::ConnectionKey, secrets_manager::SecretsManager, StorageIndex,
    },
    telemetry_nats::NatsHeaders,
};
use greentic_oauth_core::{
    provider::{Provider, ProviderError, ProviderErrorKind, ProviderResult},
    types::{OAuthFlowRequest, OAuthFlowResult, OwnerKind, TokenHandleClaims, TokenSet},
};
use serde::Deserialize;
use serde_json::json;
use tempfile::tempdir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, oneshot},
    time,
};
use url::Url;

struct FakeProvider;

impl FakeProvider {
    fn new() -> Self {
        Self
    }
}

impl Provider for FakeProvider {
    fn auth_url(&self) -> &str {
        "https://fake.provider/oauth/authorize"
    }

    fn token_url(&self) -> &str {
        "https://fake.provider/oauth/token"
    }

    fn redirect_uri(&self) -> &str {
        "https://broker.example.com/callback"
    }

    fn build_authorize_redirect(
        &self,
        request: &OAuthFlowRequest,
    ) -> ProviderResult<OAuthFlowResult> {
        let mut pairs: Vec<(String, String)> = request
            .state
            .clone()
            .map(|state| vec![("state".into(), state)])
            .unwrap_or_default();
        if let Some(challenge) = &request.code_challenge {
            pairs.push(("code_challenge".into(), challenge.clone()));
        }
        let mut url = Url::parse(self.auth_url()).unwrap();
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in &pairs {
                qp.append_pair(k, v);
            }
        }

        Ok(OAuthFlowResult {
            redirect_url: url.to_string(),
            state: request.state.clone(),
            scopes: request.scopes.clone(),
        })
    }

    fn exchange_code(&self, _claims: &TokenHandleClaims, _code: &str) -> ProviderResult<TokenSet> {
        Ok(TokenSet {
            access_token: "token-abc".into(),
            expires_in: Some(1200),
            refresh_token: Some("refresh-xyz".into()),
            token_type: Some("Bearer".into()),
            scopes: vec!["read".into(), "offline_access".into()],
        })
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
    let jws =
        JwsService::from_base64_secret("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=").unwrap();
    let jwe = JweVault::from_key_bytes(&[2u8; 32]).unwrap();
    let csrf = CsrfKey::new(&[3u8; 32]).unwrap();
    SecurityConfig {
        jws,
        jwe,
        csrf,
        discovery: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_context(
    registry: Arc<ProviderRegistry>,
    security: Arc<SecurityConfig>,
    secrets: Arc<EnvSecretsManager>,
    index: Arc<StorageIndex>,
    redirect_guard: Arc<RedirectGuard>,
    publisher: SharedPublisher,
    rate_limiter: Arc<RateLimiter>,
    config_root: Arc<PathBuf>,
    provider_catalog: Arc<ProviderCatalog>,
) -> SharedContext<EnvSecretsManager> {
    Arc::new(AppContext {
        providers: registry,
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

#[derive(Deserialize)]
struct StoredTokenEnvelope {
    ciphertext: String,
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct CallbackEventPayload {
    flow_id: String,
    token_handle: TokenHandleClaims,
}

#[tokio::test]
async fn nats_request_and_publish_flow() {
    let mut registry = ProviderRegistry::new();
    let provider = Arc::new(FakeProvider::new());
    registry.insert("fake", provider.clone() as Arc<dyn Provider>);
    let providers = Arc::new(registry);

    let security = Arc::new(security_config());
    let secrets =
        Arc::new(EnvSecretsManager::new(tempdir().unwrap().path().to_path_buf()).unwrap());
    let index = Arc::new(StorageIndex::new());
    let redirect_guard = Arc::new(
        RedirectGuard::from_list(vec!["https://app.example.com/success".to_string()]).unwrap(),
    );

    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping nats flow test: {err}");
            return;
        }
        Err(err) => panic!("failed to bind mock NATS server: {err}"),
    };
    let addr = listener.local_addr().unwrap();
    let url = format!("nats://{addr}");

    let options = NatsOptions {
        url: url.clone(),
        tls_domain: None,
    };

    let request_payload = json!({
        "owner_kind": "user",
        "owner_id": "user-1",
        "scopes": ["read"],
        "visibility": "team",
        "redirect_uri": "https://app.example.com/success"
    });

    let (response_tx, response_rx) = oneshot::channel();
    let (event_tx, mut event_rx) = mpsc::channel::<(String, Vec<u8>, NatsHeaders)>(1);
    let server_handle = tokio::spawn(run_mock_server(
        listener,
        request_payload.clone(),
        response_tx,
        event_tx,
    ));

    let (writer, reader) = nats::connect(&options).await.unwrap();
    let publisher: SharedPublisher = Arc::new(NatsEventPublisher::new(writer.clone()));
    let rate_limiter = Arc::new(RateLimiter::new(100, Duration::from_secs(60)));
    let config_root = Arc::new(PathBuf::from("./configs"));
    let provider_catalog = Arc::new(ProviderCatalog::load(&config_root.join("providers")).unwrap());

    let context = build_context(
        providers,
        security.clone(),
        secrets.clone(),
        index.clone(),
        redirect_guard,
        publisher.clone(),
        rate_limiter,
        config_root.clone(),
        provider_catalog,
    );

    let request_handle = nats::spawn_request_listener(writer.clone(), reader, context.clone())
        .await
        .unwrap();

    let response_payload = time::timeout(Duration::from_secs(2), response_rx)
        .await
        .unwrap()
        .unwrap();

    let response_json: serde_json::Value = serde_json::from_slice(&response_payload).unwrap();
    let state = response_json["state"].as_str().unwrap().to_string();

    let callback_response = callback::complete::<EnvSecretsManager>(
        Query(CallbackQuery {
            code: Some("authcode".into()),
            state: Some(state.clone()),
            error: None,
        }),
        State(context.clone()),
    )
    .await
    .unwrap()
    .into_response();
    assert_eq!(callback_response.status(), StatusCode::TEMPORARY_REDIRECT);

    let secret_path = {
        let payload = security.csrf.open("state", &state).unwrap();
        let flow_state: FlowState = serde_json::from_str(&payload).unwrap();
        flow_state.secret_path().unwrap()
    };

    let stored: StoredTokenEnvelope = secrets
        .get_json(&secret_path)
        .unwrap()
        .expect("stored secret");
    let decrypted = security.jwe.decrypt(&stored.ciphertext).unwrap();
    assert!(stored.expires_at.is_some());
    assert_eq!(decrypted.access_token, "token-abc");

    let (event_subject, event_payload, _event_headers) =
        time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(event_subject, "oauth.res.acme.prod._.fake.flow-123");

    let event: CallbackEventPayload = serde_json::from_slice(&event_payload).unwrap();
    assert_eq!(event.flow_id, "flow-123");
    assert_eq!(event.token_handle.provider, "fake");

    let key = ConnectionKey::from_owner(
        "prod",
        "acme",
        None,
        &OwnerKind::User {
            subject: "user-1".into(),
        },
        "user-1",
    );
    let connection = index.get("fake", &key).expect("connection");
    assert_eq!(connection.path, secret_path.as_str());
    request_handle.abort();
    server_handle.abort();
}

async fn run_mock_server(
    listener: TcpListener,
    request_payload: serde_json::Value,
    response_tx: oneshot::Sender<Vec<u8>>,
    event_tx: mpsc::Sender<(String, Vec<u8>, NatsHeaders)>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut response_tx = Some(response_tx);

    writer
        .write_all(b"INFO {\"server_id\":\"mock\"}\r\n")
        .await
        .unwrap();

    let mut line = String::new();
    let mut subscribed = false;
    loop {
        line.clear();
        if reader.read_line(&mut line).await.unwrap() == 0 {
            break;
        }
        if line.starts_with("CONNECT") {
            writer.write_all(b"+OK\r\n").await.unwrap();
        } else if line.starts_with("PING") {
            writer.write_all(b"PONG\r\n").await.unwrap();
        } else if line.starts_with("SUB") && !subscribed {
            subscribed = true;
            writer.write_all(b"+OK\r\n").await.unwrap();
            let payload = request_payload.to_string();
            let command = format!(
                "MSG oauth.req.acme.prod._.fake.flow-123 1 INBOX.1 {}\r\n{}\r\n",
                payload.len(),
                payload
            );
            writer.write_all(command.as_bytes()).await.unwrap();
        } else if line.starts_with("HPUB") {
            let mut parts = line.split_whitespace();
            parts.next();
            let subject = parts.next().unwrap().to_string();
            let header_len: usize = parts.next().unwrap().parse().unwrap();
            let total_len: usize = parts.next().unwrap().parse().unwrap();
            let mut header_bytes = vec![0u8; header_len];
            reader.read_exact(&mut header_bytes).await.unwrap();
            let mut payload = vec![0u8; total_len - header_len];
            reader.read_exact(&mut payload).await.unwrap();
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await.unwrap();
            let headers =
                NatsHeaders::from_bytes(&header_bytes).expect("parse nats headers in test");

            if subject.starts_with("INBOX") {
                if let Some(tx) = response_tx.take() {
                    let _ = tx.send(payload);
                }
            } else if subject.starts_with("oauth.res") {
                assert_eq!(subject, "oauth.res.acme.prod._.fake.flow-123");
                let _ = event_tx.send((subject, payload, headers)).await;
            }

            writer.write_all(b"+OK\r\n").await.unwrap();
        } else if line.starts_with("PUB") {
            let mut parts = line.split_whitespace();
            parts.next();
            let subject = parts.next().unwrap();
            let size: usize = parts.next().unwrap().parse().unwrap();
            let mut payload = vec![0u8; size];
            reader.read_exact(&mut payload).await.unwrap();
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await.unwrap();

            if subject.starts_with("INBOX") {
                if let Some(tx) = response_tx.take() {
                    let _ = tx.send(payload);
                }
            } else if subject.starts_with("oauth.res") {
                assert_eq!(subject, "oauth.res.acme.prod._.fake.flow-123");
                let _ = event_tx
                    .send((subject.to_string(), payload, NatsHeaders::default()))
                    .await;
            }

            writer.write_all(b"+OK\r\n").await.unwrap();
        }
    }
}
