use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Error, Result};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use dotenvy::dotenv;
use greentic_oauth_core::{OwnerKind as CoreOwnerKind, TenantCtx, TokenHandleClaims};
use greentic_oauth_sdk::{
    FlowResult, InitiateAuthRequest, Method, OwnerKind, SignedFetchRequest, Visibility,
};
use serde::{Deserialize, Serialize};
use tokio::signal;
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    init_tracing()?;

    let port: u16 = std::env::var("APP_PORT")
        .unwrap_or_else(|_| "3000".into())
        .parse()
        .unwrap_or(3000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let app_state = AppState {
        broker: Arc::new(DemoBroker::new()),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/oauth/start", post(start_oauth))
        .route("/oauth/callback", get(complete_oauth))
        .route("/oauth/token", post(exchange_token))
        .route("/oauth/signed-fetch", post(signed_fetch))
        .with_state(app_state);

    info!(?addr, "demo axum app listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app)
        .with_graceful_shutdown(async {
            let _ = signal::ctrl_c().await;
        })
        .await?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    broker: Arc<dyn Broker + Send + Sync>,
}

#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct StartInput {
    owner_id: String,
    #[serde(default)]
    scopes: Vec<String>,
    redirect_uri: Option<String>,
}

#[derive(Serialize)]
struct StartOutput {
    flow_id: String,
    redirect_url: String,
    state: String,
}

#[derive(Serialize)]
struct FlowResultOutput {
    flow_id: String,
    env: String,
    tenant: String,
    team: Option<String>,
    provider: String,
    storage_path: String,
}

#[derive(Deserialize)]
struct TokenInput {
    token_handle: String,
    #[serde(default)]
    force_refresh: bool,
}

#[derive(Serialize)]
struct TokenOutput {
    access_token: String,
    expires_at: u64,
}

#[derive(Deserialize)]
struct SignedFetchInput {
    token_handle: String,
    url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: Option<String>,
}

#[derive(Serialize)]
struct SignedFetchOutput {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

async fn health() -> &'static str {
    "ok"
}

async fn start_oauth(
    State(state): State<AppState>,
    Json(payload): Json<StartInput>,
) -> Result<Json<StartOutput>, AppError> {
    let response = state
        .broker
        .initiate_flow(payload)
        .await
        .map_err(AppError)?;
    Ok(Json(response))
}

async fn complete_oauth(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
) -> Result<Json<FlowResultOutput>, AppError> {
    let result = state.broker.complete_flow(params).await.map_err(AppError)?;
    Ok(Json(FlowResultOutput {
        flow_id: result.flow_id,
        env: result.env,
        tenant: result.tenant,
        team: result.team,
        provider: result.provider,
        storage_path: result.storage_path,
    }))
}

async fn exchange_token(
    State(state): State<AppState>,
    Json(payload): Json<TokenInput>,
) -> Result<Json<TokenOutput>, AppError> {
    let access = state
        .broker
        .exchange_token(payload)
        .await
        .map_err(AppError)?;
    Ok(Json(access))
}

async fn signed_fetch(
    State(state): State<AppState>,
    Json(payload): Json<SignedFetchInput>,
) -> Result<Json<SignedFetchOutput>, AppError> {
    let response = state.broker.signed_fetch(payload).await.map_err(AppError)?;
    Ok(Json(response))
}

struct DemoBroker;

#[async_trait]
trait Broker {
    async fn initiate_flow(&self, input: StartInput) -> Result<StartOutput>;
    async fn complete_flow(&self, params: CallbackParams) -> Result<FlowResult>;
    async fn exchange_token(&self, input: TokenInput) -> Result<TokenOutput>;
    async fn signed_fetch(&self, input: SignedFetchInput) -> Result<SignedFetchOutput>;
}

impl DemoBroker {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Broker for DemoBroker {
    async fn initiate_flow(&self, input: StartInput) -> Result<StartOutput> {
        // Construct an InitiateAuthRequest to demonstrate the SDK types that wire up to the broker.
        let request = InitiateAuthRequest {
            owner_kind: OwnerKind::User,
            owner_id: input.owner_id.clone(),
            flow_id: Uuid::new_v4().to_string(),
            scopes: if input.scopes.is_empty() {
                vec!["openid".into(), "profile".into()]
            } else {
                input.scopes.clone()
            },
            redirect_uri: input.redirect_uri.clone(),
            visibility: Some(Visibility::Private),
        };

        // Normally you would call `client.initiate_auth(request).await?`. The demo fabricates
        // a redirect so the example can run without the full broker stack.
        Ok(StartOutput {
            flow_id: request.flow_id.clone(),
            redirect_url: format!(
                "https://login.example.com/oauth2/authorize?state={}",
                request.flow_id
            ),
            state: format!("state-{}", request.flow_id),
        })
    }

    async fn complete_flow(&self, params: CallbackParams) -> Result<FlowResult> {
        let claims = TokenHandleClaims {
            provider: "microsoft-graph".into(),
            subject: params.code.clone(),
            owner: CoreOwnerKind::User {
                subject: params.code.clone(),
            },
            tenant: TenantCtx {
                env: "dev".into(),
                tenant: "acme".into(),
                team: Some("ops".into()),
            },
            scopes: vec!["offline_access".into(), "openid".into(), "Mail.Read".into()],
            issued_at: 1_700_000_000,
            expires_at: 1_700_003_600,
        };

        Ok(FlowResult {
            flow_id: format!("flow-for-{}", params.state),
            env: "dev".into(),
            tenant: "acme".into(),
            team: Some("ops".into()),
            provider: "microsoft-graph".into(),
            token_handle_claims: claims,
            storage_path: "envs/dev/tenants/acme/providers/microsoft-graph/user-demo.json".into(),
        })
    }

    async fn exchange_token(&self, input: TokenInput) -> Result<TokenOutput> {
        // The real broker would POST to `/token` and decrypt the stored payload.
        let prefix = if input.force_refresh {
            "fresh"
        } else {
            "cached"
        };
        Ok(TokenOutput {
            access_token: format!("{}-access-token-for-{}", prefix, input.token_handle),
            expires_at: 1_700_000_000,
        })
    }

    async fn signed_fetch(&self, input: SignedFetchInput) -> Result<SignedFetchOutput> {
        let request = SignedFetchRequest {
            token_handle: input.token_handle,
            method: Method::from_bytes(input.method.as_deref().unwrap_or("GET").as_bytes())
                .context("invalid HTTP method")?,
            url: input.url,
            headers: input.headers,
            body: input.body.map(|body| body.into_bytes()),
        };

        let _ = request;

        Ok(SignedFetchOutput {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: String::from_utf8(br#"{"message":"demo payload"}"#.to_vec())?,
        })
    }
}

fn init_tracing() -> Result<()> {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,greentic=debug".into());
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(LevelFilter::TRACE)
        .with(tracing_subscriber::EnvFilter::new(filter))
        .try_init()
        .map_err(Error::from)?;
    Ok(())
}

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut response = Json(serde_json::json!({
            "error": self.0.to_string()
        }))
        .into_response();
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response
    }
}
