use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use greentic_oauth_core::TokenSet;
use greentic_oauth_core::oidc::{IdClaims, OidcClient, OidcError, PkceState};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    config: Arc<HarnessConfig>,
    oidc: OidcClient,
    sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
}

#[derive(Clone)]
struct SessionEntry {
    pkce: PkceState,
    tokens: Option<TokenSet>,
    updated_at: OffsetDateTime,
}

impl SessionEntry {
    fn new(pkce: PkceState) -> Self {
        Self {
            pkce,
            tokens: None,
            updated_at: OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AuthCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Clone)]
struct HarnessConfig {
    listen_addr: SocketAddr,
    base_url: Url,
    redirect_uri: Url,
    post_logout_uri: Url,
    issuer: Url,
    client_id: String,
    client_secret: Option<String>,
    scopes: Vec<String>,
    signing_key: Vec<u8>,
}

impl HarnessConfig {
    fn from_env() -> Result<Self, HarnessError> {
        let listen_addr: SocketAddr = std::env::var("HARNESS_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
            .parse()
            .map_err(|err| HarnessError::Config(format!("invalid HARNESS_LISTEN_ADDR: {err}")))?;

        let base_url = Url::parse(
            &std::env::var("RP_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string()),
        )
        .map_err(|err| HarnessError::Config(format!("invalid RP_BASE_URL: {err}")))?;

        let redirect_uri = Url::parse(
            &std::env::var("OAUTH_REDIRECT_URI")
                .unwrap_or_else(|_| format!("{}redirect", base_url)),
        )
        .map_err(|err| HarnessError::Config(format!("invalid OAUTH_REDIRECT_URI: {err}")))?;

        let post_logout_uri = Url::parse(
            &std::env::var("OAUTH_LOGOUT_REDIRECT_URI")
                .unwrap_or_else(|_| format!("{}logout/callback", base_url)),
        )
        .map_err(|err| HarnessError::Config(format!("invalid OAUTH_LOGOUT_REDIRECT_URI: {err}")))?;

        let issuer = Url::parse(
            &std::env::var("OIDC_ISSUER_URL")
                .map_err(|_| HarnessError::Config("OIDC_ISSUER_URL is required".into()))?,
        )
        .map_err(|err| HarnessError::Config(format!("invalid OIDC_ISSUER_URL: {err}")))?;

        let client_id = std::env::var("OIDC_CLIENT_ID")
            .map_err(|_| HarnessError::Config("OIDC_CLIENT_ID is required".into()))?;
        let client_secret = std::env::var("OIDC_CLIENT_SECRET").ok();

        let scopes = std::env::var("OIDC_SCOPES")
            .unwrap_or_else(|_| "openid email profile offline_access".to_string())
            .split_whitespace()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        let signing_key = std::env::var("HARNESS_SIGNING_KEY")
            .map_err(|_| HarnessError::Config("HARNESS_SIGNING_KEY is required".into()))?
            .into_bytes();

        Ok(Self {
            listen_addr,
            base_url,
            redirect_uri,
            post_logout_uri,
            issuer,
            client_id,
            client_secret,
            scopes,
            signing_key,
        })
    }

    fn cookie_secure(&self) -> bool {
        self.base_url.scheme() == "https"
    }
}

#[derive(Debug, Error)]
enum HarnessError {
    #[error("{0}")]
    Config(String),
    #[error("session not found")]
    SessionNotFound,
    #[error("missing authorization code")]
    MissingCode,
    #[error("authorization state mismatch")]
    StateMismatch,
    #[error("missing id token for logout")]
    MissingIdToken,
    #[error("oauth error: {0}")]
    OAuth(String),
    #[error("{0}")]
    Other(String),
}

impl From<OidcError> for HarnessError {
    fn from(value: OidcError) -> Self {
        HarnessError::OAuth(value.to_string())
    }
}

impl IntoResponse for HarnessError {
    fn into_response(self) -> Response {
        let status = match self {
            HarnessError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            HarnessError::SessionNotFound => StatusCode::UNAUTHORIZED,
            HarnessError::MissingCode
            | HarnessError::StateMismatch
            | HarnessError::MissingIdToken => StatusCode::BAD_REQUEST,
            HarnessError::OAuth(_) => StatusCode::BAD_GATEWAY,
            HarnessError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let message = self.to_string();
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), HarnessError> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "oauth_testharness=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Arc::new(HarnessConfig::from_env()?);
    let mut client = OidcClient::discover(&config.issuer)
        .await
        .map_err(|err| HarnessError::OAuth(err.to_string()))?;
    client
        .set_client_credentials(config.client_id.clone(), config.client_secret.clone())
        .map_err(|err| HarnessError::OAuth(err.to_string()))?;

    let app_state = AppState {
        config: Arc::clone(&config),
        oidc: client,
        sessions: Arc::new(RwLock::new(HashMap::new())),
    };

    let router = Router::new()
        .route("/health", get(health))
        .route("/auth/start", get(auth_start))
        .route("/redirect", get(auth_redirect))
        .route("/logout/start", get(logout_start))
        .route("/logout/callback", get(logout_callback))
        .route("/tokens", get(tokens_view))
        .with_state(app_state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        );

    info!("listening on {}", config.listen_addr);
    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .map_err(|err| HarnessError::Other(format!("failed to bind listener: {err}")))?;
    axum::serve(listener, router)
        .await
        .map_err(|err| HarnessError::Other(format!("server error: {err}")))
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

async fn auth_start(State(state): State<AppState>) -> Result<Response, HarnessError> {
    let scope_refs = state
        .config
        .scopes
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>();
    let (url, pkce) = state
        .oidc
        .auth_url(&state.config.redirect_uri, &scope_refs)
        .map_err(|err| HarnessError::OAuth(err.to_string()))?;

    let sid = Uuid::new_v4().to_string();
    let token = sign_session_id(&state.config, &sid)?;
    let set_cookie = build_session_cookie(&state.config, &token)?;

    state
        .sessions
        .write()
        .await
        .insert(sid, SessionEntry::new(pkce));

    let mut response = Redirect::to(url.as_str()).into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, set_cookie);
    Ok(response)
}

async fn auth_redirect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuthCallback>,
) -> Result<Response, HarnessError> {
    if let Some(error) = params.error {
        return Err(HarnessError::OAuth(format!(
            "{}: {}",
            error,
            params.error_description.unwrap_or_default()
        )));
    }

    let code = params.code.ok_or(HarnessError::MissingCode)?;
    let returned_state = params.state.ok_or(HarnessError::StateMismatch)?;

    let sid = extract_session_id(&state.config, &headers)?;
    let mut sessions = state.sessions.write().await;
    let entry = sessions
        .get_mut(&sid)
        .ok_or(HarnessError::SessionNotFound)?;

    if entry.pkce.csrf_token() != returned_state {
        return Err(HarnessError::StateMismatch);
    }

    let tokens = state
        .oidc
        .exchange_code(&code, &entry.pkce, &state.config.redirect_uri)
        .await?;

    if let Some(id_token) = tokens.id_token.as_deref() {
        let claims = state.oidc.validate_id_token(id_token, entry.pkce.nonce())?;

        validate_claims(&state.config, &claims)?;
    }

    entry.tokens = Some(tokens);
    entry.updated_at = OffsetDateTime::now_utc();

    let html = Html(
        r#"
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>OAuth Harness</title>
  </head>
  <body>
    <h1>OAuth flow completed</h1>
    <p>Tokens have been stored for this session. You can inspect them at <a href="/tokens">/tokens</a>.</p>
  </body>
</html>
"#
        .to_string(),
    );

    Ok(html.into_response())
}

async fn logout_start(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HarnessError> {
    let sid = extract_session_id(&state.config, &headers)?;
    let sessions = state.sessions.read().await;
    let entry = sessions.get(&sid).ok_or(HarnessError::SessionNotFound)?;

    let tokens = entry.tokens.as_ref().ok_or(HarnessError::MissingIdToken)?;

    let id_token = tokens
        .id_token
        .as_ref()
        .ok_or(HarnessError::MissingIdToken)?;

    let url = state
        .oidc
        .end_session_url(id_token, &state.config.post_logout_uri)?;

    Ok(Redirect::to(url.as_str()).into_response())
}

async fn logout_callback() -> impl IntoResponse {
    Html(
        r#"
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Logged out</title>
  </head>
  <body>
    <h1>Logout Complete</h1>
    <p>You may now close this window.</p>
  </body>
</html>
"#
        .to_string(),
    )
}

#[derive(Serialize)]
struct TokenDebug {
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: Option<u64>,
    scopes: Vec<String>,
    updated_at: OffsetDateTime,
}

async fn tokens_view(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HarnessError> {
    let sid = extract_session_id(&state.config, &headers)?;
    let sessions = state.sessions.read().await;
    let entry = sessions.get(&sid).ok_or(HarnessError::SessionNotFound)?;

    let tokens = entry.tokens.as_ref().ok_or(HarnessError::SessionNotFound)?;

    let body = TokenDebug {
        access_token: Some(redact_token(tokens.access_token.as_str())),
        refresh_token: tokens.refresh_token.as_deref().map(redact_token),
        id_token: tokens.id_token.as_deref().map(redact_token),
        expires_in: tokens.expires_in,
        scopes: tokens.scopes.clone(),
        updated_at: entry.updated_at,
    };

    Ok(Json(body).into_response())
}

fn extract_session_id(config: &HarnessConfig, headers: &HeaderMap) -> Result<String, HarnessError> {
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .ok_or(HarnessError::SessionNotFound)?;

    let session_value = cookie_header
        .split(';')
        .map(|pair| pair.trim())
        .find_map(|pair| pair.strip_prefix("oauth_sid="))
        .ok_or(HarnessError::SessionNotFound)?;

    verify_session_id(config, session_value)
}

fn sign_session_id(config: &HarnessConfig, sid: &str) -> Result<String, HarnessError> {
    let mut mac = HmacSha256::new_from_slice(&config.signing_key)
        .map_err(|err| HarnessError::Other(format!("invalid signing key: {err}")))?;
    mac.update(sid.as_bytes());
    let signature = mac.finalize().into_bytes();
    let encoded = URL_SAFE_NO_PAD.encode(signature);
    Ok(format!("{sid}.{encoded}"))
}

fn build_session_cookie(config: &HarnessConfig, token: &str) -> Result<HeaderValue, HarnessError> {
    let mut cookie = format!("oauth_sid={token}; Path=/; HttpOnly; SameSite=Lax");
    if config.cookie_secure() {
        cookie.push_str("; Secure");
    }
    HeaderValue::from_str(&cookie)
        .map_err(|_| HarnessError::Other("failed to encode cookie".into()))
}

fn verify_session_id(config: &HarnessConfig, value: &str) -> Result<String, HarnessError> {
    let (sid, sig) = value.split_once('.').ok_or(HarnessError::SessionNotFound)?;
    let signature = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| HarnessError::SessionNotFound)?;
    let mut mac = HmacSha256::new_from_slice(&config.signing_key)
        .map_err(|err| HarnessError::Other(format!("invalid signing key: {err}")))?;
    mac.update(sid.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| HarnessError::SessionNotFound)?;
    Ok(sid.to_string())
}

fn validate_claims(config: &HarnessConfig, claims: &IdClaims) -> Result<(), HarnessError> {
    if !claims.audience.iter().any(|aud| aud == &config.client_id) {
        return Err(HarnessError::OAuth(
            "id_token audience does not include client".into(),
        ));
    }
    if claims.nonce.as_deref().is_none() {
        return Err(HarnessError::OAuth("id_token missing nonce claim".into()));
    }
    if matches!(claims.expires_at, Some(exp) if exp < OffsetDateTime::now_utc()) {
        return Err(HarnessError::OAuth("id_token expired".into()));
    }
    Ok(())
}

fn redact_token(token: &str) -> String {
    if token.len() <= 6 {
        "***".to_string()
    } else {
        format!("{}***", &token[..6])
    }
}

#[cfg(test)]
mod tests {}
