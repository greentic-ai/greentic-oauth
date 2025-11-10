use std::str::FromStr;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    auth::{AuthSession, StateClaims, record_start_created},
    http::{
        SharedContext,
        error::AppError,
        handlers::initiate::{self, StartRequest},
        util::ensure_secure_request,
    },
    storage::{index::OwnerKindKey, secrets_manager::SecretsManager},
};

#[derive(Deserialize)]
pub struct AuthorizePath {
    pub id: String,
}

#[derive(Deserialize)]
pub struct ApiStartRequest {
    pub env: String,
    pub tenant: String,
    pub provider: String,
    #[serde(default)]
    pub team: Option<String>,
    pub owner_kind: String,
    pub owner_id: String,
    pub flow_id: String,
    #[serde(default, deserialize_with = "deserialize_scopes")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
}

#[derive(Serialize)]
pub struct ApiStartResponse {
    pub start_url: String,
}

pub async fn start_session<S>(
    headers: HeaderMap,
    State(ctx): State<SharedContext<S>>,
    Json(body): Json<ApiStartRequest>,
) -> Result<impl IntoResponse, AppError>
where
    S: SecretsManager + 'static,
{
    ensure_secure_request(&headers, ctx.allow_insecure)?;

    let base_url = ctx.oauth_base_url.as_ref().cloned().ok_or_else(|| {
        tracing::error!("OAUTH_BASE_URL not configured; refusing to create session");
        AppError::internal("oauth base url not configured")
    })?;

    let owner_kind = OwnerKindKey::from_str(body.owner_kind.as_str())
        .map_err(|_| AppError::bad_request("invalid owner_kind"))?;
    let visibility = initiate::parse_visibility(body.visibility.clone())?;

    let start_request = StartRequest {
        env: body.env,
        tenant: body.tenant,
        provider: body.provider,
        team: body.team,
        owner_kind,
        owner_id: body.owner_id,
        flow_id: body.flow_id,
        scopes: body.scopes,
        redirect_uri: body.redirect_uri,
        visibility,
        preset: body.preset,
        prompt: body.prompt,
    };

    let session_id = Ulid::new().to_string();
    let csrf = ctx.security.csrf.clone();
    let session_token = session_id.clone();
    let prepared = initiate::prepare_start(&ctx, &start_request, move |flow_state| {
        let claims = StateClaims::new(&session_token, flow_state);
        claims.sign(&csrf).map_err(AppError::from)
    })
    .await?;

    let ttl = ctx.sessions.ttl();
    let session = AuthSession::new(
        session_id.clone(),
        start_request.provider.clone(),
        prepared.flow_state.clone(),
        prepared.state_token.clone(),
        prepared.redirect_url.clone(),
        ttl,
    );
    ctx.sessions.insert(session);

    let authorize_path = format!("authorize/{session_id}");
    let start_url = base_url.join(&authorize_path)?;

    record_start_created(&start_request.provider, StatusCode::CREATED);

    Ok((
        StatusCode::CREATED,
        Json(ApiStartResponse {
            start_url: start_url.to_string(),
        }),
    ))
}

pub async fn authorize_session<S>(
    Path(AuthorizePath { id }): Path<AuthorizePath>,
    State(ctx): State<SharedContext<S>>,
) -> Result<impl IntoResponse, AppError>
where
    S: SecretsManager + 'static,
{
    if let Some(session) = ctx.sessions.get(&id) {
        return Ok(Redirect::temporary(&session.authorize_url).into_response());
    }

    Err(AppError::not_found("authorization session not found"))
}

fn deserialize_scopes<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ScopeValue {
        List(Vec<String>),
        Text(String),
    }

    let value = Option::<ScopeValue>::deserialize(deserializer)?;
    let scopes = match value {
        Some(ScopeValue::List(items)) => {
            items.into_iter().filter(|s| !s.trim().is_empty()).collect()
        }
        Some(ScopeValue::Text(text)) => text
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|segment| !segment.is_empty())
            .map(|segment| segment.to_string())
            .collect(),
        None => Vec::new(),
    };
    Ok(scopes)
}
