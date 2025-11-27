use axum::{
    Json,
    extract::{Path, State},
};
use base64::Engine;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::{
    http::{SharedContext, error::AppError},
    ids::{parse_env_id, parse_team_id, parse_tenant_id},
    provider_tokens::provider_token_service,
    storage::{
        index::{ConnectionKey, OwnerKindKey},
        secrets_manager::SecretsManager,
    },
    tokens::{
        AccessTokenResponse, SignedFetchOptions, SignedFetchOutcome, claims_from_connection,
        perform_signed_fetch, resolve_access_token, resolve_with_claims,
    },
};
use greentic_types::TenantCtx;

pub async fn get_access_token<S>(
    State(ctx): State<SharedContext<S>>,
    Json(request): Json<GetAccessTokenRequest>,
) -> Result<Json<GetAccessTokenResponse>, AppError>
where
    S: SecretsManager + 'static,
{
    let response = resolve_access_token(&ctx, &request.token_handle, request.force_refresh).await?;
    Ok(Json(GetAccessTokenResponse::from(response)))
}

pub async fn refresh_token<S>(
    Path(provider): Path<String>,
    State(ctx): State<SharedContext<S>>,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<Json<RefreshTokenResponse>, AppError>
where
    S: SecretsManager + 'static,
{
    let key = ConnectionKey {
        env: request.env.clone(),
        tenant: request.tenant.clone(),
        team: request.team.clone(),
        owner_kind: request.owner_kind.clone(),
        owner_id: request.owner_id.clone(),
        provider_account_id: request.owner_id.clone(),
    };

    let claims = claims_from_connection(&provider, &key, None);
    let response = resolve_with_claims(&ctx, claims, true).await?;

    Ok(Json(RefreshTokenResponse {
        expires_at: response.expires_at,
    }))
}

pub async fn signed_fetch<S>(
    State(ctx): State<SharedContext<S>>,
    Json(request): Json<SignedFetchRequest>,
) -> Result<Json<SignedFetchResponse>, AppError>
where
    S: SecretsManager + 'static,
{
    let SignedFetchRequest {
        token_handle,
        method: method_raw,
        url,
        headers,
        body,
        body_encoding,
    } = request;

    let method = Method::from_bytes(method_raw.as_bytes())
        .map_err(|_| AppError::bad_request("invalid HTTP method"))?;
    let body = SignedFetchRequest::decode_body(body, body_encoding)?;
    let headers = headers
        .into_iter()
        .map(|header| (header.name, header.value))
        .collect();

    let outcome = perform_signed_fetch(
        &ctx,
        SignedFetchOptions {
            token_handle,
            method,
            url,
            headers,
            body,
        },
    )
    .await?;

    Ok(Json(SignedFetchResponse::from(outcome)))
}

pub async fn get_resource_token<S>(
    State(ctx): State<SharedContext<S>>,
    Json(request): Json<ResourceTokenRequest>,
) -> Result<Json<ResourceTokenResponse>, AppError>
where
    S: SecretsManager + Send + Sync + 'static,
{
    let env_id = parse_env_id(&request.env).map_err(|e| AppError::bad_request(e.to_string()))?;
    let tenant_id =
        parse_tenant_id(&request.tenant).map_err(|e| AppError::bad_request(e.to_string()))?;
    let mut tenant_ctx = TenantCtx::new(env_id, tenant_id);
    if let Some(team) = &request.team {
        let team_id = parse_team_id(team).map_err(|e| AppError::bad_request(e.to_string()))?;
        tenant_ctx = tenant_ctx.with_team(Some(team_id));
    }

    let service = provider_token_service(ctx.secrets.clone());
    let token = service
        .get_provider_access_token(&tenant_ctx, &request.resource_id, &request.scopes)
        .await
        .map_err(|err| AppError::bad_request(err.to_string()))?;

    let response = AccessTokenResponse {
        access_token: token.access_token,
        expires_at: token.expires_at.unix_timestamp().max(0) as u64,
    };

    Ok(Json(ResourceTokenResponse::from(response)))
}

#[derive(Deserialize)]
pub struct GetAccessTokenRequest {
    token_handle: String,
    #[serde(default)]
    force_refresh: bool,
}

#[derive(Serialize)]
pub struct GetAccessTokenResponse {
    access_token: String,
    expires_at: u64,
}

impl From<AccessTokenResponse> for GetAccessTokenResponse {
    fn from(value: AccessTokenResponse) -> Self {
        Self {
            access_token: value.access_token,
            expires_at: value.expires_at,
        }
    }
}

#[derive(Deserialize)]
pub struct ResourceTokenRequest {
    env: String,
    tenant: String,
    #[serde(default)]
    team: Option<String>,
    resource_id: String,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Serialize)]
pub struct ResourceTokenResponse {
    access_token: String,
    expires_at: u64,
}

impl From<AccessTokenResponse> for ResourceTokenResponse {
    fn from(value: AccessTokenResponse) -> Self {
        Self {
            access_token: value.access_token,
            expires_at: value.expires_at,
        }
    }
}

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    env: String,
    tenant: String,
    #[serde(default)]
    team: Option<String>,
    #[serde(default = "default_owner_kind")]
    owner_kind: OwnerKindKey,
    owner_id: String,
}

#[derive(Serialize)]
pub struct RefreshTokenResponse {
    expires_at: u64,
}

fn default_owner_kind() -> OwnerKindKey {
    OwnerKindKey::User
}

#[derive(Deserialize)]
pub struct SignedFetchRequest {
    token_handle: String,
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<SignedFetchHeader>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    body_encoding: BodyEncoding,
}

impl SignedFetchRequest {
    fn decode_body(
        body: Option<String>,
        encoding: BodyEncoding,
    ) -> Result<Option<Vec<u8>>, AppError> {
        match (body, encoding) {
            (None, _) => Ok(None),
            (Some(payload), BodyEncoding::Base64) => base64::engine::general_purpose::STANDARD
                .decode(payload.as_bytes())
                .map(Some)
                .map_err(|err| AppError::bad_request(format!("invalid base64 body: {err}"))),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct SignedFetchHeader {
    name: String,
    value: String,
}

#[derive(Copy, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BodyEncoding {
    #[default]
    Base64,
}

#[derive(Serialize)]
pub struct SignedFetchResponse {
    status: u16,
    headers: Vec<SignedFetchHeader>,
    body: String,
    body_encoding: &'static str,
}

impl From<SignedFetchOutcome> for SignedFetchResponse {
    fn from(value: SignedFetchOutcome) -> Self {
        let headers = value
            .headers
            .into_iter()
            .map(|(name, value)| SignedFetchHeader { name, value })
            .collect();
        let body = base64::engine::general_purpose::STANDARD.encode(value.body);
        Self {
            status: value.status,
            headers,
            body,
            body_encoding: "base64",
        }
    }
}
