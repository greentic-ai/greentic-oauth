use axum::{Json, extract::State};
use base64::Engine;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::{
    http::{SharedContext, error::AppError},
    storage::secrets_manager::SecretsManager,
    tokens::{
        AccessTokenResponse, SignedFetchOptions, SignedFetchOutcome, perform_signed_fetch,
        resolve_access_token,
    },
};

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
