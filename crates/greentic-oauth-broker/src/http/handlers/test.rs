use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;

use crate::{
    http::{SharedContext, error::AppError},
    storage::secrets_manager::SecretsManager,
};

#[derive(Deserialize)]
pub struct RefreshRequest {
    #[serde(default)]
    provider: Option<String>,
    client_id: String,
    client_secret: String,
    refresh_token: String,
    #[serde(default)]
    scope: Option<String>,
}

pub async fn refresh_grant<S>(
    State(ctx): State<SharedContext<S>>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<serde_json::Value>, AppError>
where
    S: SecretsManager + 'static,
{
    let provider_id = if let Some(id) = payload.provider.as_ref() {
        id.clone()
    } else {
        let map = ctx.providers.all();
        if map.len() == 1 {
            map.keys().next().cloned().unwrap()
        } else {
            return Err(AppError::bad_request(
                "provider not specified; set `provider` when multiple providers are registered",
            ));
        }
    };

    let provider = ctx
        .providers
        .get(&provider_id)
        .ok_or_else(|| AppError::not_found(format!("provider `{}` not registered", provider_id)))?;

    let endpoint = provider
        .token_url()
        .parse::<reqwest::Url>()
        .map_err(|err| AppError::internal(format!("invalid token endpoint url: {err}")))?;

    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("client_id", payload.client_id.as_str()),
        ("client_secret", payload.client_secret.as_str()),
        ("refresh_token", payload.refresh_token.as_str()),
    ];
    if let Some(scope) = payload.scope.as_deref()
        && !scope.is_empty()
    {
        form.push(("scope", scope));
    }

    let client = reqwest::Client::new();
    let response = client
        .post(endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|err| AppError::internal(format!("refresh request failed: {err}")))?;

    let status = response.status();
    let body = response
        .json::<serde_json::Value>()
        .await
        .map_err(|err| AppError::internal(format!("decode refresh response: {err}")))?;

    if !status.is_success() {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("refresh endpoint returned {status}: {body}"),
        ));
    }

    Ok(Json(body))
}

#[derive(Deserialize)]
pub struct SignedFetchRequest {
    access_token: String,
    url: String,
}

pub async fn signed_fetch<S>(
    State(_ctx): State<SharedContext<S>>,
    Json(payload): Json<SignedFetchRequest>,
) -> Result<Json<serde_json::Value>, AppError>
where
    S: SecretsManager + 'static,
{
    let client = reqwest::Client::new();
    let response = client
        .get(&payload.url)
        .bearer_auth(&payload.access_token)
        .send()
        .await
        .map_err(|err| AppError::internal(format!("signed fetch failed: {err}")))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| AppError::internal(format!("read response body: {err}")))?;
    let truncated = if text.len() > 1024 {
        format!("{}...", &text[..1024])
    } else {
        text
    };
    let result = serde_json::json!({
        "status": status.as_u16(),
        "body": truncated,
    });
    Ok(Json(result))
}
