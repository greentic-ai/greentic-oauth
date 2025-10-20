use std::str::FromStr;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use oauth_core::types::{OAuthFlowRequest, OwnerKind, TenantCtx};
use serde::Deserialize;
use serde_json::json;

use crate::{
    audit::{self, AuditAttributes},
    http::{error::AppError, state::FlowState},
    rate_limit,
    security::pkce::PkcePair,
    storage::{index::OwnerKindKey, models::Visibility, secrets_manager::SecretsManager},
};

use super::super::SharedContext;

#[derive(Deserialize)]
pub struct StartPath {
    pub env: String,
    pub tenant: String,
    pub provider: String,
}

#[derive(Deserialize)]
pub struct StartQuery {
    pub team: Option<String>,
    pub owner_kind: String,
    pub owner_id: String,
    pub flow_id: String,
    pub scopes: Option<String>,
    pub redirect_uri: Option<String>,
    pub visibility: Option<String>,
}

#[derive(Clone)]
pub struct StartRequest {
    pub env: String,
    pub tenant: String,
    pub provider: String,
    pub team: Option<String>,
    pub owner_kind: OwnerKindKey,
    pub owner_id: String,
    pub flow_id: String,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
    pub visibility: Visibility,
}

fn parse_scopes(input: Option<String>) -> Vec<String> {
    input
        .map(|value| {
            value
                .split(|c| c == ',' || c == ' ')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn parse_visibility(input: Option<String>) -> Result<Visibility, AppError> {
    match input {
        Some(value) => Visibility::from_str(value.to_lowercase().as_str())
            .map_err(|_| AppError::bad_request("unknown visibility")),
        None => Ok(Visibility::Private),
    }
}

fn build_owner_kind(key: OwnerKindKey, owner_id: &str) -> OwnerKind {
    match key {
        OwnerKindKey::User => OwnerKind::User {
            subject: owner_id.to_string(),
        },
        OwnerKindKey::Service => OwnerKind::Service {
            subject: owner_id.to_string(),
        },
    }
}

pub async fn process_start<S>(
    ctx: &SharedContext<S>,
    request: &StartRequest,
) -> Result<(String, String, FlowState), AppError>
where
    S: SecretsManager + 'static,
{
    let rate_key = rate_limit::key(
        &request.env,
        &request.tenant,
        request.team.as_deref(),
        &request.provider,
    );
    ctx.rate_limiter
        .check(&rate_key)
        .await
        .map_err(|_| AppError::new(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded"))?;

    let provider = ctx
        .providers
        .get(&request.provider)
        .ok_or_else(|| AppError::not_found("provider not registered"))?;

    if let Some(ref uri) = request.redirect_uri {
        if !ctx.redirect_guard.is_allowed(uri) {
            return Err(AppError::bad_request("redirect_uri not permitted"));
        }
    }

    let pkce = PkcePair::generate();

    let flow_state = FlowState::new(
        &request.env,
        &request.tenant,
        &request.provider,
        request.team.clone(),
        &request.flow_id,
        request.owner_kind.clone(),
        &request.owner_id,
        request.redirect_uri.clone(),
        &pkce.verifier,
        request.scopes.clone(),
        request.visibility.clone(),
    );

    let state_payload = serde_json::to_string(&flow_state)?;
    let state_token = ctx.security.csrf.seal("state", &state_payload)?;

    let owner = build_owner_kind(request.owner_kind.clone(), &request.owner_id);

    let oauth_request = OAuthFlowRequest {
        tenant: TenantCtx {
            env: request.env.clone(),
            tenant: request.tenant.clone(),
            team: request.team.clone(),
        },
        owner,
        redirect_uri: provider.redirect_uri().to_string(),
        state: Some(state_token.clone()),
        scopes: request.scopes.clone(),
        code_challenge: Some(pkce.challenge.clone()),
        code_challenge_method: Some("S256".to_string()),
    };

    let redirect = provider.build_authorize_redirect(&oauth_request)?;

    let attrs = AuditAttributes {
        env: &request.env,
        tenant: &request.tenant,
        team: request.team.as_deref(),
        provider: &request.provider,
    };
    let audit_data = json!({
        "flow_id": request.flow_id.clone(),
        "owner_kind": request.owner_kind.as_str(),
        "owner_id": request.owner_id.clone(),
        "scopes": request.scopes.clone(),
        "visibility": request.visibility.as_str(),
        "redirect_uri": request.redirect_uri.clone(),
    });

    audit::emit(&ctx.publisher, "started", &attrs, audit_data).await;

    Ok((redirect.redirect_url, state_token, flow_state))
}

pub async fn start<S>(
    Path(StartPath {
        env,
        tenant,
        provider,
    }): Path<StartPath>,
    Query(StartQuery {
        team,
        owner_kind,
        owner_id,
        flow_id,
        scopes,
        redirect_uri,
        visibility,
    }): Query<StartQuery>,
    State(ctx): State<SharedContext<S>>,
) -> Result<impl IntoResponse, AppError>
where
    S: SecretsManager + 'static,
{
    let owner_kind_key = OwnerKindKey::from_str(owner_kind.as_str())
        .map_err(|_| AppError::bad_request("invalid owner_kind"))?;

    let visibility = parse_visibility(visibility)?;
    let scopes_list = parse_scopes(scopes);
    let start_request = StartRequest {
        env,
        tenant,
        provider,
        team,
        owner_kind: owner_kind_key,
        owner_id,
        flow_id,
        scopes: scopes_list,
        redirect_uri,
        visibility,
    };

    let (redirect_url, _, _) = process_start(&ctx, &start_request).await?;

    Ok(Redirect::temporary(redirect_url.as_str()))
}
