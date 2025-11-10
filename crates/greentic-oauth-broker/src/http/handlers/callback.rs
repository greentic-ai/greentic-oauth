use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use greentic_oauth_core::types::{OwnerKind, TenantCtx as BrokerTenantCtx, TokenHandleClaims};
use greentic_types::{TenantCtx as TelemetryTenantCtx, telemetry::set_current_tenant_ctx};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    audit::{self, AuditAttributes},
    auth::{AuthSession, StateClaims, record_callback_failure, record_callback_success},
    http::{error::AppError, state::FlowState, util::ensure_secure_request},
    ids::{parse_env_id, parse_team_id, parse_tenant_id, parse_user_id},
    rate_limit,
    storage::{index::ConnectionKey, models::Connection, secrets_manager::SecretsManager},
    tokens::StoredToken,
};

use super::super::SharedContext;

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

pub async fn complete<S>(
    Query(CallbackQuery { code, state, error }): Query<CallbackQuery>,
    headers: HeaderMap,
    State(ctx): State<SharedContext<S>>,
) -> Result<impl IntoResponse, AppError>
where
    S: SecretsManager + 'static,
{
    ensure_secure_request(&headers, ctx.allow_insecure)?;

    let unknown_attrs = AuditAttributes {
        env: "unknown",
        tenant: "unknown",
        team: None,
        provider: "unknown",
    };

    let state_token = match state {
        Some(token) => token,
        None => {
            audit::emit(
                &ctx.publisher,
                "callback_error",
                &unknown_attrs,
                json!({
                    "flow_id": serde_json::Value::Null,
                    "reason": "missing_state",
                    "error": "state parameter missing",
                }),
            )
            .await;
            record_callback_failure("unknown", None, StatusCode::BAD_REQUEST, "missing_state");
            return Err(AppError::bad_request("missing state"));
        }
    };

    let payload = match ctx.security.csrf.open("state", &state_token) {
        Ok(value) => value,
        Err(err) => {
            audit::emit(
                &ctx.publisher,
                "callback_error",
                &unknown_attrs,
                json!({
                    "flow_id": serde_json::Value::Null,
                    "reason": "invalid_state_token",
                    "error": err.to_string(),
                }),
            )
            .await;
            record_callback_failure(
                "unknown",
                None,
                StatusCode::BAD_REQUEST,
                "invalid_state_token",
            );
            return Err(err.into());
        }
    };

    if let Ok(state_claims) = serde_json::from_str::<StateClaims>(&payload) {
        let session = match ctx.sessions.claim(&state_claims.sid) {
            Some(session) => session,
            None => {
                audit::emit(
                    &ctx.publisher,
                    "callback_error",
                    &unknown_attrs,
                    json!({
                        "flow_id": serde_json::Value::Null,
                        "reason": "session_not_found",
                        "error": "authorization session expired or already claimed",
                    }),
                )
                .await;
                record_callback_failure(
                    "unknown",
                    None,
                    StatusCode::BAD_REQUEST,
                    "session_not_found",
                );
                return Err(AppError::bad_request("authorization session expired"));
            }
        };
        let response =
            complete_session_flow(&ctx, code.clone(), error.clone(), session, state_claims).await?;
        return Ok(response);
    }

    let flow_state: FlowState = match serde_json::from_str(&payload) {
        Ok(flow) => flow,
        Err(err) => {
            audit::emit(
                &ctx.publisher,
                "callback_error",
                &unknown_attrs,
                json!({
                    "flow_id": serde_json::Value::Null,
                    "reason": "invalid_state_payload",
                    "error": err.to_string(),
                }),
            )
            .await;
            record_callback_failure(
                "unknown",
                None,
                StatusCode::BAD_REQUEST,
                "invalid_state_payload",
            );
            return Err(err.into());
        }
    };

    let response = complete_flow_core(&ctx, code, error, flow_state, None).await?;
    Ok(response)
}

async fn complete_session_flow<S>(
    ctx: &SharedContext<S>,
    code: Option<String>,
    error: Option<String>,
    session: AuthSession,
    state_claims: StateClaims,
) -> Result<Response, AppError>
where
    S: SecretsManager + 'static,
{
    let latency_ms = session
        .created_at
        .elapsed()
        .ok()
        .map(|duration| duration.as_secs_f64() * 1000.0);
    let flow_state = session.flow_state;
    let attrs = build_audit_attrs(&flow_state);

    if state_claims.tenant != flow_state.tenant
        || state_claims.team != flow_state.team
        || state_claims.user != flow_state.owner_id
        || state_claims.nonce != flow_state.nonce
    {
        audit::emit(
            &ctx.publisher,
            "callback_error",
            &attrs,
            json!({
                "flow_id": flow_state.flow_id.clone(),
                "reason": "state_mismatch",
                "error": "state claims mismatch session",
            }),
        )
        .await;
        emit_auth_failure(ctx, &flow_state, "state_mismatch").await;
        record_callback_failure(
            &flow_state.provider,
            latency_ms,
            StatusCode::BAD_REQUEST,
            "state_mismatch",
        );
        return Err(AppError::bad_request("state validation failed"));
    }

    complete_flow_core(ctx, code, error, flow_state, latency_ms).await
}

async fn complete_flow_core<S>(
    ctx: &SharedContext<S>,
    code: Option<String>,
    error: Option<String>,
    flow_state: FlowState,
    latency_ms: Option<f64>,
) -> Result<Response, AppError>
where
    S: SecretsManager + 'static,
{
    let mut telemetry_ctx = TelemetryTenantCtx::new(
        parse_env_id(flow_state.env.as_str())?,
        parse_tenant_id(flow_state.tenant.as_str())?,
    )
    .with_flow(flow_state.flow_id.clone())
    .with_provider(flow_state.provider.clone())
    .with_user(Some(parse_user_id(flow_state.owner_id.as_str())?));

    if let Some(team) = flow_state.team.as_ref() {
        telemetry_ctx = telemetry_ctx.with_team(Some(parse_team_id(team.as_str())?));
    }

    set_current_tenant_ctx(&telemetry_ctx);

    let attrs = build_audit_attrs(&flow_state);
    let flow_id = flow_state.flow_id.clone();

    let rate_key = rate_limit::key(
        &flow_state.env,
        &flow_state.tenant,
        flow_state.team.as_deref(),
        &flow_state.provider,
    );
    if ctx.rate_limiter.check(&rate_key).await.is_err() {
        audit::emit(
            &ctx.publisher,
            "callback_error",
            &attrs,
            json!({
                "flow_id": flow_id,
                "reason": "rate_limited",
                "error": "rate limit exceeded",
            }),
        )
        .await;
        emit_auth_failure(ctx, &flow_state, "rate_limited").await;
        record_callback_failure(
            &flow_state.provider,
            latency_ms,
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
        );
        return Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        ));
    }

    if let Some(err_msg) = error {
        audit::emit(
            &ctx.publisher,
            "callback_error",
            &attrs,
            json!({
                "flow_id": flow_state.flow_id.clone(),
                "reason": "provider_error",
                "error": err_msg,
            }),
        )
        .await;
        emit_auth_failure(ctx, &flow_state, "provider_error").await;
        record_callback_failure(
            &flow_state.provider,
            latency_ms,
            StatusCode::BAD_REQUEST,
            "provider_error",
        );
        return Err(AppError::bad_request(format!(
            "provider returned error: {err_msg}",
        )));
    }

    let code = match code {
        Some(value) => value,
        None => {
            audit::emit(
                &ctx.publisher,
                "callback_error",
                &attrs,
                json!({
                    "flow_id": flow_state.flow_id.clone(),
                    "reason": "missing_code",
                    "error": "missing code parameter",
                }),
            )
            .await;
            emit_auth_failure(ctx, &flow_state, "missing_code").await;
            record_callback_failure(
                &flow_state.provider,
                latency_ms,
                StatusCode::BAD_REQUEST,
                "missing_code",
            );
            return Err(AppError::bad_request("missing code"));
        }
    };

    let provider = match ctx.providers.get(&flow_state.provider) {
        Some(p) => p,
        None => {
            audit::emit(
                &ctx.publisher,
                "callback_error",
                &attrs,
                json!({
                    "flow_id": flow_state.flow_id.clone(),
                    "reason": "provider_not_registered",
                    "error": "provider not registered",
                }),
            )
            .await;
            emit_auth_failure(ctx, &flow_state, "provider_not_registered").await;
            record_callback_failure(
                &flow_state.provider,
                latency_ms,
                StatusCode::NOT_FOUND,
                "provider_not_registered",
            );
            return Err(AppError::not_found("provider not registered"));
        }
    };

    let owner_kind = match flow_state.owner_kind {
        crate::storage::index::OwnerKindKey::User => OwnerKind::User {
            subject: flow_state.owner_id.clone(),
        },
        crate::storage::index::OwnerKindKey::Service => OwnerKind::Service {
            subject: flow_state.owner_id.clone(),
        },
    };

    let tenant_ctx = BrokerTenantCtx {
        env: flow_state.env.clone(),
        tenant: flow_state.tenant.clone(),
        team: flow_state.team.clone(),
    };

    let mut claims = TokenHandleClaims {
        provider: flow_state.provider.clone(),
        subject: flow_state.owner_id.clone(),
        owner: owner_kind.clone(),
        tenant: tenant_ctx.clone(),
        scopes: flow_state.scopes.clone(),
        issued_at: current_epoch_seconds(),
        expires_at: current_epoch_seconds(),
    };

    let pkce_hint = flow_state.pkce_verifier.clone();
    let token_set = match provider.exchange_code(&claims, &code, pkce_hint.as_deref()) {
        Ok(tokens) => tokens,
        Err(err) => {
            let app_err: AppError = err.into();
            audit::emit(
                &ctx.publisher,
                "callback_error",
                &attrs,
                json!({
                    "flow_id": flow_state.flow_id.clone(),
                    "reason": "exchange_failed",
                    "error": app_err.to_string(),
                }),
            )
            .await;
            emit_auth_failure(ctx, &flow_state, "exchange_failed").await;
            record_callback_failure(
                &flow_state.provider,
                latency_ms,
                StatusCode::BAD_GATEWAY,
                "exchange_failed",
            );
            return Err(app_err);
        }
    };

    if let Some(expires) = token_set.expires_in {
        claims.expires_at = claims.issued_at.saturating_add(expires);
    }

    let ciphertext = match ctx.security.jwe.encrypt(&token_set) {
        Ok(value) => value,
        Err(err) => {
            audit::emit(
                &ctx.publisher,
                "callback_error",
                &attrs,
                json!({
                    "flow_id": flow_state.flow_id.clone(),
                    "reason": "encrypt_failed",
                    "error": err.to_string(),
                }),
            )
            .await;
            emit_auth_failure(ctx, &flow_state, "encrypt_failed").await;
            record_callback_failure(
                &flow_state.provider,
                latency_ms,
                StatusCode::INTERNAL_SERVER_ERROR,
                "encrypt_failed",
            );
            return Err(err.into());
        }
    };
    let stored = StoredToken::new(ciphertext, Some(claims.expires_at));

    let secret_path = match flow_state.secret_path() {
        Ok(path) => path,
        Err(err) => {
            audit::emit(
                &ctx.publisher,
                "callback_error",
                &attrs,
                json!({
                    "flow_id": flow_state.flow_id.clone(),
                    "reason": "secret_path_failed",
                    "error": err.to_string(),
                }),
            )
            .await;
            emit_auth_failure(ctx, &flow_state, "secret_path_failed").await;
            record_callback_failure(
                &flow_state.provider,
                latency_ms,
                StatusCode::INTERNAL_SERVER_ERROR,
                "secret_path_failed",
            );
            return Err(err.into());
        }
    };
    if let Err(err) = ctx.secrets.put_json(&secret_path, &stored) {
        audit::emit(
            &ctx.publisher,
            "callback_error",
            &attrs,
            json!({
                "flow_id": flow_state.flow_id.clone(),
                "reason": "secret_store_failed",
                "error": err.to_string(),
            }),
        )
        .await;
        emit_auth_failure(ctx, &flow_state, "secret_store_failed").await;
        record_callback_failure(
            &flow_state.provider,
            latency_ms,
            StatusCode::INTERNAL_SERVER_ERROR,
            "secret_store_failed",
        );
        return Err(err.into());
    }

    let redirect_target = flow_state.redirect_uri.clone();

    let connection_key = ConnectionKey::from_owner(
        flow_state.env.clone(),
        flow_state.tenant.clone(),
        flow_state.team.clone(),
        &owner_kind,
        flow_state.owner_id.clone(),
    );
    let connection = Connection::new(
        flow_state.visibility.clone(),
        flow_state.provider.clone(),
        flow_state.owner_id.clone(),
        secret_path.as_str(),
    );
    ctx.index.upsert(connection_key, connection);

    let event = CallbackEventPayload {
        flow_id: flow_state.flow_id.clone(),
        env: flow_state.env.clone(),
        tenant: flow_state.tenant.clone(),
        team: flow_state.team.clone(),
        provider: flow_state.provider.clone(),
        token_handle: claims.clone(),
        storage_path: secret_path.as_str().to_string(),
    };
    let team_segment = event.team.as_deref().unwrap_or("_");
    let subject = format!(
        "oauth.res.{}.{}.{}.{}.{}",
        &event.tenant, &event.env, team_segment, &event.provider, &event.flow_id
    );
    let event_bytes = match serde_json::to_vec(&event) {
        Ok(bytes) => bytes,
        Err(err) => {
            audit::emit(
                &ctx.publisher,
                "callback_error",
                &attrs,
                json!({
                    "flow_id": flow_state.flow_id.clone(),
                    "reason": "event_encode_failed",
                    "error": err.to_string(),
                }),
            )
            .await;
            emit_auth_failure(ctx, &flow_state, "event_encode_failed").await;
            record_callback_failure(
                &flow_state.provider,
                latency_ms,
                StatusCode::INTERNAL_SERVER_ERROR,
                "event_encode_failed",
            );
            return Err(err.into());
        }
    };
    if let Err(err) = ctx.publisher.publish(&subject, &event_bytes).await {
        audit::emit(
            &ctx.publisher,
            "callback_error",
            &attrs,
            json!({
                "flow_id": flow_state.flow_id.clone(),
                "reason": "event_publish_failed",
                "error": err.to_string(),
            }),
        )
        .await;
        emit_auth_failure(ctx, &flow_state, "event_publish_failed").await;
        record_callback_failure(
            &flow_state.provider,
            latency_ms,
            StatusCode::INTERNAL_SERVER_ERROR,
            "event_publish_failed",
        );
        return Err(err.into());
    }

    audit::emit(
        &ctx.publisher,
        "callback_success",
        &attrs,
        json!({
            "flow_id": flow_state.flow_id.clone(),
            "owner_id": flow_state.owner_id.clone(),
            "visibility": flow_state.visibility.as_str(),
            "storage_path": secret_path.as_str(),
        }),
    )
    .await;

    emit_auth_success(ctx, &flow_state, &claims).await;

    let status = if redirect_target.is_some() {
        StatusCode::TEMPORARY_REDIRECT
    } else {
        StatusCode::OK
    };
    record_callback_success(&flow_state.provider, latency_ms, status);

    let response = if let Some(target) = redirect_target {
        Redirect::temporary(&target).into_response()
    } else {
        (StatusCode::OK, "ok").into_response()
    };

    Ok(response)
}

fn build_audit_attrs<'a>(flow_state: &'a FlowState) -> AuditAttributes<'a> {
    AuditAttributes {
        env: &flow_state.env,
        tenant: &flow_state.tenant,
        team: flow_state.team.as_deref(),
        provider: &flow_state.provider,
    }
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[derive(Serialize)]
struct CallbackEventPayload {
    flow_id: String,
    env: String,
    tenant: String,
    team: Option<String>,
    provider: String,
    token_handle: TokenHandleClaims,
    storage_path: String,
}

#[derive(Serialize)]
struct AuthSuccessEvent<'a> {
    tenant: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    team: Option<&'a str>,
    user: &'a str,
    provider: &'a str,
    subject: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
}

#[derive(Serialize)]
struct AuthFailureEvent<'a> {
    tenant: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    team: Option<&'a str>,
    user: &'a str,
    provider: &'a str,
    reason: &'a str,
}

async fn emit_auth_success<S>(
    ctx: &SharedContext<S>,
    flow_state: &FlowState,
    claims: &TokenHandleClaims,
) where
    S: SecretsManager + 'static,
{
    let payload = AuthSuccessEvent {
        tenant: &flow_state.tenant,
        team: flow_state.team.as_deref(),
        user: &flow_state.owner_id,
        provider: &flow_state.provider,
        subject: &claims.subject,
        display_name: None,
        email: None,
        expires_at: Some(claims.expires_at),
    };
    publish_domain_event(ctx, "auth.success", &payload).await;
}

async fn emit_auth_failure<S>(ctx: &SharedContext<S>, flow_state: &FlowState, reason: &str)
where
    S: SecretsManager + 'static,
{
    let payload = AuthFailureEvent {
        tenant: &flow_state.tenant,
        team: flow_state.team.as_deref(),
        user: &flow_state.owner_id,
        provider: &flow_state.provider,
        reason,
    };
    publish_domain_event(ctx, "auth.failure", &payload).await;
}

async fn publish_domain_event<S, P>(ctx: &SharedContext<S>, subject: &str, payload: &P)
where
    S: SecretsManager + 'static,
    P: Serialize,
{
    match serde_json::to_vec(payload) {
        Ok(bytes) => {
            if let Err(err) = ctx.publisher.publish(subject, &bytes).await {
                tracing::warn!(
                    %subject,
                    error = %err,
                    "failed to publish auth domain event"
                );
            }
        }
        Err(err) => {
            tracing::warn!(
                %subject,
                error = %err,
                "failed to encode auth domain event payload"
            );
        }
    }
}
