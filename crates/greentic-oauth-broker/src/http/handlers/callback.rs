use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
};
use greentic_oauth_core::types::{OwnerKind, TenantCtx as BrokerTenantCtx, TokenHandleClaims};
use greentic_types::{
    EnvId, TeamId, TenantCtx as TelemetryTenantCtx, TenantId, UserId,
    telemetry::set_current_tenant_ctx,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    audit::{self, AuditAttributes},
    http::{error::AppError, state::FlowState, util::ensure_secure_request},
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
            return Err(err.into());
        }
    };

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
            return Err(err.into());
        }
    };

    let mut telemetry_ctx = TelemetryTenantCtx::new(
        EnvId::from(flow_state.env.as_str()),
        TenantId::from(flow_state.tenant.as_str()),
    )
    .with_flow(flow_state.flow_id.clone())
    .with_provider(flow_state.provider.clone())
    .with_user(Some(UserId::from(flow_state.owner_id.as_str())));

    if let Some(team) = flow_state.team.as_ref() {
        telemetry_ctx = telemetry_ctx.with_team(Some(TeamId::from(team.as_str())));
    }

    set_current_tenant_ctx(&telemetry_ctx);

    let attrs = AuditAttributes {
        env: &flow_state.env,
        tenant: &flow_state.tenant,
        team: flow_state.team.as_deref(),
        provider: &flow_state.provider,
    };
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
        return Err(AppError::bad_request(format!(
            "provider returned error: {err_msg}"
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

    let token_set = match provider.exchange_code(&claims, &code) {
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

    if let Some(target) = redirect_target {
        Ok(Redirect::temporary(&target).into_response())
    } else {
        Ok((StatusCode::OK, "ok").into_response())
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
