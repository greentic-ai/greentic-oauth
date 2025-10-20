use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use oauth_core::types::{OwnerKind, TenantCtx, TokenHandleClaims};
use serde::{Deserialize, Serialize};

use crate::{
    http::{error::AppError, state::FlowState},
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
    State(ctx): State<SharedContext<S>>,
) -> Result<impl IntoResponse, AppError>
where
    S: SecretsManager + 'static,
{
    if let Some(err) = error {
        return Err(AppError::bad_request(format!(
            "provider returned error: {err}"
        )));
    }

    let state_token = state.ok_or_else(|| AppError::bad_request("missing state"))?;
    let code = code.ok_or_else(|| AppError::bad_request("missing code"))?;

    let payload = ctx.security.csrf.open("state", &state_token)?;
    let flow_state: FlowState = serde_json::from_str(&payload)?;

    let provider = ctx
        .providers
        .get(&flow_state.provider)
        .ok_or_else(|| AppError::not_found("provider not registered"))?;

    let owner_kind = match flow_state.owner_kind {
        crate::storage::index::OwnerKindKey::User => OwnerKind::User {
            subject: flow_state.owner_id.clone(),
        },
        crate::storage::index::OwnerKindKey::Service => OwnerKind::Service {
            subject: flow_state.owner_id.clone(),
        },
    };

    let tenant_ctx = TenantCtx {
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

    let token_set = provider.exchange_code(&claims, &code)?;

    if let Some(expires) = token_set.expires_in {
        claims.expires_at = claims.issued_at.saturating_add(expires);
    }

    let ciphertext = ctx.security.jwe.encrypt(&token_set)?;
    let stored = StoredToken::new(ciphertext, Some(claims.expires_at));

    let secret_path = flow_state.secret_path()?;
    ctx.secrets.put_json(&secret_path, &stored)?;

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
    let event_bytes = serde_json::to_vec(&event)?;
    ctx.publisher.publish(&subject, &event_bytes).await?;

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
