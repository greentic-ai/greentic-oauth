use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;

use crate::{
    http::error::AppError,
    storage::{models::Connection, secrets_manager::SecretsManager},
};
use greentic_types::{
    EnvId, TeamId, TenantCtx as TelemetryTenantCtx, TenantId, telemetry::set_current_tenant_ctx,
};

use super::super::SharedContext;

#[derive(Deserialize)]
pub struct StatusPath {
    pub env: String,
    pub tenant: String,
    pub provider: String,
}

#[derive(Deserialize)]
pub struct StatusQuery {
    pub team: Option<String>,
}

pub async fn get_status<S>(
    Path(StatusPath {
        env,
        tenant,
        provider,
    }): Path<StatusPath>,
    Query(StatusQuery { team }): Query<StatusQuery>,
    State(ctx): State<SharedContext<S>>,
) -> Result<Json<Vec<Connection>>, AppError>
where
    S: SecretsManager + 'static,
{
    let mut telemetry_ctx =
        TelemetryTenantCtx::new(EnvId::from(env.as_str()), TenantId::from(tenant.as_str()))
            .with_provider(provider.clone());

    if let Some(team_id) = team.as_ref() {
        telemetry_ctx = telemetry_ctx.with_team(Some(TeamId::from(team_id.as_str())));
    }

    set_current_tenant_ctx(&telemetry_ctx);

    let connections = ctx
        .index
        .list_provider(&provider, &env, &tenant, team.as_deref());

    Ok(Json(connections))
}
