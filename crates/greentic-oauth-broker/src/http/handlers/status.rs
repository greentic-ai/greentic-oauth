use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;

use crate::{
    http::error::AppError,
    storage::{models::Connection, secrets_manager::SecretsManager},
    telemetry,
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
    telemetry::set_request_context(Some(tenant.as_str()), team.as_deref(), None, None);

    let connections = ctx
        .index
        .list_provider(&provider, &env, &tenant, team.as_deref());

    Ok(Json(connections))
}
