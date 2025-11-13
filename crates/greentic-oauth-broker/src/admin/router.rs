use super::models::{DesiredAppRequest, ProvisionReport};
use crate::{
    admin::{
        secrets::{NoopSecretStore, SecretStore},
        traits::{AdminActionContext, ProvisionContext},
    },
    http::{SharedContext, error::AppError},
    storage::secrets_manager::SecretsManager,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::json;
#[derive(Deserialize)]
pub struct StartQuery {
    pub tenant: String,
}

pub async fn list_providers<S>(
    State(ctx): State<SharedContext<S>>,
) -> Result<Json<Vec<serde_json::Value>>, AppError>
where
    S: SecretsManager + 'static,
{
    let payload = ctx
        .admin_registry
        .list()
        .into_iter()
        .map(|prov| {
            json!({
                "provider": prov.name(),
                "capabilities": prov.capabilities(),
            })
        })
        .collect();
    Ok(Json(payload))
}

pub async fn start<S>(
    Path(provider): Path<String>,
    Query(StartQuery { tenant }): Query<StartQuery>,
    State(ctx): State<SharedContext<S>>,
) -> Result<Json<serde_json::Value>, AppError>
where
    S: SecretsManager + 'static,
{
    let provisioner = ctx
        .admin_registry
        .get(&provider)
        .ok_or_else(|| AppError::not_found("provider not registered"))?;

    let store: &dyn SecretStore = ctx.secrets.as_ref();
    let action_ctx = AdminActionContext::new(store, ctx.admin_consent.as_ref());
    let redirect = provisioner
        .authorize_admin_start(action_ctx, &tenant)
        .map_err(|err| AppError::internal(err.to_string()))?;

    Ok(Json(match redirect {
        Some(url) => json!({ "redirect_url": url }),
        None => json!({ "started": false }),
    }))
}

pub async fn callback<S>(
    Path(provider): Path<String>,
    Query(params): Query<Vec<(String, String)>>,
    State(ctx): State<SharedContext<S>>,
) -> Result<StatusCode, AppError>
where
    S: SecretsManager + 'static,
{
    let tenant = params
        .iter()
        .find(|(k, _)| k == "tenant")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| AppError::bad_request("missing tenant parameter"))?;
    let provisioner = ctx
        .admin_registry
        .get(&provider)
        .ok_or_else(|| AppError::not_found("provider not registered"))?;
    let store: &dyn SecretStore = ctx.secrets.as_ref();
    let action_ctx = AdminActionContext::new(store, ctx.admin_consent.as_ref());
    provisioner
        .authorize_admin_callback(action_ctx, &tenant, &params)
        .map_err(|err| AppError::internal(err.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn ensure<S>(
    Path(provider): Path<String>,
    State(ctx): State<SharedContext<S>>,
    Json(body): Json<DesiredAppRequest>,
) -> Result<Json<ProvisionReport>, AppError>
where
    S: SecretsManager + 'static,
{
    let provisioner = ctx
        .admin_registry
        .get(&provider)
        .ok_or_else(|| AppError::not_found("provider not registered"))?;
    let store: &dyn SecretStore = ctx.secrets.as_ref();
    let provision_ctx = ProvisionContext::new(&body.tenant, store);
    let report = provisioner
        .ensure_application(provision_ctx, &body.desired)
        .map_err(|err| AppError::internal(err.to_string()))?;
    Ok(Json(report))
}

pub async fn plan<S>(
    Path(provider): Path<String>,
    State(ctx): State<SharedContext<S>>,
    Json(body): Json<DesiredAppRequest>,
) -> Result<Json<ProvisionReport>, AppError>
where
    S: SecretsManager + 'static,
{
    let provisioner = ctx
        .admin_registry
        .get(&provider)
        .ok_or_else(|| AppError::not_found("provider not registered"))?;
    let noop = NoopSecretStore;
    let provision_ctx = ProvisionContext::dry_run(&body.tenant, &noop);
    let report = provisioner
        .ensure_application(provision_ctx, &body.desired)
        .map_err(|err| AppError::internal(err.to_string()))?;
    Ok(Json(report))
}

pub fn router<S>() -> axum::Router<SharedContext<S>>
where
    S: SecretsManager + 'static,
{
    use axum::routing::{get, post};
    let mut router = axum::Router::new()
        .route("/providers", get(list_providers))
        .route("/providers/{provider}/start", post(start))
        .route("/providers/{provider}/callback", get(callback))
        .route("/providers/{provider}/ensure", post(ensure))
        .route("/providers/{provider}/plan", post(plan));

    #[cfg(feature = "admin-ms")]
    {
        router = router.nest("/messaging/teams", crate::admin::messaging::teams::router());
    }

    router
}
