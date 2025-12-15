use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use serde_json;

use crate::{
    admin::{
        models::{
            CredentialPolicy, DesiredApp, DesiredAppRequest, DesiredResource,
            DesiredTenantMetadata, ProvisionReport,
        },
        providers::microsoft::{MicrosoftProvisioner, TeamsPlanReport},
        secrets::{
            SecretStore, messaging_tenant_path, read_string_secret_at, write_string_secret_at,
        },
        traits::{AdminProvisioner, ProvisionContext},
    },
    http::{SharedContext, error::AppError},
    storage::secrets_manager::SecretsManager,
};

#[derive(Deserialize)]
struct TenantQuery {
    tenant: String,
}

#[derive(Deserialize)]
struct TeamInstallRequest {
    tenant: String,
    team_id: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TeamsPayload {
    Legacy(DesiredAppRequest),
    Spec(TeamsTenantRequest),
}

#[derive(Clone, Deserialize, Serialize)]
struct TeamsTenantRequest {
    tenant_key: String,
    provider_tenant_id: String,
    #[serde(default)]
    requested_scopes: Vec<String>,
    #[serde(default)]
    resources: Vec<TeamsResource>,
    #[serde(default)]
    credential_policy: Option<CredentialPolicy>,
    #[serde(default)]
    extra_params: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TeamsResource {
    Team {
        id: String,
        #[serde(default)]
        display_name: Option<String>,
    },
    Channel {
        id: String,
        #[serde(default)]
        display_name: Option<String>,
    },
}

pub fn router<S>() -> Router<SharedContext<S>>
where
    S: SecretsManager + 'static,
{
    Router::new()
        .route("/tenant/plan", post(plan::<S>))
        .route("/tenant/ensure", post(ensure::<S>))
        .route("/tenant/install", post(install_team::<S>))
        .route("/tenant/spec", get(get_spec::<S>))
        .route("/tenant/team/{team_id}", delete(remove_team::<S>))
}

async fn plan<S>(
    State(ctx): State<SharedContext<S>>,
    Json(payload): Json<TeamsPayload>,
) -> Result<Json<TeamsPlanReport>, AppError>
where
    S: SecretsManager + 'static,
{
    let (request, _) = normalize_payload(payload)?;
    let store: Arc<dyn SecretStore> = ctx.secrets.clone();
    let provisioner = MicrosoftProvisioner::new(Some(store.clone()));
    let provision_ctx = ProvisionContext::dry_run(&request.tenant, store.as_ref());
    let report = provisioner
        .plan_tenant(&provision_ctx, &request.desired)
        .map_err(|err| AppError::internal(err.to_string()))?;
    Ok(Json(report))
}

async fn ensure<S>(
    State(ctx): State<SharedContext<S>>,
    Json(payload): Json<TeamsPayload>,
) -> Result<Json<ProvisionReport>, AppError>
where
    S: SecretsManager + 'static,
{
    let (request, spec) = normalize_payload(payload)?;
    if let Some(spec) = spec {
        let store: Arc<dyn SecretStore> = ctx.secrets.clone();
        store_spec(store.as_ref(), &request.tenant, &spec)?;
    }

    let store: Arc<dyn SecretStore> = ctx.secrets.clone();
    let provisioner = MicrosoftProvisioner::new(Some(store.clone()));
    let provision_ctx = ProvisionContext::new(&request.tenant, store.as_ref());
    let report = provisioner
        .ensure_application(provision_ctx, &request.desired)
        .map_err(|err| AppError::internal(err.to_string()))?;
    Ok(Json(report))
}

async fn install_team<S>(
    State(ctx): State<SharedContext<S>>,
    Json(body): Json<TeamInstallRequest>,
) -> Result<Json<ProvisionReport>, AppError>
where
    S: SecretsManager + 'static,
{
    let store: Arc<dyn SecretStore> = ctx.secrets.clone();
    let provisioner = MicrosoftProvisioner::new(Some(store.clone()));
    let provision_ctx = ProvisionContext::new(&body.tenant, store.as_ref());
    let report = provisioner
        .ensure_single_team(&provision_ctx, &body.team_id)
        .map_err(|err| AppError::internal(err.to_string()))?;
    Ok(Json(report))
}

async fn remove_team<S>(
    State(ctx): State<SharedContext<S>>,
    Path(team_id): Path<String>,
    Query(TenantQuery { tenant }): Query<TenantQuery>,
) -> Result<Json<ProvisionReport>, AppError>
where
    S: SecretsManager + 'static,
{
    let store: Arc<dyn SecretStore> = ctx.secrets.clone();
    let provisioner = MicrosoftProvisioner::new(Some(store.clone()));
    let provision_ctx = ProvisionContext::new(&tenant, store.as_ref());
    let report = provisioner
        .remove_team(&provision_ctx, &team_id)
        .map_err(|err| AppError::internal(err.to_string()))?;
    prune_team_from_spec(store.as_ref(), &tenant, &team_id)?;
    Ok(Json(report))
}

async fn get_spec<S>(
    State(ctx): State<SharedContext<S>>,
    Query(TenantQuery { tenant }): Query<TenantQuery>,
) -> Result<Json<TeamsTenantRequest>, AppError>
where
    S: SecretsManager + 'static,
{
    let store = ctx.secrets.as_ref() as &dyn SecretStore;
    let spec =
        read_spec(store, &tenant)?.ok_or_else(|| AppError::not_found("teams spec not found"))?;
    Ok(Json(spec))
}

fn normalize_payload(
    payload: TeamsPayload,
) -> Result<(DesiredAppRequest, Option<TeamsTenantRequest>), AppError> {
    match payload {
        TeamsPayload::Legacy(request) => Ok((request, None)),
        TeamsPayload::Spec(spec) => {
            let request = spec.as_desired_app_request();
            Ok((request, Some(spec)))
        }
    }
}

impl TeamsTenantRequest {
    fn as_desired_app_request(&self) -> DesiredAppRequest {
        DesiredAppRequest {
            tenant: self.tenant_key.clone(),
            desired: DesiredApp {
                display_name: format!("Teams tenant {}", self.tenant_key),
                redirect_uris: Vec::new(),
                scopes: self.requested_scopes.clone(),
                audience: None,
                creds: self
                    .credential_policy
                    .clone()
                    .unwrap_or(CredentialPolicy::ClientSecret { rotate_days: 180 }),
                webhooks: None,
                extra_params: self.extra_params.clone(),
                resources: self
                    .resources
                    .iter()
                    .map(TeamsResource::to_desired_resource)
                    .collect(),
                tenant_metadata: Some(DesiredTenantMetadata {
                    provider_tenant_id: Some(self.provider_tenant_id.clone()),
                }),
            },
        }
    }
}

impl TeamsResource {
    fn to_desired_resource(&self) -> DesiredResource {
        match self {
            TeamsResource::Team { id, display_name } => DesiredResource {
                kind: "team".into(),
                id: id.clone(),
                display_name: display_name.clone(),
            },
            TeamsResource::Channel { id, display_name } => DesiredResource {
                kind: "channel".into(),
                id: id.clone(),
                display_name: display_name.clone(),
            },
        }
    }
}

fn spec_secret_path(tenant: &str) -> String {
    messaging_tenant_path(tenant, "teams", "spec.json")
}

fn store_spec(
    secrets: &dyn SecretStore,
    tenant: &str,
    spec: &TeamsTenantRequest,
) -> Result<(), AppError> {
    let path = spec_secret_path(tenant);
    let payload =
        serde_json::to_string_pretty(spec).map_err(|err| AppError::internal(err.to_string()))?;
    write_string_secret_at(secrets, &path, &payload)
        .map_err(|err| AppError::internal(err.to_string()))
}

fn prune_team_from_spec(
    secrets: &dyn SecretStore,
    tenant: &str,
    team_id: &str,
) -> Result<(), AppError> {
    let path = spec_secret_path(tenant);
    let Some(raw) =
        read_string_secret_at(secrets, &path).map_err(|err| AppError::internal(err.to_string()))?
    else {
        return Ok(());
    };
    let mut spec: TeamsTenantRequest =
        serde_json::from_str(&raw).map_err(|err| AppError::internal(err.to_string()))?;
    let before = spec.resources.len();
    spec.resources.retain(|resource| match resource {
        TeamsResource::Team { id, .. } => id != team_id,
        TeamsResource::Channel { id, .. } => !id.starts_with(&format!("{team_id}|")),
    });
    if spec.resources.len() == before {
        return Ok(());
    }
    store_spec(secrets, tenant, &spec)
}

fn read_spec(
    secrets: &dyn SecretStore,
    tenant: &str,
) -> Result<Option<TeamsTenantRequest>, AppError> {
    let path = spec_secret_path(tenant);
    let raw =
        read_string_secret_at(secrets, &path).map_err(|err| AppError::internal(err.to_string()))?;
    Ok(match raw {
        Some(data) => {
            Some(serde_json::from_str(&data).map_err(|err| AppError::internal(err.to_string()))?)
        }
        None => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::secrets_manager::{SecretPath, StorageError};
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemorySecrets {
        inner: Mutex<BTreeMap<String, serde_json::Value>>,
    }

    impl SecretStore for MemorySecrets {
        fn put_json_value(
            &self,
            path: &SecretPath,
            value: &serde_json::Value,
        ) -> Result<(), StorageError> {
            self.inner
                .lock()
                .unwrap()
                .insert(path.as_str().to_string(), value.clone());
            Ok(())
        }

        fn get_json_value(
            &self,
            path: &SecretPath,
        ) -> Result<Option<serde_json::Value>, StorageError> {
            Ok(self.inner.lock().unwrap().get(path.as_str()).cloned())
        }

        fn delete_value(&self, path: &SecretPath) -> Result<(), StorageError> {
            self.inner.lock().unwrap().remove(path.as_str());
            Ok(())
        }
    }

    #[test]
    fn spec_converts_to_desired_request() {
        let spec = TeamsTenantRequest {
            tenant_key: "acme".into(),
            provider_tenant_id: "tenant-guid".into(),
            requested_scopes: vec!["ChannelMessage.Read.Group".into()],
            resources: vec![
                TeamsResource::Team {
                    id: "19:team".into(),
                    display_name: Some("Support".into()),
                },
                TeamsResource::Channel {
                    id: "19:team|19:channel".into(),
                    display_name: None,
                },
            ],
            credential_policy: None,
            extra_params: None,
        };

        let request = spec.as_desired_app_request();
        assert_eq!(request.tenant, "acme");
        assert_eq!(
            request
                .desired
                .tenant_metadata
                .as_ref()
                .and_then(|meta| meta.provider_tenant_id.as_deref()),
            Some("tenant-guid")
        );
        assert_eq!(request.desired.resources.len(), 2);
    }

    #[test]
    fn prune_team_updates_spec_secret() {
        let store = MemorySecrets::default();
        let spec = TeamsTenantRequest {
            tenant_key: "acme".into(),
            provider_tenant_id: "tenant-guid".into(),
            requested_scopes: Vec::new(),
            resources: vec![
                TeamsResource::Team {
                    id: "19:team".into(),
                    display_name: None,
                },
                TeamsResource::Channel {
                    id: "19:team|19:channel".into(),
                    display_name: None,
                },
            ],
            credential_policy: None,
            extra_params: None,
        };
        store_spec(&store, "acme", &spec).unwrap();
        prune_team_from_spec(&store, "acme", "19:team").unwrap();
        let raw = read_string_secret_at(&store, &spec_secret_path("acme"))
            .unwrap()
            .unwrap();
        let stored: TeamsTenantRequest = serde_json::from_str(&raw).unwrap();
        assert!(stored.resources.is_empty());
    }
}
