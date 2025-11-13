use axum::{
    Json,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{error, warn};

use crate::{
    admin::{
        providers::microsoft::MicrosoftProvisioner,
        secrets::{messaging_tenant_path, read_string_secret_at},
        traits::ProvisionContext,
    },
    events::PublishError,
    storage::secrets_manager::SecretsManager,
};

use super::super::SharedContext;

const TEAMS_PROVIDER_KEY: &str = "teams";

#[derive(Deserialize)]
pub struct GraphValidationQuery {
    #[serde(rename = "validationToken")]
    validation_token: Option<String>,
}

#[derive(Deserialize)]
pub struct GraphNotificationEnvelope {
    value: Vec<GraphNotificationValue>,
}

#[derive(Deserialize)]
struct GraphNotificationValue {
    #[serde(rename = "subscriptionId")]
    subscription_id: String,
    #[serde(rename = "clientState")]
    client_state: Option<String>,
    resource: String,
    #[serde(rename = "changeType")]
    change_type: Option<String>,
    #[serde(rename = "resourceData")]
    resource_data: Option<Value>,
}

pub async fn graph_validation(
    Path(_tenant): Path<String>,
    Query(GraphValidationQuery { validation_token }): Query<GraphValidationQuery>,
) -> impl IntoResponse {
    if let Some(token) = validation_token {
        let mut response = Response::new(token.into());
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            "text/plain; charset=utf-8".parse().unwrap(),
        );
        response
    } else {
        StatusCode::BAD_REQUEST.into_response()
    }
}

pub async fn graph_notify<S>(
    State(ctx): State<SharedContext<S>>,
    Path(tenant): Path<String>,
    Query(GraphValidationQuery { validation_token }): Query<GraphValidationQuery>,
    Json(envelope): Json<GraphNotificationEnvelope>,
) -> impl IntoResponse
where
    S: SecretsManager + 'static,
{
    if let Some(token) = validation_token {
        let mut response = Response::new(token.into());
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            "text/plain; charset=utf-8".parse().unwrap(),
        );
        return response;
    }

    for notification in &envelope.value {
        match verify_notification(ctx.secrets.as_ref(), &tenant, notification) {
            Ok(_) => {}
            Err(NotifyError::Authentication(reason)) => {
                warn!(
                    tenant = tenant.as_str(),
                    subscription_id = notification.subscription_id.as_str(),
                    %reason,
                    "rejecting Teams notification"
                );
                return StatusCode::UNAUTHORIZED.into_response();
            }
            Err(NotifyError::Storage(err)) => {
                error!(
                    tenant = tenant.as_str(),
                    subscription_id = notification.subscription_id.as_str(),
                    error = ?err,
                    "failed to read Teams webhook secret"
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    for notification in &envelope.value {
        if let Err(err) = dispatch_notification(&ctx, &tenant, notification).await {
            error!(
                tenant = tenant.as_str(),
                subscription_id = notification.subscription_id.as_str(),
                error = ?err,
                "failed to dispatch Teams change notification"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // Kick the reconciler to ensure the tenant stays in sync.
    let provisioner = MicrosoftProvisioner::new();
    let store = ctx.secrets.as_ref();
    let provision_ctx = ProvisionContext::new(&tenant, store);
    if let Err(err) = provisioner.reconcile_stored_tenant(&provision_ctx, None) {
        warn!(
            tenant = tenant.as_str(),
            error = %err,
            "Teams reconcile after webhook failed"
        );
    }

    StatusCode::ACCEPTED.into_response()
}

fn verify_notification<S>(
    secrets: &S,
    tenant: &str,
    notification: &GraphNotificationValue,
) -> Result<(), NotifyError>
where
    S: SecretsManager + 'static,
{
    let provided = notification
        .client_state
        .as_deref()
        .ok_or_else(|| NotifyError::Authentication("missing clientState".into()))?;
    let secret_path = subscription_secret_path(tenant, &notification.subscription_id);
    let expected = read_string_secret_at(secrets, &secret_path).map_err(NotifyError::Storage)?;
    let Some(expected) = expected else {
        return Err(NotifyError::Authentication(
            "subscription secret not found".into(),
        ));
    };
    if secure_equals(&expected, provided) {
        Ok(())
    } else {
        Err(NotifyError::Authentication("clientState mismatch".into()))
    }
}

async fn dispatch_notification<S>(
    ctx: &SharedContext<S>,
    tenant: &str,
    notification: &GraphNotificationValue,
) -> Result<(), PublishError>
where
    S: SecretsManager + 'static,
{
    let (team_id, channel_id) = parse_resource(&notification.resource);
    let subject = format!("admin.ms.teams.notify.{tenant}");
    let payload = json!({
        "tenant": tenant,
        "subscription_id": notification.subscription_id,
        "resource": notification.resource,
        "team_id": team_id,
        "channel_id": channel_id,
        "change_type": notification.change_type,
        "resource_data": notification.resource_data,
    });
    let bytes =
        serde_json::to_vec(&payload).map_err(|err| PublishError::Dispatch(err.to_string()))?;
    ctx.publisher.publish(&subject, &bytes).await
}

fn subscription_secret_path(tenant: &str, subscription_id: &str) -> String {
    messaging_tenant_path(
        tenant,
        TEAMS_PROVIDER_KEY,
        &format!("webhook_secret/{subscription_id}"),
    )
}

fn secure_equals(expected: &str, provided: &str) -> bool {
    use subtle::ConstantTimeEq;
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

enum NotifyError {
    Authentication(String),
    Storage(crate::storage::secrets_manager::StorageError),
}

fn parse_resource(resource: &str) -> (Option<String>, Option<String>) {
    // Expected formats:
    // /teams/{team}/channels/{channel}/messages
    // /teams/{team}/channels/getAllMessages
    let trimmed = resource.trim_matches('/');
    let segments: Vec<&str> = trimmed.split('/').collect();
    if segments.len() < 2 {
        return (None, None);
    }
    let mut team_id = None;
    let mut channel_id = None;
    let mut iter = segments.iter();
    while let Some(segment) = iter.next() {
        match *segment {
            "teams" => {
                team_id = iter.next().map(|s| (*s).to_string());
            }
            "channels" => {
                if let Some(next_seg) = iter.next()
                    && *next_seg != "getAllMessages"
                {
                    channel_id = Some((*next_seg).to_string());
                }
            }
            _ => {}
        }
    }
    (team_id, channel_id)
}
