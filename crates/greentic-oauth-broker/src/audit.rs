use serde_json::{Value, json};
use tracing::{info, warn};

use crate::events::SharedPublisher;

#[derive(Clone, Debug)]
pub struct AuditAttributes<'a> {
    pub env: &'a str,
    pub tenant: &'a str,
    pub team: Option<&'a str>,
    pub provider: &'a str,
}

pub async fn emit(
    publisher: &SharedPublisher,
    action: &str,
    attrs: &AuditAttributes<'_>,
    data: Value,
) {
    let team_segment = attrs.team.unwrap_or("_");
    let subject = format!(
        "oauth.audit.{}.{}.{}.{}.{}",
        attrs.env, attrs.tenant, team_segment, attrs.provider, action
    );
    let payload = json!({
        "action": action,
        "env": attrs.env,
        "tenant": attrs.tenant,
        "team": attrs.team,
        "provider": attrs.provider,
        "data": data,
        "timestamp": current_epoch_seconds(),
    });

    let log = AuditLogFields::new(action, attrs, &data);

    info!(
        target: "oauth.audit",
        action = log.action,
        env = log.env,
        tenant = log.tenant,
        team = log.team,
        provider = log.provider,
        flow_id = log.flow_id.as_deref(),
        owner_id = log.owner_id.as_deref(),
        visibility = log.visibility.as_deref(),
        storage_path = log.storage_path.as_deref(),
        reason = log.reason.as_deref(),
        error_message = log.error.as_deref(),
        subject = %subject,
        event = %payload,
        "audit event recorded"
    );

    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(err) = publisher.publish(&subject, &bytes).await {
                warn!(
                    target: "oauth.audit",
                    action = log.action,
                    env = log.env,
                    tenant = log.tenant,
                    team = log.team,
                    provider = log.provider,
                    flow_id = log.flow_id.as_deref(),
                    owner_id = log.owner_id.as_deref(),
                    visibility = log.visibility.as_deref(),
                    storage_path = log.storage_path.as_deref(),
                    reason = log.reason.as_deref(),
                    error_message = log.error.as_deref(),
                    subject = %subject,
                    publish_error = %err,
                    "failed to publish audit event"
                );
            }
        }
        Err(err) => warn!(
            target: "oauth.audit",
            action = log.action,
            env = log.env,
            tenant = log.tenant,
            team = log.team,
            provider = log.provider,
            flow_id = log.flow_id.as_deref(),
            owner_id = log.owner_id.as_deref(),
            visibility = log.visibility.as_deref(),
            storage_path = log.storage_path.as_deref(),
            reason = log.reason.as_deref(),
            error_message = log.error.as_deref(),
            event = %payload,
            encode_error = %err,
            "failed to encode audit payload"
        ),
    }
}

fn current_epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

struct AuditLogFields<'a> {
    action: &'a str,
    env: &'a str,
    tenant: &'a str,
    team: &'a str,
    provider: &'a str,
    flow_id: Option<String>,
    owner_id: Option<String>,
    visibility: Option<String>,
    storage_path: Option<String>,
    reason: Option<String>,
    error: Option<String>,
}

impl<'a> AuditLogFields<'a> {
    fn new(action: &'a str, attrs: &'a AuditAttributes<'_>, data: &Value) -> Self {
        Self {
            action,
            env: attrs.env,
            tenant: attrs.tenant,
            team: attrs.team.unwrap_or("_"),
            provider: attrs.provider,
            flow_id: value_as_string(data, "flow_id"),
            owner_id: value_as_string(data, "owner_id"),
            visibility: value_as_string(data, "visibility"),
            storage_path: value_as_string(data, "storage_path"),
            reason: value_as_string(data, "reason"),
            error: value_as_string(data, "error"),
        }
    }
}

fn value_as_string(data: &Value, key: &str) -> Option<String> {
    data.get(key).map(|value| match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}
