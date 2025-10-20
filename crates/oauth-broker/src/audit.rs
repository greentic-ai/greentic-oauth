use serde_json::{json, Value};
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

    info!(
        target: "oauth_audit",
        action,
        env = attrs.env,
        tenant = attrs.tenant,
        team = team_segment,
        provider = attrs.provider,
        event = %payload
    );

    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(err) = publisher.publish(&subject, &bytes).await {
                warn!(%subject, error = %err, "failed to publish audit event");
            }
        }
        Err(err) => warn!(error = %err, "failed to encode audit payload"),
    }
}

fn current_epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}
