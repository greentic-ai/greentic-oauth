use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{
    http::state::FlowState,
    security::{CsrfKey, SecurityError},
};

/// Canonical state payload embedded in the OAuth `state` parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateClaims {
    pub sid: String,
    pub tenant: String,
    pub team: Option<String>,
    pub user: String,
    pub nonce: String,
    pub ts: u64,
}

impl StateClaims {
    pub fn new(session_id: impl Into<String>, flow_state: &FlowState) -> Self {
        Self {
            sid: session_id.into(),
            tenant: flow_state.tenant.clone(),
            team: flow_state.team.clone(),
            user: flow_state.owner_id.clone(),
            nonce: flow_state.nonce.clone(),
            ts: current_epoch_seconds(),
        }
    }

    pub fn sign(&self, csrf: &CsrfKey) -> Result<String, SecurityError> {
        let payload = self.canonical_json();
        csrf.seal("state", &payload)
    }

    pub fn canonical_json(&self) -> String {
        let sid = serde_json::to_string(&self.sid).unwrap();
        let tenant = serde_json::to_string(&self.tenant).unwrap();
        let team = match &self.team {
            Some(value) => serde_json::to_string(value).unwrap(),
            None => "null".to_string(),
        };
        let user = serde_json::to_string(&self.user).unwrap();
        let nonce = serde_json::to_string(&self.nonce).unwrap();
        format!(
            "{{\"sid\":{sid},\"tenant\":{tenant},\"team\":{team},\"user\":{user},\"nonce\":{nonce},\"ts\":{ts}}}",
            ts = self.ts
        )
    }
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_flow_state() -> FlowState {
        FlowState::new(
            "prod",
            "acme",
            "fake",
            Some("team".into()),
            "flow-1",
            crate::storage::index::OwnerKindKey::User,
            "user-123",
            Some("https://app.example.com/callback".into()),
            None,
            vec!["offline_access".into()],
            crate::storage::models::Visibility::Private,
        )
    }

    #[test]
    fn canonical_json_has_stable_order() {
        let claims = StateClaims::new("01H", &sample_flow_state());
        let json = claims.canonical_json();
        assert!(json.starts_with("{\"sid\""));
        assert!(json.contains("\"team\":\"team\""));
    }

    #[test]
    fn sign_and_roundtrip() {
        let claims = StateClaims::new("01H", &sample_flow_state());
        let csrf = CsrfKey::new(&[7u8; 32]).expect("csrf");
        let token = claims.sign(&csrf).expect("sign");
        let payload = csrf.open("state", &token).expect("open");
        assert_eq!(payload, claims.canonical_json());
    }
}
