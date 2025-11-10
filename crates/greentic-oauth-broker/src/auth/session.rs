use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, SystemTime},
};

use crate::http::state::FlowState;

/// Active interactive OAuth session awaiting user authorization.
#[derive(Clone, Debug)]
pub struct AuthSession {
    pub id: String,
    pub provider: String,
    pub flow_state: FlowState,
    pub state_token: String,
    pub authorize_url: String,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

impl AuthSession {
    pub fn new(
        id: impl Into<String>,
        provider: impl Into<String>,
        flow_state: FlowState,
        state_token: impl Into<String>,
        authorize_url: impl Into<String>,
        ttl: Duration,
    ) -> Self {
        let created_at = SystemTime::now();
        let expires_at = created_at
            .checked_add(ttl)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        Self {
            id: id.into(),
            provider: provider.into(),
            flow_state,
            state_token: state_token.into(),
            authorize_url: authorize_url.into(),
            created_at,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        match SystemTime::now().duration_since(self.expires_at) {
            Ok(duration) => duration > Duration::from_secs(0),
            Err(_) => false,
        }
    }
}

/// Thread-safe in-memory store for interactive sessions.
pub struct AuthSessionStore {
    ttl: Duration,
    inner: RwLock<HashMap<String, AuthSession>>,
}

impl AuthSessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn insert(&self, session: AuthSession) {
        let mut guard = self.inner.write().expect("session store poisoned");
        guard.insert(session.id.clone(), session);
    }

    pub fn get(&self, id: &str) -> Option<AuthSession> {
        let mut guard = self.inner.write().expect("session store poisoned");
        if let Some(session) = guard.get(id) {
            if session.is_expired() {
                guard.remove(id);
                return None;
            }
            return Some(session.clone());
        }
        None
    }

    pub fn claim(&self, id: &str) -> Option<AuthSession> {
        let mut guard = self.inner.write().expect("session store poisoned");
        if let Some(session) = guard.remove(id) {
            if session.is_expired() {
                return None;
            }
            return Some(session);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_expires_after_ttl() {
        let store = AuthSessionStore::new(Duration::from_secs(1));
        let flow = FlowState::new(
            "env",
            "tenant",
            "provider",
            None,
            "flow",
            crate::storage::index::OwnerKindKey::User,
            "user",
            Some("https://app.example.com/cb".into()),
            "verifier",
            "challenge",
            vec!["scope".into()],
            crate::storage::models::Visibility::Private,
        );
        let session = AuthSession::new(
            "01H",
            "provider",
            flow,
            "state",
            "https://example.com/authorize",
            Duration::from_millis(10),
        );
        store.insert(session);
        std::thread::sleep(Duration::from_millis(20));
        assert!(store.get("01H").is_none());
    }
}
