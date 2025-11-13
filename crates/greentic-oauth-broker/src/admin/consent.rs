use std::{
    collections::{BTreeMap, HashMap},
    sync::RwLock,
    time::{Duration, Instant},
};

/// Ephemeral state tracking an in-flight admin consent (PKCE) exchange.
#[derive(Clone, Debug)]
pub struct AdminConsentState {
    pub provider: String,
    pub tenant: String,
    pub redirect_uri: String,
    pub pkce_verifier: String,
    pub extras: BTreeMap<String, String>,
    created_at: Instant,
}

impl AdminConsentState {
    pub fn new(
        provider: impl Into<String>,
        tenant: impl Into<String>,
        redirect_uri: impl Into<String>,
        pkce_verifier: impl Into<String>,
        extras: BTreeMap<String, String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            tenant: tenant.into(),
            redirect_uri: redirect_uri.into(),
            pkce_verifier: pkce_verifier.into(),
            extras,
            created_at: Instant::now(),
        }
    }

    pub fn extras(&self, key: &str) -> Option<&str> {
        self.extras.get(key).map(|s| s.as_str())
    }
}

/// In-memory store of pending admin consent states.
pub struct AdminConsentStore {
    ttl: Duration,
    inner: RwLock<HashMap<String, AdminConsentState>>,
}

impl AdminConsentStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert(&self, state: String, consent: AdminConsentState) {
        let mut guard = self.inner.write().expect("consent store poisoned");
        guard.insert(state, consent);
    }

    pub fn claim(&self, state: &str) -> Option<AdminConsentState> {
        let mut guard = self.inner.write().expect("consent store poisoned");
        guard.remove(state).and_then(|consent| {
            if consent.created_at + self.ttl < Instant::now() {
                None
            } else {
                Some(consent)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_claims_before_expiry() {
        let store = AdminConsentStore::new(Duration::from_secs(60));
        let mut extras = BTreeMap::new();
        extras.insert("issuer".into(), "https://example.com".into());
        store.insert(
            "state".into(),
            AdminConsentState::new("okta", "tenant", "https://cb", "verifier", extras),
        );
        assert!(store.claim("state").is_some());
        assert!(store.claim("state").is_none());
    }

    #[test]
    fn drops_expired_states() {
        let store = AdminConsentStore::new(Duration::from_millis(5));
        store.insert(
            "state".into(),
            AdminConsentState::new("okta", "tenant", "https://cb", "verifier", BTreeMap::new()),
        );
        std::thread::sleep(Duration::from_millis(10));
        assert!(store.claim("state").is_none());
    }
}
