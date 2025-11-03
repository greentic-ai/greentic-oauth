use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Generic interface for storing PKCE code verifiers keyed by state.
pub trait CodeVerifierStore: Send + Sync {
    fn put(&self, state: String, verifier: String, ttl: Duration);
    fn take(&self, state: &str) -> Option<String>;
}

#[derive(Debug)]
struct Entry {
    verifier: String,
    expires_at: Instant,
}

/// In-memory implementation backed by a mutex protected hash map.
#[derive(Debug, Default)]
pub struct InMemoryCodeVerifierStore {
    entries: Mutex<HashMap<String, Entry>>,
}

impl InMemoryCodeVerifierStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn purge_expired(entries: &mut HashMap<String, Entry>) {
        let now = Instant::now();
        entries.retain(|_, entry| entry.expires_at > now);
    }
}

impl CodeVerifierStore for InMemoryCodeVerifierStore {
    fn put(&self, state: String, verifier: String, ttl: Duration) {
        let expires_at = Instant::now() + ttl;
        let mut guard = self.entries.lock().expect("verifier store lock");
        Self::purge_expired(&mut guard);
        guard.insert(
            state,
            Entry {
                verifier,
                expires_at,
            },
        );
    }

    fn take(&self, state: &str) -> Option<String> {
        let mut guard = self.entries.lock().expect("verifier store lock");
        Self::purge_expired(&mut guard);
        guard.remove(state).and_then(|entry| {
            if entry.expires_at > Instant::now() {
                Some(entry.verifier)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    #[test]
    fn put_and_take_roundtrip() {
        let store = InMemoryCodeVerifierStore::new();
        store.put(
            "state-123".into(),
            "verifier".into(),
            Duration::from_secs(5),
        );
        assert_eq!(store.take("state-123"), Some("verifier".into()));
        assert_eq!(store.take("state-123"), None);
    }

    #[test]
    fn expired_entries_are_dropped() {
        let store = InMemoryCodeVerifierStore::new();
        store.put(
            "state-exp".into(),
            "verifier".into(),
            Duration::from_millis(50),
        );
        thread::sleep(Duration::from_millis(70));
        assert_eq!(store.take("state-exp"), None);
    }
}
