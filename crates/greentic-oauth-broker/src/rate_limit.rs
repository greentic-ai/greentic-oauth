use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

#[derive(Debug)]
pub struct RateLimiter {
    inner: Mutex<HashMap<String, Vec<Instant>>>,
    max: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max,
            window,
        }
    }

    pub async fn check(&self, key: &str) -> Result<(), RateLimitError> {
        let mut guard = self.inner.lock().await;
        let now = Instant::now();
        let entries = guard.entry(key.to_string()).or_default();
        entries.retain(|ts| now.saturating_duration_since(*ts) < self.window);
        if entries.len() >= self.max {
            return Err(RateLimitError);
        }
        entries.push(now);
        Ok(())
    }
}

#[derive(Debug)]
pub struct RateLimitError;

pub fn key(env: &str, tenant: &str, team: Option<&str>, provider: &str) -> String {
    format!("{}:{}:{}:{}", env, tenant, team.unwrap_or("_"), provider)
}
