use std::collections::BTreeMap;

use greentic_telemetry::{Carrier, extract_carrier, inject_carrier};
use tracing::info;

/// Container for NATS header propagation.
#[derive(Clone, Debug, Default)]
pub struct NatsHeaders {
    inner: BTreeMap<String, String>,
}

impl NatsHeaders {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.inner.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.inner.get(key)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.inner.iter()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = String::from("NATS/1.0\r\n");
        for (key, value) in &self.inner {
            buffer.push_str(key);
            buffer.push_str(": ");
            buffer.push_str(value);
            buffer.push_str("\r\n");
        }
        buffer.push_str("\r\n");
        buffer.into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|err| format!("invalid NATS header encoding: {err}"))?;
        let mut lines = text.split("\r\n");
        let prelude = lines
            .next()
            .ok_or_else(|| "missing NATS header prelude".to_string())?;
        if prelude.trim() != "NATS/1.0" {
            return Err("unexpected NATS header prelude".to_string());
        }

        let mut headers = BTreeMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| format!("invalid header line `{line}`"))?;
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }

        Ok(Self { inner: headers })
    }
}

impl Carrier for NatsHeaders {
    fn set(&mut self, key: &str, value: String) {
        self.inner.insert(key.to_string(), value);
    }

    fn get(&self, key: &str) -> Option<String> {
        self.inner.get(key).cloned()
    }
}

pub fn inject(headers: &mut NatsHeaders) {
    inject_carrier(headers);
}

pub fn extract(headers: &NatsHeaders) {
    if headers.is_empty() {
        return;
    }
    extract_carrier(headers);
    info!(
        target: "greentic.telemetry",
        event = "nats.extract",
        headers = headers.len(),
        "trace context extracted from NATS headers"
    );
}
