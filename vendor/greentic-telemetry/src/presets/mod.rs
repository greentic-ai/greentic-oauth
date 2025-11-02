use std::collections::HashMap;

use anyhow::{Context, Result};

pub mod aws;
pub mod azure;
pub mod datadog;
pub mod gcp;
pub mod loki;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudPreset {
    Aws,
    Gcp,
    Azure,
    Datadog,
    Loki,
    None,
}

#[derive(Debug, Default, Clone)]
pub struct PresetConfig {
    pub export_mode: Option<crate::export::ExportMode>,
    pub otlp_endpoint: Option<String>,
    pub otlp_headers: HashMap<String, String>,
}

pub fn detect_from_env() -> Option<CloudPreset> {
    let value = std::env::var("CLOUD_PRESET").ok()?.to_ascii_lowercase();
    match value.as_str() {
        "aws" => Some(CloudPreset::Aws),
        "gcp" => Some(CloudPreset::Gcp),
        "azure" => Some(CloudPreset::Azure),
        "datadog" => Some(CloudPreset::Datadog),
        "loki" => Some(CloudPreset::Loki),
        "none" => Some(CloudPreset::None),
        other => {
            tracing::warn!("unknown CLOUD_PRESET value: {other}");
            None
        }
    }
}

pub fn load_preset(preset: CloudPreset) -> Result<PresetConfig> {
    match preset {
        CloudPreset::Aws => aws::config(),
        CloudPreset::Gcp => gcp::config(),
        CloudPreset::Azure => azure::config(),
        CloudPreset::Datadog => datadog::config(),
        CloudPreset::Loki => loki::config(),
        CloudPreset::None => Ok(PresetConfig::default()),
    }
}

pub fn parse_headers_from_env(headers: Option<String>) -> Result<HashMap<String, String>> {
    let headers = headers.unwrap_or_default();
    let mut map = HashMap::new();
    for pair in headers.split(',') {
        let trimmed = pair.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (key, value) = trimmed
            .split_once('=')
            .with_context(|| format!("invalid OTLP_HEADERS entry '{trimmed}'"))?;
        map.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(map)
}
