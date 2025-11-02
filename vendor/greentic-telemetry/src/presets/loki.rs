use anyhow::Result;

use super::PresetConfig;

pub fn config() -> Result<PresetConfig> {
    let endpoint = std::env::var("OTLP_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty());

    Ok(PresetConfig {
        otlp_endpoint: endpoint,
        ..PresetConfig::default()
    })
}
