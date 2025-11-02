use anyhow::Result;

use super::{PresetConfig, parse_headers_from_env};
use crate::export::ExportMode;

pub fn config() -> Result<PresetConfig> {
    let endpoint = std::env::var("OTLP_ENDPOINT")
        .ok()
        .filter(|ep| !ep.is_empty())
        .or_else(|| Some(String::from("http://datadog-agent:4317")));

    let mut headers = parse_headers_from_env(std::env::var("OTLP_HEADERS").ok())?;
    if let Some(api_key) = std::env::var("DD_API_KEY")
        .ok()
        .filter(|value| !value.is_empty())
    {
        headers.entry("DD_API_KEY".into()).or_insert(api_key);
    }

    Ok(PresetConfig {
        export_mode: Some(ExportMode::OtlpGrpc),
        otlp_endpoint: endpoint,
        otlp_headers: headers,
    })
}
