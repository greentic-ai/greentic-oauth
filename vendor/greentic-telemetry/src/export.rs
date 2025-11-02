use std::collections::HashMap;
use std::env;

use anyhow::{Context, Result, anyhow};

use crate::presets::{self, CloudPreset, PresetConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportMode {
    JsonStdout,
    OtlpGrpc,
    OtlpHttp,
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    not(any(feature = "otlp-grpc", feature = "otlp-http")),
    allow(dead_code)
)]
pub enum Sampling {
    Parent,
    TraceIdRatio(f64),
}

#[cfg_attr(
    not(any(feature = "otlp-grpc", feature = "otlp-http")),
    allow(dead_code)
)]
pub struct ExportConfig {
    pub mode: ExportMode,
    pub endpoint: Option<String>,
    pub headers: HashMap<String, String>,
    pub sampling: Sampling,
}

impl ExportConfig {
    pub fn json_default() -> Self {
        Self {
            mode: ExportMode::JsonStdout,
            endpoint: None,
            headers: HashMap::new(),
            sampling: Sampling::Parent,
        }
    }

    pub fn from_env() -> Result<Self> {
        let preset = presets::detect_from_env().and_then(|preset| match preset {
            CloudPreset::None => None,
            other => Some(other),
        });

        let preset_config = if let Some(preset) = preset {
            presets::load_preset(preset)?
        } else {
            PresetConfig::default()
        };

        let explicit_export = env::var("TELEMETRY_EXPORT").ok();
        let mode = match explicit_export
            .clone()
            .unwrap_or_else(|| "json-stdout".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "json-stdout" => ExportMode::JsonStdout,
            "otlp-grpc" => ExportMode::OtlpGrpc,
            "otlp-http" => ExportMode::OtlpHttp,
            other => {
                return Err(anyhow!(
                    "unsupported TELEMETRY_EXPORT value: {other}. expected one of json-stdout, otlp-grpc, otlp-http"
                ));
            }
        };

        let mut endpoint = env::var("OTLP_ENDPOINT").ok().filter(|s| !s.is_empty());
        if endpoint.is_none() {
            endpoint = preset_config.otlp_endpoint;
        }

        let mut headers = parse_headers(env::var("OTLP_HEADERS").ok().as_deref())?;
        if headers.is_empty() {
            headers = preset_config.otlp_headers;
        }

        let sampling = parse_sampling(env::var("TELEMETRY_SAMPLING").ok().as_deref())?;

        let inferred_mode = if explicit_export.is_none() {
            preset_config.export_mode.unwrap_or(match preset {
                Some(CloudPreset::Loki) => ExportMode::JsonStdout,
                _ => mode,
            })
        } else {
            mode
        };

        Ok(Self {
            mode: inferred_mode,
            endpoint,
            headers,
            sampling,
        })
    }
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self::json_default()
    }
}

fn parse_headers(value: Option<&str>) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();

    let Some(value) = value else {
        return Ok(headers);
    };

    for pair in value.split(',') {
        let trimmed = pair.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (key, val) = trimmed
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid OTLP_HEADERS entry '{trimmed}', expected key=value"))?;

        if key.trim().is_empty() {
            return Err(anyhow!(
                "invalid OTLP_HEADERS entry '{trimmed}', key cannot be empty"
            ));
        }

        headers.insert(key.trim().to_string(), val.trim().to_string());
    }

    Ok(headers)
}

fn parse_sampling(value: Option<&str>) -> Result<Sampling> {
    let Some(value) = value else {
        return Ok(Sampling::Parent);
    };

    let normalized = value.to_ascii_lowercase();
    if normalized == "parent" {
        return Ok(Sampling::Parent);
    }

    if let Some(rest) = normalized.strip_prefix("traceidratio:") {
        let ratio: f64 = rest
            .parse()
            .with_context(|| format!("invalid traceidratio value '{rest}'"))?;
        if !(0.0..=1.0).contains(&ratio) {
            return Err(anyhow!(
                "traceidratio must be between 0.0 and 1.0 inclusive, got {ratio}"
            ));
        }
        return Ok(Sampling::TraceIdRatio(ratio));
    }

    Err(anyhow!(
        "unsupported TELEMETRY_SAMPLING '{value}', expected parent or traceidratio:<ratio>"
    ))
}

#[cfg(any(feature = "otlp-grpc", feature = "otlp-http"))]
impl Sampling {
    pub(crate) fn into_sampler(self) -> opentelemetry_sdk::trace::Sampler {
        use opentelemetry_sdk::trace::Sampler;

        match self {
            Sampling::Parent => Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
            Sampling::TraceIdRatio(ratio) => {
                let ratio_sampler = Sampler::TraceIdRatioBased(ratio);
                Sampler::ParentBased(Box::new(ratio_sampler))
            }
        }
    }
}
