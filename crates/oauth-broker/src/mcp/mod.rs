use std::path::Path;

use thiserror::Error;

use crate::discovery::{build_config_requirements, build_flow_blueprint, load_provider_descriptor};

#[derive(Debug, Error)]
pub enum McpError {
    #[error(transparent)]
    Discovery(#[from] crate::discovery::DiscoveryError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, McpError>;

pub fn describe(
    config_root: &Path,
    tenant: &str,
    provider: &str,
    team: Option<&str>,
    user: Option<&str>,
) -> Result<String> {
    let descriptor = load_provider_descriptor(config_root, provider, Some(tenant), team, user)?;
    Ok(serde_json::to_string(&descriptor)?)
}

pub fn requirements(
    config_root: &Path,
    tenant: &str,
    provider: &str,
    team: Option<&str>,
    user: Option<&str>,
) -> Result<String> {
    let descriptor = load_provider_descriptor(config_root, provider, Some(tenant), team, user)?;
    let requirements = build_config_requirements(&descriptor, tenant, team, user);
    Ok(serde_json::to_string(&requirements)?)
}

pub fn start(
    config_root: &Path,
    tenant: &str,
    provider: &str,
    grant_type: &str,
    team: Option<&str>,
    user: Option<&str>,
) -> Result<String> {
    let descriptor = load_provider_descriptor(config_root, provider, Some(tenant), team, user)?;
    let blueprint = build_flow_blueprint(&descriptor, tenant, team, user, grant_type);
    Ok(serde_json::to_string(&blueprint)?)
}

pub mod schemas {
    pub const DESCRIBE: &str = include_str!("schemas/oauth.describe.json");
    pub const REQUIREMENTS: &str = include_str!("schemas/oauth.requirements.json");
    pub const START: &str = include_str!("schemas/oauth.start.json");
}
