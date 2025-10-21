use std::{collections::BTreeSet, fs};

use axum::{body::Body, extract::State, http::Response};
use serde_json::{json, Value};

use crate::{
    discovery::load_provider_descriptor,
    http::{error::AppError, util::json_response, SharedContext},
    storage::secrets_manager::SecretsManager,
};

pub async fn document<S>(State(ctx): State<SharedContext<S>>) -> Result<Response<Body>, AppError>
where
    S: SecretsManager + 'static,
{
    let api_base =
        std::env::var("OAUTH_DISCOVERY_API_BASE").unwrap_or_else(|_| "{api_base}".to_string());
    let base_trimmed = api_base.trim_end_matches('/');
    let service_name =
        std::env::var("SERVICE_NAME").unwrap_or_else(|_| "greentic-oauth".to_string());
    let owner = std::env::var("OAUTH_DISCOVERY_OWNER").unwrap_or_else(|_| "greentic".to_string());

    let mut grant_types = BTreeSet::new();
    let mut auth_methods = BTreeSet::new();
    let providers_dir = ctx.config_root.join("providers");
    if providers_dir.exists() {
        let entries =
            fs::read_dir(&providers_dir).map_err(|err| AppError::internal(err.to_string()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "yaml") {
                if let Some(id) = path.file_stem().and_then(|s| s.to_str()) {
                    let descriptor =
                        load_provider_descriptor(&*ctx.config_root, id, None, None, None)
                            .map_err(|err| AppError::internal(err.to_string()))?;
                    for grant in descriptor.grant_types {
                        grant_types.insert(grant);
                    }
                    for method in descriptor.token_endpoint_auth_methods {
                        auth_methods.insert(method);
                    }
                }
            }
        }
    }

    let mut payload = json!({
        "spec_version": "1.0",
        "service_name": service_name,
        "api_base": base_trimmed,
        "capabilities": {
            "grant_types": grant_types.into_iter().collect::<Vec<_>>(),
            "auth_methods": auth_methods.into_iter().collect::<Vec<_>>(),
            "features": [
                "mcp",
                "wit",
                "nats-propagation",
                "webhook-callbacks",
            ],
        },
        "providers_index": format!("{base_trimmed}/oauth/discovery/providers"),
        "metadata": {
            "owner": owner,
        },
    });

    if let Some(discovery) = ctx.security.discovery.as_ref() {
        let jwks_uri = format!("{base_trimmed}/.well-known/jwks.json");
        if let Value::Object(map) = &mut payload {
            map.insert("jwks_uri".into(), Value::String(jwks_uri));
            map.insert("kid".into(), Value::String(discovery.kid().to_string()));
        }
    }

    json_response(payload)
}
