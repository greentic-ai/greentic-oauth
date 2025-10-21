use std::fs;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::Response,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use crate::{
    discovery::{
        build_config_requirements, build_flow_blueprint, load_provider_descriptor, DiscoveryError,
        ProviderDescriptor,
    },
    http::error::AppError,
    http::util::{json_response, json_response_from_serializable},
    http::SharedContext,
    storage::secrets_manager::SecretsManager,
};

#[derive(Deserialize)]
pub struct ProviderPath {
    pub provider_id: String,
}

#[derive(Deserialize)]
pub struct ScopedProviderPath {
    pub tenant: String,
    pub provider_id: String,
}

#[derive(Deserialize)]
pub struct ScopedQuery {
    pub team: Option<String>,
    pub user: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ProviderSummary {
    pub id: String,
    pub display_name: String,
    pub grant_types: Vec<String>,
    pub docs_url: Option<String>,
}

#[derive(Deserialize)]
pub struct FlowBlueprintRequest {
    pub grant_type: String,
    pub team: Option<String>,
    pub user: Option<String>,
}

pub async fn list_providers<S>(
    State(ctx): State<SharedContext<S>>,
) -> Result<Response<Body>, AppError>
where
    S: SecretsManager + 'static,
{
    let mut providers = Vec::new();
    let root = ctx.config_root.join("providers");
    let entries = fs::read_dir(&root).map_err(|err| AppError::internal(err.to_string()))?;
    for entry in entries.flatten() {
        if let Some(ext) = entry.path().extension() {
            if ext == "yaml" {
                if let Some(file_stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
                    match load_provider_descriptor(&*ctx.config_root, file_stem, None, None, None) {
                        Ok(descriptor) => providers.push(ProviderSummary {
                            id: descriptor.id,
                            display_name: descriptor.display_name,
                            grant_types: descriptor.grant_types,
                            docs_url: descriptor.docs_url,
                        }),
                        Err(err) => return Err(map_error(err)),
                    }
                }
            }
        }
    }
    providers.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    json_response_from_serializable(&providers)
}

pub async fn get_base_provider<S>(
    Path(ProviderPath { provider_id }): Path<ProviderPath>,
    State(ctx): State<SharedContext<S>>,
) -> Result<Response<Body>, AppError>
where
    S: SecretsManager + 'static,
{
    let descriptor = load_provider_descriptor(&*ctx.config_root, &provider_id, None, None, None)
        .map_err(map_error)?;
    descriptor_response(&ctx, descriptor)
}

pub async fn get_scoped_provider<S>(
    Path(ScopedProviderPath {
        tenant,
        provider_id,
    }): Path<ScopedProviderPath>,
    Query(ScopedQuery { team, user }): Query<ScopedQuery>,
    State(ctx): State<SharedContext<S>>,
) -> Result<Response<Body>, AppError>
where
    S: SecretsManager + 'static,
{
    let descriptor = load_provider_descriptor(
        &*ctx.config_root,
        &provider_id,
        Some(&tenant),
        team.as_deref(),
        user.as_deref(),
    )
    .map_err(map_error)?;
    descriptor_response(&ctx, descriptor)
}

pub async fn get_requirements<S>(
    Path(ScopedProviderPath {
        tenant,
        provider_id,
    }): Path<ScopedProviderPath>,
    Query(ScopedQuery { team, user }): Query<ScopedQuery>,
    State(ctx): State<SharedContext<S>>,
) -> Result<Response<Body>, AppError>
where
    S: SecretsManager + 'static,
{
    let descriptor = load_provider_descriptor(
        &*ctx.config_root,
        &provider_id,
        Some(&tenant),
        team.as_deref(),
        user.as_deref(),
    )
    .map_err(map_error)?;

    let requirements =
        build_config_requirements(&descriptor, &tenant, team.as_deref(), user.as_deref());
    json_response_from_serializable(&requirements)
}

pub async fn post_blueprint<S>(
    Path(ScopedProviderPath {
        tenant,
        provider_id,
    }): Path<ScopedProviderPath>,
    State(ctx): State<SharedContext<S>>,
    Json(body): Json<FlowBlueprintRequest>,
) -> Result<Response<Body>, AppError>
where
    S: SecretsManager + 'static,
{
    let descriptor = load_provider_descriptor(
        &*ctx.config_root,
        &provider_id,
        Some(&tenant),
        body.team.as_deref(),
        body.user.as_deref(),
    )
    .map_err(map_error)?;

    let blueprint = build_flow_blueprint(
        &descriptor,
        &tenant,
        body.team.as_deref(),
        body.user.as_deref(),
        &body.grant_type,
    );

    json_response_from_serializable(&blueprint)
}

pub async fn get_jwks<S>(State(ctx): State<SharedContext<S>>) -> Result<Response<Body>, AppError>
where
    S: SecretsManager + 'static,
{
    if let Some(discovery) = ctx.security.discovery.as_ref() {
        let jwks = discovery.jwks_document();
        json_response(jwks)
    } else {
        Err(AppError::not_found("discovery signing not configured"))
    }
}

fn map_error(err: DiscoveryError) -> AppError {
    match err {
        DiscoveryError::NotFound(_, _) => AppError::not_found(err.to_string()),
        _ => AppError::internal(err.to_string()),
    }
}

fn descriptor_response<S>(
    ctx: &SharedContext<S>,
    descriptor: ProviderDescriptor,
) -> Result<Response<Body>, AppError>
where
    S: SecretsManager + 'static,
{
    let mut value = serde_json::to_value(&descriptor)?;
    if let Some(signer) = ctx.security.discovery.as_ref() {
        let payload_bytes = serde_json::to_vec(&value)?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let signature = signer.sign(&payload_bytes)?;
        let signature_value = json!({
            "protected": signature.protected,
            "payload": payload_b64,
            "signature": signature.signature,
        });
        value
            .as_object_mut()
            .ok_or_else(|| AppError::internal("descriptor must serialize to object"))?
            .insert("signature".into(), signature_value);
    }

    json_response(value)
}
