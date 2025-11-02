use std::{collections::HashSet, fs};

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
use url::form_urlencoded;

use crate::{
    discovery::{
        build_config_requirements, build_flow_blueprint, load_provider_descriptor, DiscoveryError,
        ProviderDescriptor,
    },
    http::error::AppError,
    http::util::{json_response, json_response_from_serializable},
    http::SharedContext,
    providers::manifest::{ManifestContext, ResolvedProviderManifest},
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
pub struct ProviderCatalogEntry {
    pub id: String,
    pub label: String,
    pub version: String,
}

#[derive(Deserialize)]
pub struct FlowBlueprintRequest {
    pub grant_type: String,
    pub team: Option<String>,
    pub user: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub state: Option<String>,
}

pub async fn list_providers<S>(
    State(ctx): State<SharedContext<S>>,
) -> Result<Response<Body>, AppError>
where
    S: SecretsManager + 'static,
{
    let mut providers: Vec<ProviderCatalogEntry> = ctx
        .provider_catalog
        .iter()
        .map(|manifest| ProviderCatalogEntry {
            id: manifest.id.clone(),
            label: manifest.label.clone(),
            version: manifest.version.clone(),
        })
        .collect();
    let mut seen: HashSet<String> = providers.iter().map(|p| p.id.clone()).collect();

    let root = ctx.config_root.join("providers");
    let entries = fs::read_dir(&root).map_err(|err| AppError::internal(err.to_string()))?;
    for entry in entries.flatten() {
        if let Some(ext) = entry.path().extension() {
            if ext == "yaml" {
                if let Some(file_stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
                    if seen.contains(file_stem) {
                        continue;
                    }
                    match load_provider_descriptor(&*ctx.config_root, file_stem, None, None, None) {
                        Ok(descriptor) => {
                            providers.push(ProviderCatalogEntry {
                                id: descriptor.id.clone(),
                                label: descriptor.display_name,
                                version: "legacy".to_string(),
                            });
                            seen.insert(descriptor.id);
                        }
                        Err(err) => return Err(map_error(err)),
                    }
                }
            }
        }
    }
    providers.sort_by(|a, b| a.label.cmp(&b.label));
    json_response_from_serializable(&providers)
}

fn resolved_manifest_value(
    manifest: Option<&ResolvedProviderManifest>,
) -> Result<Option<serde_json::Value>, AppError> {
    manifest
        .map(|inner| serde_json::to_value(inner).map_err(|err| AppError::internal(err.to_string())))
        .transpose()
}

fn base_manifest_value(
    manifest: Option<&crate::providers::manifest::ProviderManifest>,
) -> Result<Option<serde_json::Value>, AppError> {
    manifest
        .map(|inner| serde_json::to_value(inner).map_err(|err| AppError::internal(err.to_string())))
        .transpose()
}

fn manifest_context<'a>(
    tenant: &'a str,
    provider_id: &'a str,
    team: Option<&'a str>,
    user: Option<&'a str>,
) -> ManifestContext<'a> {
    ManifestContext::new(tenant, provider_id, team, user)
}

fn expand_blueprint_auth_url(
    manifest: &ResolvedProviderManifest,
    descriptor: &ProviderDescriptor,
    request: &FlowBlueprintRequest,
) -> Option<String> {
    let template = manifest
        .blueprints
        .as_ref()
        .and_then(|blueprints| blueprints.auth_url_template.as_ref())?
        .to_string();

    let mut expanded = template;

    if let Some(auth_endpoint) = manifest.auth.as_deref().or(descriptor.auth_url.as_deref()) {
        expanded = expanded.replace("{authorization_endpoint}", auth_endpoint);
    }

    if let Some(redirect_uri) = request
        .redirect_uri
        .as_deref()
        .or_else(|| manifest.redirect_uris.first().map(|value| value.as_str()))
    {
        expanded = expanded.replace("{redirect_uri}", &encode_component(redirect_uri));
    }

    if let Some(scopes_value) = request
        .scopes
        .as_ref()
        .map(|scopes| scopes.join(" "))
        .or_else(|| {
            if manifest.scopes.is_empty() {
                None
            } else {
                Some(manifest.scopes.join(" "))
            }
        })
    {
        expanded = expanded.replace("{scopes}", &encode_component(&scopes_value));
    }

    if let Some(state) = request.state.as_deref() {
        expanded = expanded.replace("{state}", &encode_component(state));
    }

    Some(expanded)
}

fn encode_component(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
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
    let manifest_json = base_manifest_value(ctx.provider_catalog.get(&provider_id))?;
    descriptor_response(&ctx, descriptor, manifest_json)
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
    let manifest_ctx = manifest_context(&tenant, &provider_id, team.as_deref(), user.as_deref());
    let manifest = ctx.provider_catalog.resolve(&provider_id, &manifest_ctx);
    let manifest_json = resolved_manifest_value(manifest.as_ref())?;
    descriptor_response(&ctx, descriptor, manifest_json)
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
    let manifest_ctx = manifest_context(&tenant, &provider_id, team.as_deref(), user.as_deref());
    let manifest = ctx.provider_catalog.resolve(&provider_id, &manifest_ctx);

    let requirements = build_config_requirements(
        &descriptor,
        &tenant,
        team.as_deref(),
        user.as_deref(),
        manifest.as_ref(),
    );
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
    let manifest_ctx = manifest_context(
        &tenant,
        &provider_id,
        body.team.as_deref(),
        body.user.as_deref(),
    );
    let manifest = ctx.provider_catalog.resolve(&provider_id, &manifest_ctx);

    let mut blueprint = build_flow_blueprint(
        &descriptor,
        &tenant,
        body.team.as_deref(),
        body.user.as_deref(),
        &body.grant_type,
    );

    if let Some(resolved_manifest) = manifest.as_ref() {
        if let Some(url) = expand_blueprint_auth_url(resolved_manifest, &descriptor, &body) {
            blueprint.auth_url_example = Some(url);
        }
    }

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
    manifest: Option<serde_json::Value>,
) -> Result<Response<Body>, AppError>
where
    S: SecretsManager + 'static,
{
    let mut value = serde_json::to_value(&descriptor)?;
    if let Some(manifest_value) = manifest {
        value
            .as_object_mut()
            .ok_or_else(|| AppError::internal("descriptor must serialize to object"))?
            .insert("manifest".into(), manifest_value);
    }
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
