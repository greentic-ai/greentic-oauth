use std::{collections::BTreeMap, str::FromStr};

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
};
use greentic_oauth_core::types::{OAuthFlowRequest, OwnerKind, TenantCtx as BrokerTenantCtx};
use greentic_types::{TenantCtx as TelemetryTenantCtx, telemetry::set_current_tenant_ctx};
use serde::Deserialize;
use serde_json::json;

use crate::{
    audit::{self, AuditAttributes},
    http::{error::AppError, state::FlowState, util::ensure_secure_request},
    ids::{parse_env_id, parse_team_id, parse_tenant_id},
    providers::{manifest::ManifestContext, presets},
    rate_limit,
    security::pkce::PkcePair,
    storage::{index::OwnerKindKey, models::Visibility, secrets_manager::SecretsManager},
};
use tracing::warn;

use super::super::SharedContext;

#[derive(Deserialize)]
pub struct StartPath {
    pub env: String,
    pub tenant: String,
    pub provider: String,
}

#[derive(Deserialize)]
pub struct StartQuery {
    pub team: Option<String>,
    pub owner_kind: String,
    pub owner_id: String,
    pub flow_id: String,
    pub scopes: Option<String>,
    pub redirect_uri: Option<String>,
    pub visibility: Option<String>,
    pub preset: Option<String>,
    pub prompt: Option<String>,
    #[serde(default)]
    pub extra: BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct StartRequest {
    pub env: String,
    pub tenant: String,
    pub provider: String,
    pub team: Option<String>,
    pub owner_kind: OwnerKindKey,
    pub owner_id: String,
    pub flow_id: String,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
    pub visibility: Visibility,
    pub preset: Option<String>,
    pub prompt: Option<String>,
    pub extra_params: BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct PreparedStart {
    pub redirect_url: String,
    pub state_token: String,
    pub flow_state: FlowState,
}

const EXTRA_KEY_MAX_LEN: usize = 32;
const EXTRA_VALUE_MAX_LEN: usize = 256;
const EXTRA_PARAM_LIMIT: usize = 8;

const OIDC_EXTRA_KEYS: &[&str] = &["prompt", "login_hint", "access_type", "resource", "claims"];
const MS_EXTRA_KEYS: &[&str] = &["prompt", "login_hint", "domain_hint", "resource"];

fn allowed_extra_keys(provider: &str) -> &'static [&'static str] {
    if provider.eq_ignore_ascii_case("msgraph")
        || provider.eq_ignore_ascii_case("microsoft-graph")
        || provider.eq_ignore_ascii_case("microsoft")
    {
        MS_EXTRA_KEYS
    } else {
        OIDC_EXTRA_KEYS
    }
}

pub(crate) fn sanitize_extra_params(
    provider: &str,
    allow_extra: bool,
    raw: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    if raw.is_empty() || !allow_extra {
        if !raw.is_empty() && !allow_extra {
            warn!(
                provider = provider,
                "extra params disabled; dropping {} user-supplied entries",
                raw.len()
            );
        }
        return BTreeMap::new();
    }

    let allowed = allowed_extra_keys(provider);
    let mut filtered = BTreeMap::new();
    for (key, value) in raw.iter() {
        if filtered.len() >= EXTRA_PARAM_LIMIT {
            warn!(
                provider = provider,
                "extra param limit ({}) reached; ignoring additional entries", EXTRA_PARAM_LIMIT
            );
            break;
        }

        let normalized_key = key.trim().to_ascii_lowercase();
        if normalized_key.is_empty() || normalized_key.len() > EXTRA_KEY_MAX_LEN {
            warn!(
                provider = provider,
                key = key,
                "ignoring extra param with invalid key length"
            );
            continue;
        }
        if !normalized_key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        {
            warn!(
                provider = provider,
                key = %normalized_key,
                "ignoring extra param with invalid characters"
            );
            continue;
        }
        if !allowed.contains(&normalized_key.as_str()) {
            warn!(
                provider = provider,
                key = %normalized_key,
                "extra param not allowed for provider"
            );
            continue;
        }

        let trimmed = value.trim();
        if trimmed.is_empty()
            || trimmed.len() > EXTRA_VALUE_MAX_LEN
            || !trimmed.is_ascii()
            || trimmed.chars().any(char::is_control)
        {
            warn!(
                provider = provider,
                key = %normalized_key,
                "ignoring extra param due to unsafe value"
            );
            continue;
        }

        filtered.insert(normalized_key, trimmed.to_string());
    }

    filtered
}

fn parse_scopes(input: Option<String>) -> Vec<String> {
    input
        .map(|value| {
            value
                .split([',', ' '])
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn parse_visibility(input: Option<String>) -> Result<Visibility, AppError> {
    match input {
        Some(value) => Visibility::from_str(value.to_lowercase().as_str())
            .map_err(|_| AppError::bad_request("unknown visibility")),
        None => Ok(Visibility::Private),
    }
}

fn build_owner_kind(key: OwnerKindKey, owner_id: &str) -> OwnerKind {
    match key {
        OwnerKindKey::User => OwnerKind::User {
            subject: owner_id.to_string(),
        },
        OwnerKindKey::Service => OwnerKind::Service {
            subject: owner_id.to_string(),
        },
    }
}

pub async fn prepare_start<S, F>(
    ctx: &SharedContext<S>,
    request: &StartRequest,
    build_state: F,
) -> Result<PreparedStart, AppError>
where
    S: SecretsManager + 'static,
    F: FnOnce(&FlowState) -> Result<String, AppError>,
{
    let mut telemetry_ctx = TelemetryTenantCtx::new(
        parse_env_id(request.env.as_str())?,
        parse_tenant_id(request.tenant.as_str())?,
    )
    .with_flow(request.flow_id.clone())
    .with_provider(request.provider.clone());

    if let Some(team) = request.team.as_ref() {
        telemetry_ctx = telemetry_ctx.with_team(Some(parse_team_id(team.as_str())?));
    }

    set_current_tenant_ctx(&telemetry_ctx);

    let rate_key = rate_limit::key(
        &request.env,
        &request.tenant,
        request.team.as_deref(),
        &request.provider,
    );
    ctx.rate_limiter
        .check(&rate_key)
        .await
        .map_err(|_| AppError::new(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded"))?;

    let provider = ctx
        .providers
        .get(&request.provider)
        .ok_or_else(|| AppError::not_found("provider not registered"))?;

    let manifest_ctx = ManifestContext::new(
        &request.tenant,
        &request.provider,
        request.team.as_deref(),
        None,
    );
    let resolved_manifest = ctx
        .provider_catalog
        .resolve(&request.provider, &manifest_ctx);

    if let Some(ref uri) = request.redirect_uri
        && !ctx.redirect_guard.is_allowed(uri)
    {
        return Err(AppError::bad_request("redirect_uri not permitted"));
    }

    if let Some(manifest) = &resolved_manifest {
        let provider_redirect = provider.redirect_uri();
        if !manifest
            .redirect_uris
            .iter()
            .any(|uri| uri == provider_redirect)
        {
            return Err(AppError::internal(format!(
                "provider redirect_uri `{provider_redirect}` not registered for `{}`",
                request.provider
            )));
        }
    }

    let preset = request
        .preset
        .as_deref()
        .and_then(presets::resolve)
        .or_else(|| presets::resolve(request.provider.as_str()));

    let mut scopes = if request.scopes.is_empty() {
        resolved_manifest
            .as_ref()
            .map(|manifest| manifest.scopes.clone())
            .unwrap_or_default()
    } else {
        request.scopes.clone()
    };

    if scopes.is_empty()
        && let Some(preset) = preset
    {
        scopes = preset.scopes.iter().map(|s| s.to_string()).collect();
    }

    if scopes.is_empty() {
        scopes = vec![
            "offline_access".to_string(),
            "openid".to_string(),
            "profile".to_string(),
        ];
    }

    let mut extra_params = request.extra_params.clone();
    if let Some(prompt_value) = request
        .prompt
        .clone()
        .or_else(|| preset.and_then(|p| p.prompt).map(|p| p.to_string()))
    {
        extra_params.insert("prompt".into(), prompt_value);
    }
    if let Some(resource) = preset.and_then(|p| p.resource) {
        extra_params.insert("resource".into(), resource.to_string());
    }

    let pkce = PkcePair::generate();

    let flow_state = FlowState::new(
        &request.env,
        &request.tenant,
        &request.provider,
        request.team.clone(),
        &request.flow_id,
        request.owner_kind.clone(),
        &request.owner_id,
        request.redirect_uri.clone(),
        Some(pkce.verifier.clone()),
        scopes.clone(),
        request.visibility.clone(),
    );

    let state_token = build_state(&flow_state)?;

    let owner = build_owner_kind(request.owner_kind.clone(), &request.owner_id);

    let oauth_request = OAuthFlowRequest {
        tenant: BrokerTenantCtx {
            env: request.env.clone(),
            tenant: request.tenant.clone(),
            team: request.team.clone(),
        },
        owner,
        redirect_uri: provider.redirect_uri().to_string(),
        state: Some(state_token.clone()),
        scopes: scopes.clone(),
        code_challenge: Some(pkce.challenge.clone()),
        code_challenge_method: Some("S256".to_string()),
        extra_params: if extra_params.is_empty() {
            None
        } else {
            Some(extra_params.clone())
        },
    };

    let redirect = provider.build_authorize_redirect(&oauth_request)?;

    let attrs = AuditAttributes {
        env: &request.env,
        tenant: &request.tenant,
        team: request.team.as_deref(),
        provider: &request.provider,
    };
    let audit_data = json!({
        "flow_id": request.flow_id.clone(),
        "owner_kind": request.owner_kind.as_str(),
        "owner_id": request.owner_id.clone(),
        "scopes": scopes,
        "visibility": request.visibility.as_str(),
        "redirect_uri": request.redirect_uri.clone(),
    });

    audit::emit(&ctx.publisher, "started", &attrs, audit_data).await;

    Ok(PreparedStart {
        redirect_url: redirect.redirect_url,
        state_token,
        flow_state,
    })
}

pub async fn process_start<S>(
    ctx: &SharedContext<S>,
    request: &StartRequest,
) -> Result<(String, String, FlowState), AppError>
where
    S: SecretsManager + 'static,
{
    let csrf = ctx.security.csrf.clone();
    let prepared = prepare_start(ctx, request, move |flow_state| {
        let payload = serde_json::to_string(flow_state)?;
        csrf.seal("state", &payload).map_err(AppError::from)
    })
    .await?;

    Ok((
        prepared.redirect_url,
        prepared.state_token,
        prepared.flow_state,
    ))
}

pub async fn start<S>(
    Path(StartPath {
        env,
        tenant,
        provider,
    }): Path<StartPath>,
    Query(StartQuery {
        team,
        owner_kind,
        owner_id,
        flow_id,
        scopes,
        redirect_uri,
        visibility,
        preset,
        prompt,
        extra,
    }): Query<StartQuery>,
    headers: HeaderMap,
    State(ctx): State<SharedContext<S>>,
) -> Result<impl IntoResponse, AppError>
where
    S: SecretsManager + 'static,
{
    ensure_secure_request(&headers, ctx.allow_insecure)?;

    let owner_kind_key = OwnerKindKey::from_str(owner_kind.as_str())
        .map_err(|_| AppError::bad_request("invalid owner_kind"))?;

    let visibility = parse_visibility(visibility)?;
    let scopes_list = parse_scopes(scopes);
    let extra_params = sanitize_extra_params(provider.as_str(), ctx.allow_extra_params, &extra);

    let start_request = StartRequest {
        env,
        tenant,
        provider,
        team,
        owner_kind: owner_kind_key,
        owner_id,
        flow_id,
        scopes: scopes_list,
        redirect_uri,
        visibility,
        preset,
        prompt,
        extra_params,
    };

    let (redirect_url, _, _) = process_start(&ctx, &start_request).await?;

    Ok(Redirect::temporary(redirect_url.as_str()))
}
