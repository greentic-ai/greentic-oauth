use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use greentic_oauth_core::{TokenHandleClaims, TokenSet, provider::Provider};
use reqwest::{
    Client, Method, Response,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    audit::{self, AuditAttributes},
    http::{SharedContext, error::AppError},
    storage::{
        index::ConnectionKey,
        secrets_manager::{SecretPath, SecretsManager},
    },
    telemetry,
};

const REFRESH_WINDOW_SECS: u64 = 300;
const DEFAULT_TTL_SECS: u64 = 3600;

/// Envelope persisted in secret storage containing encrypted token data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub ciphertext: String,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl StoredToken {
    pub fn new(ciphertext: String, expires_at: Option<u64>) -> Self {
        Self {
            ciphertext,
            expires_at,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct SignedFetchOptions {
    pub token_handle: String,
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SignedFetchOutcome {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

pub async fn resolve_access_token<S>(
    ctx: &SharedContext<S>,
    token_handle: &str,
    force_refresh: bool,
) -> Result<AccessTokenResponse, AppError>
where
    S: SecretsManager + 'static,
{
    let claims = ctx.security.jws.verify(token_handle)?;
    telemetry::set_request_context(
        Some(claims.tenant.tenant.as_str()),
        claims.tenant.team.as_deref(),
        None,
        Some(claims.subject.as_str()),
    );
    let attrs = AuditAttributes {
        env: &claims.tenant.env,
        tenant: &claims.tenant.tenant,
        team: claims.tenant.team.as_deref(),
        provider: &claims.provider,
    };
    let owner_kind_label = match &claims.owner {
        greentic_oauth_core::types::OwnerKind::User { .. } => "user",
        greentic_oauth_core::types::OwnerKind::Service { .. } => "service",
    };

    let provider = ctx.providers.get(&claims.provider).ok_or_else(|| {
        AppError::not_found(format!("provider `{}` not registered", claims.provider))
    })?;

    let key = ConnectionKey::from_owner(
        claims.tenant.env.clone(),
        claims.tenant.tenant.clone(),
        claims.tenant.team.clone(),
        &claims.owner,
        claims.subject.clone(),
    );
    let connection = ctx
        .index
        .get(&claims.provider, &key)
        .ok_or_else(|| AppError::not_found("connection not found"))?;

    let secret_path = SecretPath::new(connection.path)?;
    let mut stored = ctx
        .secrets
        .get_json::<StoredToken>(&secret_path)?
        .ok_or_else(|| AppError::not_found("token payload missing"))?;
    let mut token_set = ctx.security.jwe.decrypt(&stored.ciphertext)?;

    let now = now_epoch_seconds();
    let mut expires_at = stored
        .expires_at
        .or(Some(claims.expires_at))
        .unwrap_or(claims.expires_at);

    let needs_refresh = force_refresh || expires_at.saturating_sub(now) <= REFRESH_WINDOW_SECS;

    if needs_refresh {
        if let Some(refresh_token) = token_set.refresh_token.clone() {
            let reason = if force_refresh {
                "forced"
            } else {
                "expiry_window"
            };
            let previous_expires = stored.expires_at;
            let mut refreshed =
                match refresh_provider_token(provider.as_ref(), &claims, &refresh_token) {
                    Ok(value) => value,
                    Err(err) => {
                        let error_message = err.to_string();
                        audit::emit(
                            &ctx.publisher,
                            "refresh",
                            &attrs,
                            json!({
                                "status": "error",
                                "reason": reason,
                                "subject": claims.subject,
                                "owner_kind": owner_kind_label,
                                "force": force_refresh,
                                "error": error_message,
                            }),
                        )
                        .await;
                        return Err(err);
                    }
                };
            if refreshed.refresh_token.is_none() {
                refreshed.refresh_token = Some(refresh_token.clone());
            }
            expires_at = refreshed
                .expires_in
                .map(|ttl| now.saturating_add(ttl))
                .unwrap_or_else(|| now.saturating_add(DEFAULT_TTL_SECS));
            token_set = refreshed;
            let ciphertext = match ctx.security.jwe.encrypt(&token_set) {
                Ok(value) => value,
                Err(err) => {
                    let error_message = err.to_string();
                    audit::emit(
                        &ctx.publisher,
                        "refresh",
                        &attrs,
                        json!({
                            "status": "error",
                            "reason": reason,
                            "subject": claims.subject,
                            "owner_kind": owner_kind_label,
                            "force": force_refresh,
                            "error": error_message,
                        }),
                    )
                    .await;
                    return Err(err.into());
                }
            };
            stored.ciphertext = ciphertext;
            stored.expires_at = Some(expires_at);
            if let Err(err) = ctx.secrets.put_json(&secret_path, &stored) {
                let error_message = err.to_string();
                audit::emit(
                    &ctx.publisher,
                    "refresh",
                    &attrs,
                    json!({
                        "status": "error",
                        "reason": reason,
                        "subject": claims.subject,
                        "owner_kind": owner_kind_label,
                        "force": force_refresh,
                        "error": error_message,
                    }),
                )
                .await;
                return Err(err.into());
            }
            audit::emit(
                &ctx.publisher,
                "refresh",
                &attrs,
                json!({
                    "status": "success",
                    "reason": reason,
                    "subject": claims.subject,
                    "owner_kind": owner_kind_label,
                    "force": force_refresh,
                    "previous_expires_at": previous_expires,
                    "expires_at": expires_at,
                }),
            )
            .await;
        } else if stored.expires_at.is_none() {
            stored.expires_at = Some(expires_at);
            ctx.secrets.put_json(&secret_path, &stored)?;
        }
    } else if stored.expires_at.is_none() {
        stored.expires_at = Some(expires_at);
        ctx.secrets.put_json(&secret_path, &stored)?;
    }

    Ok(AccessTokenResponse {
        access_token: token_set.access_token,
        expires_at,
    })
}

fn refresh_provider_token(
    provider: &dyn Provider,
    claims: &TokenHandleClaims,
    refresh_token: &str,
) -> Result<TokenSet, AppError> {
    provider
        .refresh(claims, refresh_token)
        .map_err(AppError::from)
}

pub async fn revoke_token<S>(ctx: &SharedContext<S>, token_handle: &str) -> Result<(), AppError>
where
    S: SecretsManager + 'static,
{
    let unknown_attrs = AuditAttributes {
        env: "unknown",
        tenant: "unknown",
        team: None,
        provider: "unknown",
    };
    let claims = match ctx.security.jws.verify(token_handle) {
        Ok(value) => value,
        Err(err) => {
            audit::emit(
                &ctx.publisher,
                "revoke",
                &unknown_attrs,
                json!({
                    "status": "error",
                    "reason": "invalid_token_handle",
                    "error": err.to_string(),
                }),
            )
            .await;
            return Err(err.into());
        }
    };
    telemetry::set_request_context(
        Some(claims.tenant.tenant.as_str()),
        claims.tenant.team.as_deref(),
        None,
        Some(claims.subject.as_str()),
    );
    let attrs = AuditAttributes {
        env: &claims.tenant.env,
        tenant: &claims.tenant.tenant,
        team: claims.tenant.team.as_deref(),
        provider: &claims.provider,
    };
    let owner_kind_label = match &claims.owner {
        greentic_oauth_core::types::OwnerKind::User { .. } => "user",
        greentic_oauth_core::types::OwnerKind::Service { .. } => "service",
    };

    let provider = match ctx.providers.get(&claims.provider) {
        Some(p) => p,
        None => {
            audit::emit(
                &ctx.publisher,
                "revoke",
                &attrs,
                json!({
                    "status": "error",
                    "reason": "provider_not_registered",
                    "subject": claims.subject,
                    "owner_kind": owner_kind_label,
                }),
            )
            .await;
            return Err(AppError::not_found(format!(
                "provider `{}` not registered",
                claims.provider
            )));
        }
    };

    let key = ConnectionKey::from_owner(
        claims.tenant.env.clone(),
        claims.tenant.tenant.clone(),
        claims.tenant.team.clone(),
        &claims.owner,
        claims.subject.clone(),
    );
    let connection = match ctx.index.get(&claims.provider, &key) {
        Some(conn) => conn,
        None => {
            audit::emit(
                &ctx.publisher,
                "revoke",
                &attrs,
                json!({
                    "status": "error",
                    "reason": "connection_not_found",
                    "subject": claims.subject,
                    "owner_kind": owner_kind_label,
                }),
            )
            .await;
            return Err(AppError::not_found("connection not found"));
        }
    };

    let secret_path = SecretPath::new(connection.path.clone())?;
    let stored = match ctx.secrets.get_json::<StoredToken>(&secret_path)? {
        Some(value) => value,
        None => {
            audit::emit(
                &ctx.publisher,
                "revoke",
                &attrs,
                json!({
                    "status": "error",
                    "reason": "token_payload_missing",
                    "subject": claims.subject,
                    "owner_kind": owner_kind_label,
                }),
            )
            .await;
            return Err(AppError::not_found("token payload missing"));
        }
    };
    let token_set = match ctx.security.jwe.decrypt(&stored.ciphertext) {
        Ok(value) => value,
        Err(err) => {
            audit::emit(
                &ctx.publisher,
                "revoke",
                &attrs,
                json!({
                    "status": "error",
                    "reason": "decrypt_failed",
                    "subject": claims.subject,
                    "owner_kind": owner_kind_label,
                    "error": err.to_string(),
                }),
            )
            .await;
            return Err(err.into());
        }
    };
    let revoke_token = token_set
        .refresh_token
        .clone()
        .unwrap_or(token_set.access_token.clone());

    let result = provider.revoke(&claims, &revoke_token);
    match result {
        Ok(()) => {
            if let Err(err) = ctx.secrets.delete(&secret_path) {
                audit::emit(
                    &ctx.publisher,
                    "revoke",
                    &attrs,
                    json!({
                        "status": "error",
                        "reason": "secret_delete_failed",
                        "subject": claims.subject,
                        "owner_kind": owner_kind_label,
                        "error": err.to_string(),
                    }),
                )
                .await;
                return Err(err.into());
            }
            audit::emit(
                &ctx.publisher,
                "revoke",
                &attrs,
                json!({
                    "status": "success",
                    "subject": claims.subject,
                    "owner_kind": owner_kind_label,
                    "revoked_token_kind": if token_set.refresh_token.is_some() {
                        "refresh_token"
                    } else {
                        "access_token"
                    },
                }),
            )
            .await;
            Ok(())
        }
        Err(err) => {
            let app_err: AppError = err.into();
            audit::emit(
                &ctx.publisher,
                "revoke",
                &attrs,
                json!({
                    "status": "error",
                    "reason": "provider_error",
                    "subject": claims.subject,
                    "owner_kind": owner_kind_label,
                    "error": app_err.to_string(),
                }),
            )
            .await;
            Err(app_err)
        }
    }
}

pub async fn perform_signed_fetch<S>(
    ctx: &SharedContext<S>,
    opts: SignedFetchOptions,
) -> Result<SignedFetchOutcome, AppError>
where
    S: SecretsManager + 'static,
{
    let unknown_attrs = AuditAttributes {
        env: "unknown",
        tenant: "unknown",
        team: None,
        provider: "unknown",
    };
    let claims = match ctx.security.jws.verify(&opts.token_handle) {
        Ok(value) => value,
        Err(err) => {
            audit::emit(
                &ctx.publisher,
                "signed_fetch",
                &unknown_attrs,
                json!({
                    "status": "error",
                    "reason": "invalid_token_handle",
                    "method": opts.method.to_string(),
                    "url": opts.url,
                    "error": err.to_string(),
                }),
            )
            .await;
            return Err(err.into());
        }
    };
    telemetry::set_request_context(
        Some(claims.tenant.tenant.as_str()),
        claims.tenant.team.as_deref(),
        None,
        Some(claims.subject.as_str()),
    );
    let attrs = AuditAttributes {
        env: &claims.tenant.env,
        tenant: &claims.tenant.tenant,
        team: claims.tenant.team.as_deref(),
        provider: &claims.provider,
    };
    let owner_kind_label = match &claims.owner {
        greentic_oauth_core::types::OwnerKind::User { .. } => "user",
        greentic_oauth_core::types::OwnerKind::Service { .. } => "service",
    };
    let method_string = opts.method.to_string();
    let url_string = opts.url.clone();
    let client = Client::new();
    let mut attempts = 1usize;
    let mut refreshed = false;

    let mut token = match resolve_access_token(ctx, &opts.token_handle, false).await {
        Ok(value) => value,
        Err(err) => {
            let message = err.to_string();
            audit::emit(
                &ctx.publisher,
                "signed_fetch",
                &attrs,
                json!({
                    "status": "error",
                    "reason": "resolve_failed",
                    "method": method_string,
                    "url": url_string,
                    "owner_kind": owner_kind_label,
                    "subject": claims.subject,
                    "force_refresh": false,
                    "attempts": attempts,
                    "error": message,
                }),
            )
            .await;
            return Err(err);
        }
    };
    let mut response = match dispatch_request(&client, &opts, &token.access_token).await {
        Ok(resp) => resp,
        Err(err) => {
            let message = err.to_string();
            audit::emit(
                &ctx.publisher,
                "signed_fetch",
                &attrs,
                json!({
                    "status": "error",
                    "reason": "request_failed",
                    "method": method_string,
                    "url": url_string,
                    "owner_kind": owner_kind_label,
                    "subject": claims.subject,
                    "force_refresh": false,
                    "attempts": attempts,
                    "error": message,
                }),
            )
            .await;
            return Err(err);
        }
    };

    if response.status().as_u16() == 401 {
        attempts += 1;
        refreshed = true;
        token = match resolve_access_token(ctx, &opts.token_handle, true).await {
            Ok(value) => value,
            Err(err) => {
                let message = err.to_string();
                audit::emit(
                    &ctx.publisher,
                    "signed_fetch",
                    &attrs,
                    json!({
                        "status": "error",
                        "reason": "resolve_failed",
                        "method": method_string,
                        "url": url_string,
                        "owner_kind": owner_kind_label,
                        "subject": claims.subject,
                        "force_refresh": true,
                        "attempts": attempts,
                        "error": message,
                    }),
                )
                .await;
                return Err(err);
            }
        };
        response = match dispatch_request(&client, &opts, &token.access_token).await {
            Ok(resp) => resp,
            Err(err) => {
                let message = err.to_string();
                audit::emit(
                    &ctx.publisher,
                    "signed_fetch",
                    &attrs,
                    json!({
                        "status": "error",
                        "reason": "request_failed",
                        "method": method_string,
                        "url": url_string,
                        "owner_kind": owner_kind_label,
                        "subject": claims.subject,
                        "force_refresh": true,
                        "attempts": attempts,
                        "error": message,
                    }),
                )
                .await;
                return Err(err);
            }
        };
    }

    let status = response.status().as_u16();
    let headers = flatten_headers(response.headers());
    let body = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => {
            let message = err.to_string();
            audit::emit(
                &ctx.publisher,
                "signed_fetch",
                &attrs,
                json!({
                    "status": "error",
                    "reason": "body_read_failed",
                    "method": method_string,
                    "url": url_string,
                    "owner_kind": owner_kind_label,
                    "subject": claims.subject,
                    "force_refresh": refreshed,
                    "attempts": attempts,
                    "error": message,
                }),
            )
            .await;
            return Err(AppError::internal(message));
        }
    };

    audit::emit(
        &ctx.publisher,
        "signed_fetch",
        &attrs,
        json!({
            "status": "success",
            "method": method_string,
            "url": url_string,
            "owner_kind": owner_kind_label,
            "subject": claims.subject,
            "force_refresh": refreshed,
            "attempts": attempts,
            "http_status": status,
        }),
    )
    .await;

    Ok(SignedFetchOutcome {
        status,
        headers,
        body: body.to_vec(),
    })
}

async fn dispatch_request(
    client: &Client,
    opts: &SignedFetchOptions,
    access_token: &str,
) -> Result<Response, AppError> {
    let mut request = client
        .request(opts.method.clone(), &opts.url)
        .bearer_auth(access_token);

    for (name, value) in &opts.headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| AppError::bad_request(format!("invalid header name `{name}`")))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| AppError::bad_request(format!("invalid header value for `{name}`")))?;
        request = request.header(header_name, header_value);
    }

    if let Some(body) = &opts.body {
        request = request.body(body.clone());
    }

    request
        .send()
        .await
        .map_err(|err| AppError::internal(err.to_string()))
}

fn flatten_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let name = name.as_str().to_string();
            let value = value.to_str().map(|s| s.to_string()).unwrap_or_else(|_| {
                let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
                format!("base64:{encoded}")
            });
            (name, value)
        })
        .collect()
}
