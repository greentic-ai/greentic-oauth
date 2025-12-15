use super::super::{
    consent::AdminConsentState,
    models::{CredentialPolicy, DesiredApp, ProvisionCaps, ProvisionReport},
    secrets::{
        SecretStore, messaging_global_path, messaging_tenant_path, read_string_secret_at,
        write_string_secret_at,
    },
    traits::{AdminActionContext, AdminProvisioner, ProvisionContext},
};
use crate::security::pkce::PkcePair;
use anyhow::{Context, Result, anyhow, bail};
use rand::distr::{Alphanumeric, SampleString};
use reqwest::{blocking::Client as HttpClient, blocking::RequestBuilder};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tracing::warn;
use ulid::Ulid;
use url::Url;

const PROVIDER_KEY: &str = "auth0";
const AUTH0_CONSENT_SCOPES: &[&str] = &["openid", "profile", "offline_access"];
const SECRET_AUTH0_DOMAIN: &str = "oauth/providers/auth0/domain";
const SECRET_AUTH0_CLIENT_ID: &str = "oauth/providers/auth0/client-id";
const SECRET_AUTH0_CLIENT_SECRET: &str = "oauth/providers/auth0/client-secret";

pub struct Auth0Provisioner {
    public_host: String,
    directory_override: Option<Arc<dyn Auth0Directory>>,
    consent_http: Arc<dyn Auth0ConsentHttpClient>,
}

impl Default for Auth0Provisioner {
    fn default() -> Self {
        Self::new()
    }
}

impl Auth0Provisioner {
    pub fn new() -> Self {
        let public_host =
            std::env::var("PUBLIC_HOST").unwrap_or_else(|_| "localhost:8080".to_string());
        Self {
            public_host,
            directory_override: None,
            consent_http: Arc::new(ReqwestAuth0ConsentHttpClient),
        }
    }

    #[cfg(test)]
    fn with_directory(directory: Arc<dyn Auth0Directory>) -> Self {
        Self {
            public_host: "localhost:8080".into(),
            directory_override: Some(directory),
            consent_http: Arc::new(ReqwestAuth0ConsentHttpClient),
        }
    }

    #[cfg(test)]
    fn with_directory_and_http(
        directory: Arc<dyn Auth0Directory>,
        consent_http: Arc<dyn Auth0ConsentHttpClient>,
    ) -> Self {
        Self {
            public_host: "localhost:8080".into(),
            directory_override: Some(directory),
            consent_http,
        }
    }

    fn directory(&self, secrets: &dyn SecretStore) -> Arc<dyn Auth0Directory> {
        if let Some(override_dir) = &self.directory_override {
            return override_dir.clone();
        }

        match LiveAuth0Directory::from_store(secrets) {
            Ok(Some(dir)) => Arc::new(dir),
            Ok(None) => Arc::new(MockAuth0Directory::default()),
            Err(err) => {
                warn!("Auth0 management credentials unavailable ({err}); using mock directory");
                Arc::new(MockAuth0Directory::default())
            }
        }
    }

    fn default_redirects(&self) -> Vec<String> {
        vec![
            format!(
                "https://{}/admin/oauth/global/callback/{}",
                self.public_host, PROVIDER_KEY
            ),
            format!(
                "https://{}/admin/oauth/tenant/callback/{}",
                self.public_host, PROVIDER_KEY
            ),
        ]
    }

    fn desired_redirects(&self, desired: &DesiredApp) -> BTreeSet<String> {
        if desired.redirect_uris.is_empty() {
            self.default_redirects().into_iter().collect()
        } else {
            desired
                .redirect_uris
                .iter()
                .map(|u| u.to_string())
                .collect()
        }
    }

    fn desired_scopes(&self, desired: &DesiredApp) -> BTreeSet<String> {
        let mut scopes: BTreeSet<String> = desired.scopes.iter().cloned().collect();
        for base in ["openid", "profile", "offline_access"] {
            scopes.insert(base.to_string());
        }
        scopes
    }

    fn public_base_url(&self) -> Result<Url> {
        if self.public_host.starts_with("http://") || self.public_host.starts_with("https://") {
            Url::parse(&self.public_host).context("PUBLIC_HOST must include a valid scheme")
        } else {
            Url::parse(&format!("https://{}", self.public_host))
                .context("failed to parse PUBLIC_HOST as https URL")
        }
    }

    fn callback_url(&self, tenant: &str) -> Result<String> {
        let mut base = self.public_base_url()?;
        base.set_path(&format!("/admin/providers/{}/callback", self.name()));
        base.query_pairs_mut().clear();
        base.query_pairs_mut().append_pair("tenant", tenant);
        Ok(base.to_string())
    }

    fn ensure_global_application(
        &self,
        ctx: ProvisionContext<'_>,
        desired: &DesiredApp,
        directory: &dyn Auth0Directory,
    ) -> Result<ProvisionReport> {
        let label = if desired.display_name.trim().is_empty() {
            "Greentic Auth0 Global".to_string()
        } else {
            desired.display_name.clone()
        };

        let mut report = ProvisionReport {
            provider: self.name().into(),
            tenant: ctx.tenant().into(),
            ..ProvisionReport::default()
        };

        let mut created_app = false;
        let mut app = match directory.fetch_application(&label)? {
            Some(app) => app,
            None => {
                created_app = true;
                Auth0Application::new(label.clone())
            }
        };

        let redirects = self.desired_redirects(desired);
        if app.redirect_uris != redirects {
            app.redirect_uris = redirects;
            report.updated.push("redirect_uris".into());
        }

        let scopes = self.desired_scopes(desired);
        if app.scopes != scopes {
            app.scopes = scopes;
            report.updated.push("scopes".into());
        }

        let rotate_days = match &desired.creds {
            CredentialPolicy::ClientSecret { rotate_days } => *rotate_days,
            CredentialPolicy::Certificate { .. } => {
                bail!("Auth0 provisioner does not support certificate credentials yet")
            }
        };
        let rotated = app.ensure_secret(rotate_days);

        let saved_app = if ctx.is_dry_run() {
            app
        } else {
            directory.save_application(app)?
        };

        if created_app {
            report.created.push("application".into());
        }
        if rotated {
            report.created.push("client_secret".into());
        }

        if let Some(client_id) = saved_app.client_id.as_deref() {
            let client_id_path = messaging_global_path(PROVIDER_KEY, "client_id");
            write_string_secret_at(ctx.secrets(), &client_id_path, client_id)?;
            report.credentials.push(client_id_path);
        } else {
            report
                .warnings
                .push("client_id unavailable; ensure live mode is configured".into());
        }

        if let Some(secret) = saved_app.secret.as_ref() {
            let secret_path = messaging_global_path(PROVIDER_KEY, "client_secret");
            write_string_secret_at(ctx.secrets(), &secret_path, &secret.value)?;
            report.credentials.push(secret_path);
        }

        let config_path = messaging_global_path(PROVIDER_KEY, "app_config.json");
        let config = json!({
            "label": label,
            "client_id": saved_app.client_id,
            "redirect_uris": saved_app.redirect_uris.iter().collect::<Vec<_>>(),
            "scopes": saved_app.scopes.iter().collect::<Vec<_>>(),
        });
        write_string_secret_at(ctx.secrets(), &config_path, &config.to_string())?;
        report.credentials.push(config_path);

        Ok(report)
    }

    fn ensure_tenant_credentials(
        &self,
        ctx: ProvisionContext<'_>,
        extras: &BTreeMap<String, String>,
    ) -> Result<ProvisionReport> {
        let tenant = ctx.tenant();
        let issuer = sanitize_field(extras, "issuer")?;
        let client_id = sanitize_field(extras, "client_id")?;
        let client_secret = sanitize_field(extras, "client_secret")?;
        let refresh_token = extras
            .get("refresh_token")
            .map(|s| sanitize_value("refresh_token", s));

        let mut report = ProvisionReport {
            provider: self.name().into(),
            tenant: tenant.into(),
            ..ProvisionReport::default()
        };

        let mut credentials = Vec::new();
        let mut created = Vec::new();

        for (key, value) in [
            ("issuer", issuer),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ] {
            let path = messaging_tenant_path(tenant, PROVIDER_KEY, key);
            write_string_secret_at(ctx.secrets(), &path, value)?;
            credentials.push(path);
            created.push(key.to_string());
        }

        match refresh_token.transpose()? {
            Some(token) => {
                let path = messaging_tenant_path(tenant, PROVIDER_KEY, "refresh_token");
                write_string_secret_at(ctx.secrets(), &path, token)?;
                credentials.push(path);
                created.push("refresh_token".into());
            }
            None => report
                .warnings
                .push("refresh_token not provided; complete consent flow to obtain one".into()),
        }

        if let Some(audience) = extras.get("audience") {
            let value = sanitize_value("audience", audience)?;
            let path = messaging_tenant_path(tenant, PROVIDER_KEY, "audience");
            write_string_secret_at(ctx.secrets(), &path, value)?;
            credentials.push(path);
            created.push("audience".into());
        }

        report.created = created;
        report.credentials = credentials;
        Ok(report)
    }
}

impl AdminProvisioner for Auth0Provisioner {
    fn name(&self) -> &'static str {
        PROVIDER_KEY
    }

    fn capabilities(&self) -> ProvisionCaps {
        ProvisionCaps {
            app_create: true,
            redirect_manage: true,
            secret_create: true,
            webhook: false,
            scope_grant: true,
        }
    }

    fn authorize_admin_start(
        &self,
        ctx: AdminActionContext<'_>,
        tenant: &str,
    ) -> Result<Option<Url>> {
        let issuer = read_required_tenant_secret(ctx.secrets(), tenant, "issuer")?;
        let client_id = read_required_tenant_secret(ctx.secrets(), tenant, "client_id")?;
        let client_secret = read_optional_tenant_secret(ctx.secrets(), tenant, "client_secret")?;
        let audience = read_optional_tenant_secret(ctx.secrets(), tenant, "audience")?;
        let redirect_uri = self.callback_url(tenant)?;
        let pkce = PkcePair::generate();
        let state = Ulid::new().to_string();

        let mut extras = BTreeMap::new();
        extras.insert("issuer".into(), issuer.clone());
        extras.insert("client_id".into(), client_id.clone());
        extras.insert("redirect_uri".into(), redirect_uri.clone());
        if let Some(secret) = client_secret.as_ref() {
            extras.insert("client_secret".into(), secret.clone());
        }
        if let Some(audience) = audience.as_ref() {
            extras.insert("audience".into(), audience.clone());
        }

        ctx.consent().insert(
            state.clone(),
            AdminConsentState::new(
                self.name(),
                tenant,
                redirect_uri.clone(),
                pkce.verifier.clone(),
                extras,
            ),
        );

        let scope_value = AUTH0_CONSENT_SCOPES.join(" ");
        let mut params = vec![
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", scope_value.as_str()),
            ("state", state.as_str()),
            ("code_challenge", pkce.challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];
        if let Some(audience) = audience.as_ref() {
            params.push(("audience", audience.as_str()));
        }
        let authorize_url = Url::parse_with_params(
            &format!("{}/authorize", normalize_issuer(&issuer)?),
            &params,
        )?;
        Ok(Some(authorize_url))
    }

    fn authorize_admin_callback(
        &self,
        ctx: AdminActionContext<'_>,
        tenant: &str,
        query: &[(String, String)],
    ) -> Result<()> {
        let state = find_param(query, "state").ok_or_else(|| anyhow!("missing state"))?;
        let code = find_param(query, "code").ok_or_else(|| anyhow!("missing code"))?;
        let consent = ctx
            .consent()
            .claim(state)
            .ok_or_else(|| anyhow!("unknown or expired consent state"))?;
        if consent.provider != self.name() {
            bail!("state does not belong to {}", self.name());
        }
        if consent.tenant != tenant {
            bail!("tenant mismatch for consent flow");
        }

        let issuer = consent
            .extras("issuer")
            .ok_or_else(|| anyhow!("consent state missing issuer"))?;
        let client_id = consent
            .extras("client_id")
            .ok_or_else(|| anyhow!("consent state missing client_id"))?;
        let client_secret = consent.extras("client_secret");

        let mut form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("client_id".to_string(), client_id.to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), consent.redirect_uri.clone()),
            ("code_verifier".to_string(), consent.pkce_verifier.clone()),
        ];
        if let Some(secret) = client_secret {
            form.push(("client_secret".into(), secret.to_string()));
        }
        if let Some(audience) = consent.extras("audience") {
            form.push(("audience".into(), audience.to_string()));
        }

        let token_url = format!("{}/oauth/token", normalize_issuer(issuer)?);
        let token_body = self
            .consent_http
            .exchange_code(&token_url, &form)
            .context("Auth0 token request failed")?;
        let refresh_token = token_body
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("token response missing refresh_token"))?;
        let path = messaging_tenant_path(tenant, PROVIDER_KEY, "refresh_token");
        write_string_secret_at(ctx.secrets(), &path, refresh_token)?;
        Ok(())
    }

    fn ensure_application(
        &self,
        ctx: ProvisionContext<'_>,
        desired: &DesiredApp,
    ) -> Result<ProvisionReport> {
        let directory = self.directory(ctx.secrets());
        if ctx.tenant().eq_ignore_ascii_case("global") {
            self.ensure_global_application(ctx, desired, directory.as_ref())
        } else {
            let extras = desired
                .extra_params
                .as_ref()
                .ok_or_else(|| anyhow!("tenant provisioning requires extra_params"))?;
            self.ensure_tenant_credentials(ctx, extras)
        }
    }
}

fn sanitize_field<'a>(extras: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    extras
        .get(key)
        .map(|s| sanitize_value(key, s))
        .transpose()?
        .ok_or_else(|| anyhow!("extra_params missing `{key}`"))
}

fn sanitize_value<'a>(key: &str, value: &'a str) -> Result<&'a str> {
    if value.len() > 512 {
        bail!("value for `{key}` exceeds 512 characters");
    }
    if value.chars().any(|c| c.is_control()) {
        bail!("value for `{key}` contains control characters");
    }
    Ok(value)
}

fn normalize_issuer(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("issuer must not be empty");
    }
    let without_trailing = trimmed.trim_end_matches('/');
    if without_trailing.is_empty() {
        bail!("issuer missing host");
    }
    Ok(without_trailing.to_string())
}

fn read_required_tenant_secret(
    secrets: &dyn SecretStore,
    tenant: &str,
    key: &str,
) -> Result<String> {
    let path = messaging_tenant_path(tenant, PROVIDER_KEY, key);
    read_string_secret_at(secrets, &path)?
        .ok_or_else(|| anyhow!("tenant `{tenant}` missing `{key}` secret"))
}

fn read_optional_tenant_secret(
    secrets: &dyn SecretStore,
    tenant: &str,
    key: &str,
) -> Result<Option<String>> {
    let path = messaging_tenant_path(tenant, PROVIDER_KEY, key);
    Ok(read_string_secret_at(secrets, &path)?)
}

fn find_param<'a>(query: &'a [(String, String)], key: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

#[derive(Clone)]
struct Auth0Application {
    label: String,
    client_id: Option<String>,
    redirect_uris: BTreeSet<String>,
    scopes: BTreeSet<String>,
    secret: Option<Auth0Secret>,
}

impl Auth0Application {
    fn new(label: String) -> Self {
        Self {
            label,
            client_id: None,
            redirect_uris: BTreeSet::new(),
            scopes: BTreeSet::new(),
            secret: None,
        }
    }

    fn ensure_secret(&mut self, rotate_days: u32) -> bool {
        let rotate_after = Duration::from_secs(rotate_days.max(1) as u64 * 86_400);
        let needs_rotation = match &self.secret {
            None => true,
            Some(secret) => secret
                .created_at
                .elapsed()
                .map(|elapsed| elapsed >= rotate_after)
                .unwrap_or(true),
        };
        if needs_rotation {
            let new_secret = Alphanumeric.sample_string(&mut rand::rng(), 64);
            self.secret = Some(Auth0Secret {
                value: new_secret,
                created_at: SystemTime::now(),
            });
        }
        needs_rotation
    }
}

#[derive(Clone)]
struct Auth0Secret {
    value: String,
    created_at: SystemTime,
}

trait Auth0Directory: Send + Sync {
    fn fetch_application(&self, label: &str) -> Result<Option<Auth0Application>>;
    fn save_application(&self, app: Auth0Application) -> Result<Auth0Application>;
}

#[derive(Default)]
struct MockAuth0Directory {
    apps: Mutex<BTreeMap<String, Auth0Application>>,
}

impl Auth0Directory for MockAuth0Directory {
    fn fetch_application(&self, label: &str) -> Result<Option<Auth0Application>> {
        Ok(self.apps.lock().unwrap().get(label).cloned())
    }

    fn save_application(&self, mut app: Auth0Application) -> Result<Auth0Application> {
        if app.client_id.is_none() {
            app.client_id = Some(format!("mock-{}", Ulid::new()));
        }
        self.apps
            .lock()
            .unwrap()
            .insert(app.label.clone(), app.clone());
        Ok(app)
    }
}

struct LiveAuth0Directory {
    api: Auth0ApiClient,
}

impl LiveAuth0Directory {
    fn from_store(secrets: &dyn SecretStore) -> Result<Option<Self>> {
        let domain = read_string_secret_at(secrets, SECRET_AUTH0_DOMAIN)?;
        let client_id = read_string_secret_at(secrets, SECRET_AUTH0_CLIENT_ID)?;
        let client_secret = read_string_secret_at(secrets, SECRET_AUTH0_CLIENT_SECRET)?;
        let any_present = domain.is_some() || client_id.is_some() || client_secret.is_some();

        if any_present {
            let domain =
                domain.ok_or_else(|| anyhow!("secret `{SECRET_AUTH0_DOMAIN}` must be set"))?;
            let client_id = client_id
                .ok_or_else(|| anyhow!("secret `{SECRET_AUTH0_CLIENT_ID}` must be set"))?;
            let client_secret = client_secret
                .ok_or_else(|| anyhow!("secret `{SECRET_AUTH0_CLIENT_SECRET}` must be set"))?;
            let api = Auth0ApiClient::new(&domain, &client_id, &client_secret)?;
            return Ok(Some(Self { api }));
        }

        let domain_present = std::env::var("AUTH0_DOMAIN").is_ok();
        let client_id_present = std::env::var("AUTH0_MGMT_CLIENT_ID").is_ok();
        let client_secret_present = std::env::var("AUTH0_MGMT_CLIENT_SECRET").is_ok();
        if domain_present && client_id_present && client_secret_present {
            let domain = std::env::var("AUTH0_DOMAIN")?;
            let mgmt_client_id = std::env::var("AUTH0_MGMT_CLIENT_ID")?;
            let mgmt_client_secret = std::env::var("AUTH0_MGMT_CLIENT_SECRET")?;
            let api = Auth0ApiClient::new(&domain, &mgmt_client_id, &mgmt_client_secret)?;
            Ok(Some(Self { api }))
        } else if domain_present || client_id_present || client_secret_present {
            bail!(
                "AUTH0_DOMAIN, AUTH0_MGMT_CLIENT_ID, and AUTH0_MGMT_CLIENT_SECRET must all be set for live mode"
            );
        } else {
            Ok(None)
        }
    }
}

impl Auth0Directory for LiveAuth0Directory {
    fn fetch_application(&self, _label: &str) -> Result<Option<Auth0Application>> {
        self.api.fetch_application(_label)
    }

    fn save_application(&self, app: Auth0Application) -> Result<Auth0Application> {
        self.api.save_application(app)
    }
}

struct Auth0ApiClient {
    http: HttpClient,
    base_url: Url,
    token_client_id: String,
    token_client_secret: String,
    token: Mutex<Option<AccessToken>>,
}

struct AccessToken {
    value: String,
    expires_at: SystemTime,
}

impl Auth0ApiClient {
    fn new(domain: &str, client_id: &str, client_secret: &str) -> Result<Self> {
        let base = format!("https://{domain}/");
        let http = HttpClient::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("failed to build Auth0 HTTP client")?;
        Ok(Self {
            http,
            base_url: Url::parse(&base)?,
            token_client_id: client_id.into(),
            token_client_secret: client_secret.into(),
            token: Mutex::new(None),
        })
    }

    fn fetch_application(&self, label: &str) -> Result<Option<Auth0Application>> {
        let url = self.base_url.join("api/v2/clients")?;
        let query = [
            ("fields", "client_id,name,callbacks,grant_types"),
            ("include_fields", "true"),
            ("q", &format!("name:\"{label}\"")),
            ("search_engine", "v3"),
            ("per_page", "20"),
            ("page", "0"),
        ];
        let response: Vec<Value> = self.send_json(self.http.get(url).query(&query))?;
        for item in response {
            if item
                .get("name")
                .and_then(|v| v.as_str())
                .map(|name| name.eq_ignore_ascii_case(label))
                .unwrap_or(false)
            {
                return Ok(Some(Self::value_to_application(&item)?));
            }
        }
        Ok(None)
    }

    fn save_application(&self, app: Auth0Application) -> Result<Auth0Application> {
        if let Some(client_id) = app.client_id.clone() {
            let payload = self.application_payload(&app);
            let url = self.base_url.join(&format!("api/v2/clients/{client_id}"))?;
            let value: Value = self.send_json(self.http.patch(url).json(&payload))?;
            let mut updated = Self::value_to_application(&value)?;
            if app.secret.is_some()
                && let Some(secret) = self.rotate_secret(updated.client_id.as_deref())?
            {
                updated.secret = Some(secret);
            }
            Ok(updated)
        } else {
            let payload = self.application_payload(&app);
            let url = self.base_url.join("api/v2/clients")?;
            let value: Value = self.send_json(self.http.post(url).json(&payload))?;
            let mut created = Self::value_to_application(&value)?;
            if let Some(secret) =
                value
                    .get("client_secret")
                    .and_then(|v| v.as_str())
                    .map(|secret| Auth0Secret {
                        value: secret.to_string(),
                        created_at: SystemTime::now(),
                    })
            {
                created.secret = Some(secret);
            }
            Ok(created)
        }
    }

    fn rotate_secret(&self, client_id: Option<&str>) -> Result<Option<Auth0Secret>> {
        let Some(client_id) = client_id else {
            return Ok(None);
        };
        let url = self
            .base_url
            .join(&format!("api/v2/clients/{client_id}/rotate-secret"))?;
        let value: Value = self.send_json(self.http.post(url))?;
        Ok(value
            .get("client_secret")
            .and_then(|v| v.as_str())
            .map(|secret| Auth0Secret {
                value: secret.to_string(),
                created_at: SystemTime::now(),
            }))
    }

    fn send_json<T: DeserializeOwned>(&self, builder: RequestBuilder) -> Result<T> {
        let response = builder
            .bearer_auth(self.access_token()?)
            .header("Accept", "application/json")
            .send()
            .context("Auth0 API call failed")?;
        if response.status().is_success() {
            response
                .json::<T>()
                .context("failed to parse Auth0 response")
        } else {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            Err(anyhow!("Auth0 API error {status}: {body}"))
        }
    }

    fn application_payload(&self, app: &Auth0Application) -> Value {
        let callbacks: Vec<&str> = app.redirect_uris.iter().map(|s| s.as_str()).collect();
        json!({
            "name": app.label,
            "callbacks": callbacks,
            "app_type": "regular_web",
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "client_secret_post",
            "oidc_conformant": true,
        })
    }

    fn value_to_application(value: &Value) -> Result<Auth0Application> {
        let label = value
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Auth0 app missing name"))?
            .to_string();
        let client_id = value
            .get("client_id")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());
        let redirect_uris = value
            .get("callbacks")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(String::from))
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        Ok(Auth0Application {
            label,
            client_id,
            redirect_uris,
            scopes: BTreeSet::new(),
            secret: None,
        })
    }

    fn access_token(&self) -> Result<String> {
        {
            let guard = self.token.lock().expect("auth0 token lock poisoned");
            if let Some(token) = guard.as_ref()
                && token.expires_at > SystemTime::now() + Duration::from_secs(30)
            {
                return Ok(token.value.clone());
            }
        }

        let token_url = self.base_url.join("oauth/token")?;
        let payload = json!({
            "client_id": self.token_client_id,
            "client_secret": self.token_client_secret,
            "audience": format!("{}api/v2/", self.base_url),
            "grant_type": "client_credentials",
        });
        let response = self
            .http
            .post(token_url)
            .json(&payload)
            .send()
            .context("failed to obtain Auth0 token")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!("Auth0 token request failed {status}: {body}");
        }
        let value: Value = response.json().context("invalid Auth0 token response")?;
        let access_token = value
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("token response missing access_token"))?
            .to_string();
        let expires_in = value
            .get("expires_in")
            .and_then(|v| v.as_i64())
            .unwrap_or(3600) as u64;
        *self.token.lock().unwrap() = Some(AccessToken {
            value: access_token.clone(),
            expires_at: SystemTime::now() + Duration::from_secs(expires_in),
        });
        Ok(access_token)
    }
}

trait Auth0ConsentHttpClient: Send + Sync {
    fn exchange_code(&self, url: &str, form: &[(String, String)]) -> Result<Value>;
}

#[derive(Default)]
struct ReqwestAuth0ConsentHttpClient;

impl Auth0ConsentHttpClient for ReqwestAuth0ConsentHttpClient {
    fn exchange_code(&self, url: &str, form: &[(String, String)]) -> Result<Value> {
        let owned_form: Vec<(String, String)> = form.to_vec();
        let response = HttpClient::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("failed to build Auth0 consent HTTP client")?
            .post(url)
            .form(&owned_form)
            .send()
            .context("Auth0 token request failed")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!("Auth0 token request failed {status}: {body}");
        }
        response
            .json::<Value>()
            .context("invalid Auth0 token response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admin::{
            consent::AdminConsentStore,
            secrets::{SecretStore, messaging_tenant_path},
            traits::AdminActionContext,
        },
        storage::secrets_manager::{SecretPath, StorageError},
    };
    use serde_json::Value;
    use std::{collections::HashMap, sync::Mutex, time::Duration};

    #[derive(Default)]
    struct MemoryStore {
        writes: Mutex<Vec<(String, Value)>>,
        values: Mutex<HashMap<String, Value>>,
    }

    impl SecretStore for MemoryStore {
        fn put_json_value(&self, path: &SecretPath, value: &Value) -> Result<(), StorageError> {
            let key = path.as_str().to_string();
            self.writes
                .lock()
                .unwrap()
                .push((key.clone(), value.clone()));
            self.values.lock().unwrap().insert(key, value.clone());
            Ok(())
        }

        fn get_json_value(&self, path: &SecretPath) -> Result<Option<Value>, StorageError> {
            Ok(self.values.lock().unwrap().get(path.as_str()).cloned())
        }

        fn delete_value(&self, path: &SecretPath) -> Result<(), StorageError> {
            self.values.lock().unwrap().remove(path.as_str());
            Ok(())
        }
    }

    impl MemoryStore {
        fn read_string(&self, path: &str) -> Option<String> {
            self.values
                .lock()
                .unwrap()
                .get(path)
                .and_then(|value| value.get("value"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        }
    }

    fn desired_app() -> DesiredApp {
        DesiredApp {
            display_name: "Greentic Auth0".into(),
            redirect_uris: vec![],
            scopes: vec![],
            audience: None,
            creds: CredentialPolicy::ClientSecret { rotate_days: 90 },
            webhooks: None,
            extra_params: None,
            resources: Vec::new(),
            tenant_metadata: None,
        }
    }

    type RequestCapture = (String, Vec<(String, String)>);

    #[derive(Default)]
    struct StubConsentHttp {
        last_request: Mutex<Option<RequestCapture>>,
        refresh_token: String,
    }

    impl StubConsentHttp {
        fn new(refresh_token: &str) -> Self {
            Self {
                refresh_token: refresh_token.to_string(),
                ..Default::default()
            }
        }

        fn take_request(&self) -> Option<RequestCapture> {
            self.last_request.lock().unwrap().take()
        }
    }

    impl Auth0ConsentHttpClient for StubConsentHttp {
        fn exchange_code(&self, url: &str, form: &[(String, String)]) -> Result<Value> {
            assert!(
                url.ends_with("/oauth/token"),
                "expected auth0 token endpoint, got {url}"
            );
            *self.last_request.lock().unwrap() = Some((url.to_string(), form.to_vec()));
            Ok(json!({ "refresh_token": self.refresh_token }))
        }
    }

    #[test]
    fn ensures_global_app() {
        let directory: Arc<dyn Auth0Directory> = Arc::new(MockAuth0Directory::default());
        let provisioner = Auth0Provisioner::with_directory(directory);
        let store = MemoryStore::default();
        let ctx = ProvisionContext::new("global", &store);
        let report = provisioner
            .ensure_application(ctx, &desired_app())
            .expect("ensure");
        assert!(
            report
                .credentials
                .iter()
                .any(|path| path.contains("messaging/global/auth0/client_id"))
        );
    }

    #[test]
    fn stores_tenant_credentials() {
        let provisioner = Auth0Provisioner::with_directory(Arc::new(MockAuth0Directory::default()));
        let store = MemoryStore::default();
        let mut extras = BTreeMap::new();
        extras.insert("issuer".into(), "https://acme.eu.auth0.com/".into());
        extras.insert("client_id".into(), "CLIENT".into());
        extras.insert("client_secret".into(), "SECRET".into());
        extras.insert("refresh_token".into(), "REFRESH".into());
        let mut desired = desired_app();
        desired.extra_params = Some(extras);
        let ctx = ProvisionContext::new("tenant-a", &store);
        let report = provisioner
            .ensure_application(ctx, &desired)
            .expect("ensure");
        assert!(report.warnings.is_empty());
        assert!(
            report
                .credentials
                .iter()
                .any(|path| path.contains("tenant-a/auth0/refresh_token"))
        );
    }

    #[tokio::test]
    async fn admin_consent_flow_persists_refresh_token() {
        let secrets = MemoryStore::default();
        let issuer = "https://tenant.eu.auth0.com/".to_string();
        let tenant = "acme";
        for (key, value) in [
            ("issuer", issuer.as_str()),
            ("client_id", "CLIENT"),
            ("client_secret", "SECRET"),
        ] {
            let path = messaging_tenant_path(tenant, PROVIDER_KEY, key);
            write_string_secret_at(&secrets, &path, value).unwrap();
        }

        let consent_http = Arc::new(StubConsentHttp::new("rt-123"));
        let provisioner = Auth0Provisioner::with_directory_and_http(
            Arc::new(MockAuth0Directory::default()),
            consent_http.clone(),
        );
        let consent_store = AdminConsentStore::new(Duration::from_secs(60));
        let start_ctx = AdminActionContext::new(&secrets, &consent_store);
        let start_url = provisioner
            .authorize_admin_start(start_ctx, tenant)
            .expect("start")
            .expect("start url");
        let state = Url::parse(start_url.as_str())
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string())
            .expect("state param");

        let callback_ctx = AdminActionContext::new(&secrets, &consent_store);
        provisioner
            .authorize_admin_callback(
                callback_ctx,
                tenant,
                &[("state".into(), state), ("code".into(), "CODE123".into())],
            )
            .expect("callback");

        let recorded = consent_http.take_request().expect("http call recorded");
        assert!(recorded.0.starts_with(issuer.trim_end_matches('/')));
        assert!(
            recorded
                .1
                .iter()
                .any(|(k, v)| k == "code" && v == "CODE123")
        );

        let refresh_path = messaging_tenant_path(tenant, PROVIDER_KEY, "refresh_token");
        assert_eq!(
            secrets.read_string(&refresh_path).as_deref(),
            Some("rt-123")
        );
    }
}
