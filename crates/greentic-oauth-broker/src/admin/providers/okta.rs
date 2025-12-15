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
    env,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tracing::warn;
use ulid::Ulid;
use url::Url;

const PROVIDER_KEY: &str = "okta";
const DEFAULT_AUTHZ_SERVER: &str = "default";
const OKTA_CONSENT_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];
const SECRET_OKTA_BASE_URL: &str = "oauth/providers/okta/base-url";
const SECRET_OKTA_API_TOKEN: &str = "oauth/providers/okta/api-token";
const SECRET_OKTA_TENANT_BASE_URL: &str = "oauth/providers/okta/tenant/base-url";
const SECRET_OKTA_TENANT_API_TOKEN: &str = "oauth/providers/okta/tenant/api-token";

pub struct OktaProvisioner {
    public_host: String,
    directory_override: Option<Arc<dyn OktaDirectory>>,
}

impl Default for OktaProvisioner {
    fn default() -> Self {
        Self::new(None)
    }
}

impl OktaProvisioner {
    pub fn new(secrets: Option<Arc<dyn SecretStore>>) -> Self {
        let public_host =
            std::env::var("PUBLIC_HOST").unwrap_or_else(|_| "localhost:8080".to_string());
        let mut provisioner = Self {
            public_host,
            directory_override: None,
        };
        if let Some(secrets) = secrets {
            provisioner.directory_override = LiveOktaDirectory::from_store(secrets.as_ref())
                .ok()
                .flatten()
                .map(|dir| Arc::new(dir) as Arc<dyn OktaDirectory>);
        }
        provisioner
    }

    #[cfg(test)]
    fn with_directory(directory: Arc<dyn OktaDirectory>) -> Self {
        Self {
            public_host: "localhost:8080".into(),
            directory_override: Some(directory),
        }
    }

    fn directory(&self, secrets: &dyn SecretStore) -> Arc<dyn OktaDirectory> {
        if let Some(override_dir) = &self.directory_override {
            return override_dir.clone();
        }

        match LiveOktaDirectory::from_store(secrets) {
            Ok(Some(client)) => Arc::new(client),
            Ok(None) => Arc::new(MockOktaDirectory::default()),
            Err(err) => {
                warn!("OKTA_BASE_URL/OKTA_API_TOKEN unavailable ({err}); using mock directory");
                Arc::new(MockOktaDirectory::default())
            }
        }
    }

    fn is_global_tenant(tenant: &str) -> bool {
        tenant.eq_ignore_ascii_case("global")
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
        for base in ["openid", "profile", "email", "offline_access"] {
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
        base.set_path(&format!("/admin/providers/{}/callback", PROVIDER_KEY));
        base.query_pairs_mut().clear();
        base.query_pairs_mut().append_pair("tenant", tenant);
        Ok(base.to_string())
    }

    fn ensure_global_application(
        &self,
        ctx: ProvisionContext<'_>,
        desired: &DesiredApp,
    ) -> Result<ProvisionReport> {
        let directory = self.directory(ctx.secrets());
        let label = if desired.display_name.trim().is_empty() {
            "Greentic Okta Global".to_string()
        } else {
            desired.display_name.clone()
        };
        let mut report = ProvisionReport {
            provider: self.name().into(),
            tenant: ctx.tenant().into(),
            ..ProvisionReport::default()
        };

        let mut is_new = false;
        let mut app = match directory.fetch_application(&label)? {
            Some(app) => app,
            None => {
                is_new = true;
                OktaApplication::new(label.clone())
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
                bail!("Okta provisioner does not support certificate credentials yet")
            }
        };
        let rotated = app.ensure_secret(rotate_days);

        let saved_app = if ctx.is_dry_run() {
            app
        } else {
            directory.save_application(app)?
        };

        if is_new {
            report.created.push("application".into());
        }
        if rotated {
            report.created.push("client_secret".into());
        }

        let client_id_path = messaging_global_path(PROVIDER_KEY, "client_id");
        write_string_secret_at(ctx.secrets(), &client_id_path, &saved_app.client_id)?;
        report.credentials.push(client_id_path);

        if let Some(secret) = saved_app.secret.as_ref() {
            let client_secret_path = messaging_global_path(PROVIDER_KEY, "client_secret");
            write_string_secret_at(ctx.secrets(), &client_secret_path, &secret.value)?;
            report.credentials.push(client_secret_path);
        }

        let config_path = messaging_global_path(PROVIDER_KEY, "app_config.json");
        let config = json!({
            "label": &saved_app.label,
            "app_id": saved_app.remote_id,
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
        desired: &DesiredApp,
        extras: &BTreeMap<String, String>,
    ) -> Result<ProvisionReport> {
        let tenant = ctx.tenant();
        let mut report = ProvisionReport {
            provider: self.name().into(),
            tenant: tenant.into(),
            ..ProvisionReport::default()
        };

        let issuer = sanitize_field(extras, "issuer")?;
        let mut client_id = extras
            .get("client_id")
            .map(|s| sanitize_value("client_id", s))
            .transpose()?
            .map(ToOwned::to_owned);
        let mut client_secret = extras
            .get("client_secret")
            .map(|s| sanitize_value("client_secret", s))
            .transpose()?
            .map(ToOwned::to_owned);
        let authz_server_id = extras
            .get("authz_server_id")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_AUTHZ_SERVER);
        sanitize_value("authz_server_id", authz_server_id)?;

        if client_id.is_none() || client_secret.is_none() {
            if let Some(auto) = self.automate_tenant_application(&ctx, desired)? {
                client_id.get_or_insert(auto.client_id);
                client_secret.get_or_insert(auto.client_secret);
                report.created.push("application".into());
                report.created.push("client_secret".into());
            } else {
                bail!(
                    "tenant provisioning requires client_id/client_secret or OKTA_TENANT_API_TOKEN"
                );
            }
        }

        let mut credentials = Vec::new();
        let mut created = Vec::new();

        for (key, value) in [
            ("client_id", client_id.as_deref().unwrap()),
            ("client_secret", client_secret.as_deref().unwrap()),
            ("issuer", issuer),
            ("authz_server_id", authz_server_id),
        ] {
            let path = messaging_tenant_path(tenant, PROVIDER_KEY, key);
            write_string_secret_at(ctx.secrets(), &path, value)?;
            credentials.push(path);
            created.push(key.to_string());
        }

        match extras.get("refresh_token") {
            Some(token) => {
                let token = sanitize_value("refresh_token", token)?;
                let path = messaging_tenant_path(tenant, PROVIDER_KEY, "refresh_token");
                write_string_secret_at(ctx.secrets(), &path, token)?;
                credentials.push(path);
                created.push("refresh_token".into());
            }
            None => {
                report.warnings.push(
                    "refresh_token not provided; run consent flow to finish tenant binding".into(),
                );
            }
        }

        report.created = created;
        report.credentials = credentials;
        Ok(report)
    }

    fn automate_tenant_application(
        &self,
        ctx: &ProvisionContext<'_>,
        desired: &DesiredApp,
    ) -> Result<Option<AutomatedTenantApp>> {
        let base = read_string_secret_at(ctx.secrets(), SECRET_OKTA_TENANT_BASE_URL)?;
        let token = read_string_secret_at(ctx.secrets(), SECRET_OKTA_TENANT_API_TOKEN)?;
        let api = if let (Some(base), Some(token)) = (base, token) {
            Some(OktaApiClient::new(&base, &token)?)
        } else {
            match (
                env::var("OKTA_TENANT_BASE_URL"),
                env::var("OKTA_TENANT_API_TOKEN"),
            ) {
                (Ok(base), Ok(token)) => Some(OktaApiClient::new(&base, &token)?),
                _ => None,
            }
        };
        let Some(api) = api else {
            return Ok(None);
        };
        let label = if desired.display_name.trim().is_empty() {
            format!("Greentic Okta Tenant {}", ctx.tenant())
        } else {
            desired.display_name.clone()
        };
        let mut app = OktaApplication::new(label);
        app.redirect_uris = self.desired_redirects(desired);
        app.scopes = self.desired_scopes(desired);
        app.secret = Some(OktaSecret {
            value: String::new(),
            created_at: SystemTime::now(),
        });
        let saved = api.save_application(app)?;
        let client_id = saved.client_id;
        let secret = saved
            .secret
            .as_ref()
            .ok_or_else(|| anyhow!("automated Okta tenant app missing client_secret"))?
            .value
            .clone();
        Ok(Some(AutomatedTenantApp {
            client_id,
            client_secret: secret,
        }))
    }
}

impl AdminProvisioner for OktaProvisioner {
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
        let client_secret = read_required_tenant_secret(ctx.secrets(), tenant, "client_secret")?;
        let redirect_uri = self.callback_url(tenant)?;
        let pkce = PkcePair::generate();
        let state = Ulid::new().to_string();
        let mut extras = BTreeMap::new();
        extras.insert("issuer".into(), issuer.clone());
        extras.insert("client_id".into(), client_id.clone());
        extras.insert("client_secret".into(), client_secret);
        extras.insert("redirect_uri".into(), redirect_uri.clone());
        if let Some(audience) = read_optional_tenant_secret(ctx.secrets(), tenant, "audience")? {
            extras.insert("audience".into(), audience);
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
        let scope_value = OKTA_CONSENT_SCOPES.join(" ");
        let authorize_url = Url::parse_with_params(
            &format!("{issuer}/v1/authorize"),
            &[
                ("client_id", client_id.as_str()),
                ("response_type", "code"),
                ("redirect_uri", redirect_uri.as_str()),
                ("scope", scope_value.as_str()),
                ("state", state.as_str()),
                ("code_challenge", pkce.challenge.as_str()),
                ("code_challenge_method", "S256"),
            ],
        )?;
        Ok(Some(authorize_url))
    }

    fn authorize_admin_callback(
        &self,
        ctx: AdminActionContext<'_>,
        tenant: &str,
        query: &[(String, String)],
    ) -> Result<()> {
        let state = get_param(query, "state").ok_or_else(|| anyhow!("missing state"))?;
        let code = get_param(query, "code").ok_or_else(|| anyhow!("missing code"))?;
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

        let token_url = format!("{issuer}/v1/token");
        let response = HttpClient::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("failed to build Okta consent HTTP client")?
            .post(token_url)
            .form(&form)
            .send()
            .context("Okta token request failed")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!("Okta token request failed {status}: {body}");
        }
        let token_body: Value = response.json().context("invalid Okta token response")?;
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
        if Self::is_global_tenant(ctx.tenant()) {
            self.ensure_global_application(ctx, desired)
        } else {
            let extras = desired
                .extra_params
                .as_ref()
                .ok_or_else(|| anyhow!("tenant provisioning requires extra_params"))?;
            self.ensure_tenant_credentials(ctx, desired, extras)
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

#[derive(Clone)]
struct OktaApplication {
    remote_id: Option<String>,
    label: String,
    client_id: String,
    redirect_uris: BTreeSet<String>,
    scopes: BTreeSet<String>,
    secret: Option<OktaSecret>,
}

impl OktaApplication {
    fn new(label: String) -> Self {
        Self {
            remote_id: None,
            label,
            client_id: Ulid::new().to_string(),
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
            self.secret = Some(OktaSecret {
                value: new_secret,
                created_at: SystemTime::now(),
            });
        }
        needs_rotation
    }
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

fn get_param<'a>(query: &'a [(String, String)], key: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

#[derive(Clone)]
struct OktaSecret {
    value: String,
    created_at: SystemTime,
}

struct AutomatedTenantApp {
    client_id: String,
    client_secret: String,
}

trait OktaDirectory: Send + Sync {
    fn fetch_application(&self, label: &str) -> Result<Option<OktaApplication>>;
    fn save_application(&self, app: OktaApplication) -> Result<OktaApplication>;
}

#[derive(Default)]
struct MockOktaDirectory {
    apps: Mutex<BTreeMap<String, OktaApplication>>,
}

impl OktaDirectory for MockOktaDirectory {
    fn fetch_application(&self, label: &str) -> Result<Option<OktaApplication>> {
        Ok(self.apps.lock().unwrap().get(label).cloned())
    }

    fn save_application(&self, mut app: OktaApplication) -> Result<OktaApplication> {
        if app.remote_id.is_none() {
            app.remote_id = Some(format!("mock-{}", Ulid::new()));
        }
        self.apps
            .lock()
            .unwrap()
            .insert(app.label.clone(), app.clone());
        Ok(app)
    }
}

struct LiveOktaDirectory {
    api: OktaApiClient,
}

impl LiveOktaDirectory {
    fn from_store(secrets: &dyn SecretStore) -> Result<Option<Self>> {
        let base = read_string_secret_at(secrets, SECRET_OKTA_BASE_URL)?;
        let token = read_string_secret_at(secrets, SECRET_OKTA_API_TOKEN)?;
        if base.is_some() || token.is_some() {
            let base =
                base.ok_or_else(|| anyhow!("secret `{SECRET_OKTA_BASE_URL}` must be set"))?;
            let token =
                token.ok_or_else(|| anyhow!("secret `{SECRET_OKTA_API_TOKEN}` must be set"))?;
            let api = OktaApiClient::new(&base, &token)?;
            return Ok(Some(Self { api }));
        }

        let base = match std::env::var("OKTA_BASE_URL") {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        let token = match std::env::var("OKTA_API_TOKEN") {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        let api = OktaApiClient::new(&base, &token)?;
        Ok(Some(Self { api }))
    }
}

impl OktaDirectory for LiveOktaDirectory {
    fn fetch_application(&self, label: &str) -> Result<Option<OktaApplication>> {
        self.api.fetch_application(label)
    }

    fn save_application(&self, app: OktaApplication) -> Result<OktaApplication> {
        self.api.save_application(app)
    }
}

struct OktaApiClient {
    http: HttpClient,
    base_url: Url,
    token: String,
}

impl OktaApiClient {
    fn new(base_url: &str, token: &str) -> Result<Self> {
        let mut parsed =
            Url::parse(base_url).with_context(|| format!("invalid OKTA_BASE_URL `{base_url}`"))?;
        if !parsed.path().ends_with('/') {
            parsed.set_path(&(parsed.path().to_string() + "/"));
        }
        let http = HttpClient::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("failed to build Okta HTTP client")?;
        Ok(Self {
            http,
            base_url: parsed,
            token: token.to_string(),
        })
    }

    fn fetch_application(&self, label: &str) -> Result<Option<OktaApplication>> {
        let url = self.base_url.join("api/v1/apps")?;
        let apps: Vec<Value> =
            self.send_json(self.http.get(url).query(&[("q", label), ("limit", "20")]))?;
        for value in apps {
            let matches = value
                .get("label")
                .and_then(|v| v.as_str())
                .map(|existing| existing.eq_ignore_ascii_case(label))
                .unwrap_or(false);
            if matches {
                return Ok(Some(Self::value_to_application(&value)?));
            }
        }
        Ok(None)
    }

    fn save_application(&self, app: OktaApplication) -> Result<OktaApplication> {
        let rotate_secret = app.secret.is_some();
        match app.remote_id.as_deref() {
            Some(id) => self.update_application(id, &app, rotate_secret),
            None => self.create_application(&app, rotate_secret),
        }
    }

    fn create_application(
        &self,
        app: &OktaApplication,
        rotate_secret: bool,
    ) -> Result<OktaApplication> {
        let url = self.base_url.join("api/v1/apps")?;
        let payload = Self::application_payload(app);
        let value: Value = self.send_json(self.http.post(url).json(&payload))?;
        let mut created = Self::value_to_application(&value)?;
        if rotate_secret
            && let Some(id) = created.remote_id.clone()
            && let Some(secret) = self.rotate_secret(&id)?
        {
            created.secret = Some(secret);
        }
        Ok(created)
    }

    fn update_application(
        &self,
        id: &str,
        app: &OktaApplication,
        rotate_secret: bool,
    ) -> Result<OktaApplication> {
        let url = self.base_url.join(&format!("api/v1/apps/{id}"))?;
        let payload = Self::application_payload(app);
        let value: Value = self.send_json(self.http.put(url).json(&payload))?;
        let mut updated = Self::value_to_application(&value)?;
        if rotate_secret && let Some(secret) = self.rotate_secret(id)? {
            updated.secret = Some(secret);
        }
        Ok(updated)
    }

    fn rotate_secret(&self, id: &str) -> Result<Option<OktaSecret>> {
        let url = self
            .base_url
            .join(&format!("api/v1/apps/{id}/lifecycle/newSecret"))?;
        let value: Value = self.send_json(self.http.post(url))?;
        if let Some(secret) = Self::extract_secret(&value) {
            Ok(Some(OktaSecret {
                value: secret,
                created_at: SystemTime::now(),
            }))
        } else {
            Ok(None)
        }
    }

    fn send_json<T: DeserializeOwned>(&self, builder: RequestBuilder) -> Result<T> {
        let response = builder
            .header("Authorization", format!("SSWS {}", self.token))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .send()
            .context("failed to call Okta API")?;
        if response.status().is_success() {
            response
                .json::<T>()
                .context("failed to parse Okta API response")
        } else {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            Err(anyhow!("Okta API error {status}: {body}"))
        }
    }

    fn application_payload(app: &OktaApplication) -> Value {
        let redirects: Vec<&str> = app.redirect_uris.iter().map(|s| s.as_str()).collect();
        let scopes: Vec<&str> = app.scopes.iter().map(|s| s.as_str()).collect();
        json!({
            "name": "oidc_client",
            "label": app.label.clone(),
            "signOnMode": "OPENID_CONNECT",
            "credentials": {
                "oauthClient": {
                    "autoKeyRotation": true,
                    "token_endpoint_auth_method": "client_secret_basic"
                }
            },
            "settings": {
                "oauthClient": {
                    "application_type": "web",
                    "consent_method": "REQUIRED",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "redirect_uris": redirects,
                    "scope": scopes,
                }
            }
        })
    }

    fn value_to_application(value: &Value) -> Result<OktaApplication> {
        let label = value
            .get("label")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Okta app missing label"))?
            .to_string();
        let client_id = value
            .pointer("/credentials/oauthClient/client_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let redirect_uris = value
            .pointer("/settings/oauthClient/redirect_uris")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(String::from))
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let scopes = value
            .pointer("/settings/oauthClient/scope")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(String::from))
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let secret = Self::extract_secret(value).map(|secret| OktaSecret {
            value: secret,
            created_at: SystemTime::now(),
        });
        Ok(OktaApplication {
            remote_id: value
                .get("id")
                .and_then(|v| v.as_str())
                .map(|id| id.to_string()),
            label,
            client_id,
            redirect_uris,
            scopes,
            secret,
        })
    }

    fn extract_secret(value: &Value) -> Option<String> {
        value
            .pointer("/credentials/oauthClient/client_secret")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admin::secrets::{NoopSecretStore, SecretStore},
        storage::secrets_manager::{SecretPath, StorageError},
    };
    use serde_json::Value;

    #[derive(Default)]
    struct MemoryStore {
        writes: Mutex<Vec<(String, Value)>>,
        values: Mutex<std::collections::HashMap<String, Value>>,
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

    fn desired_app() -> DesiredApp {
        DesiredApp {
            display_name: "Greentic Okta".into(),
            redirect_uris: vec![],
            scopes: vec![],
            audience: None,
            creds: CredentialPolicy::ClientSecret { rotate_days: 1 },
            webhooks: None,
            extra_params: None,
            resources: Vec::new(),
            tenant_metadata: None,
        }
    }

    #[test]
    fn ensures_global_app_and_writes_secrets() {
        let directory: Arc<dyn OktaDirectory> = Arc::new(MockOktaDirectory::default());
        let provisioner = OktaProvisioner::with_directory(directory);
        let store = MemoryStore::default();
        let ctx = ProvisionContext::new("global", &store);
        let report = provisioner
            .ensure_application(ctx, &desired_app())
            .expect("ensure");
        assert!(report.credentials.iter().any(|p| p.contains("client_id")));
        assert!(
            report
                .credentials
                .iter()
                .any(|p| p.contains("client_secret"))
        );
        assert!(
            report
                .credentials
                .iter()
                .any(|p| p.contains("app_config.json"))
        );
    }

    #[test]
    fn stores_tenant_credentials_from_extras() {
        let provisioner = OktaProvisioner::with_directory(Arc::new(MockOktaDirectory::default()));
        let store = MemoryStore::default();
        let mut extras = BTreeMap::new();
        extras.insert(
            "issuer".into(),
            "https://acme.okta.com/oauth2/default".into(),
        );
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
                .any(|p| p.contains("tenant-a/okta/refresh_token"))
        );
    }

    #[derive(Default)]
    struct RecordingDirectory {
        saved: Mutex<bool>,
    }

    impl RecordingDirectory {
        fn saved(&self) -> bool {
            *self.saved.lock().unwrap()
        }
    }

    impl OktaDirectory for RecordingDirectory {
        fn fetch_application(&self, _label: &str) -> Result<Option<OktaApplication>> {
            Ok(None)
        }

        fn save_application(&self, mut app: OktaApplication) -> Result<OktaApplication> {
            *self.saved.lock().unwrap() = true;
            app.remote_id = Some("recording".into());
            Ok(app)
        }
    }

    #[test]
    fn dry_run_does_not_persist_application() {
        let recorder = Arc::new(RecordingDirectory::default());
        let provisioner = OktaProvisioner::with_directory(recorder.clone());
        let noop = NoopSecretStore;
        let ctx = ProvisionContext::dry_run("global", &noop);
        provisioner
            .ensure_application(ctx, &desired_app())
            .expect("plan");
        assert!(!recorder.saved(), "dry-run should not save application");
    }
}
