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
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
use tracing::warn;
use ulid::Ulid;
use url::Url;

const PROVIDER_KEY: &str = "keycloak";
const SECRET_KEYCLOAK_BASE_URL: &str = "oauth/providers/keycloak/base-url";
const SECRET_KEYCLOAK_REALM: &str = "oauth/providers/keycloak/realm";
const SECRET_KEYCLOAK_CLIENT_ID: &str = "oauth/providers/keycloak/client-id";
const SECRET_KEYCLOAK_CLIENT_SECRET: &str = "oauth/providers/keycloak/client-secret";
const KEYCLOAK_CONSENT_SCOPES: &[&str] = &["openid", "profile", "offline_access"];

pub struct KeycloakProvisioner {
    public_host: String,
    directory_override: Option<Arc<dyn KeycloakDirectory>>,
    consent_http: Arc<dyn KeycloakConsentHttpClient>,
}

impl Default for KeycloakProvisioner {
    fn default() -> Self {
        Self::new(None)
    }
}

impl KeycloakProvisioner {
    pub fn new(secrets: Option<Arc<dyn SecretStore>>) -> Self {
        let public_host =
            std::env::var("PUBLIC_HOST").unwrap_or_else(|_| "localhost:8080".to_string());
        let mut provisioner = Self {
            public_host,
            directory_override: None,
            consent_http: Arc::new(ReqwestKeycloakConsentHttpClient),
        };
        if let Some(secrets) = secrets {
            provisioner.directory_override = LiveKeycloakDirectory::from_store(secrets.as_ref())
                .ok()
                .flatten()
                .map(|dir| Arc::new(dir) as Arc<dyn KeycloakDirectory>);
        }
        provisioner
    }

    #[cfg(test)]
    fn with_directory(directory: Arc<dyn KeycloakDirectory>) -> Self {
        Self {
            public_host: "localhost:8080".into(),
            directory_override: Some(directory),
            consent_http: Arc::new(ReqwestKeycloakConsentHttpClient),
        }
    }

    #[cfg(test)]
    fn with_directory_and_http(
        directory: Arc<dyn KeycloakDirectory>,
        consent_http: Arc<dyn KeycloakConsentHttpClient>,
    ) -> Self {
        Self {
            public_host: "localhost:8080".into(),
            directory_override: Some(directory),
            consent_http,
        }
    }

    fn directory(&self, secrets: &dyn SecretStore) -> Arc<dyn KeycloakDirectory> {
        if let Some(override_dir) = &self.directory_override {
            return override_dir.clone();
        }

        match LiveKeycloakDirectory::from_store(secrets) {
            Ok(Some(dir)) => Arc::new(dir),
            Ok(None) => Arc::new(MockKeycloakDirectory::default()),
            Err(err) => {
                warn!("Keycloak management credentials unavailable ({err}); using mock directory");
                Arc::new(MockKeycloakDirectory::default())
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
        if desired.scopes.is_empty() {
            ["openid", "profile"]
                .into_iter()
                .map(String::from)
                .collect()
        } else {
            desired.scopes.iter().cloned().collect()
        }
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
        directory: &dyn KeycloakDirectory,
    ) -> Result<ProvisionReport> {
        let client_name = if desired.display_name.trim().is_empty() {
            "Greentic Keycloak Global".to_string()
        } else {
            desired.display_name.clone()
        };

        let mut report = ProvisionReport {
            provider: self.name().into(),
            tenant: ctx.tenant().into(),
            ..ProvisionReport::default()
        };

        let mut app = match directory.fetch_client(&client_name)? {
            Some(app) => app,
            None => {
                report.created.push("application".into());
                KeycloakClient::new(client_name.clone())
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

        let rotate_days = match desired.creds {
            CredentialPolicy::ClientSecret { rotate_days } => rotate_days,
            CredentialPolicy::Certificate { .. } => {
                bail!("Keycloak provisioner does not support certificate credentials yet")
            }
        };
        let rotated = app.ensure_secret(rotate_days);
        if rotated {
            report.created.push("client_secret".into());
        }

        let saved_app = if ctx.is_dry_run() {
            app
        } else {
            directory.save_client(app)?
        };

        let client_id_path = messaging_global_path(PROVIDER_KEY, "client_id");
        write_string_secret_at(ctx.secrets(), &client_id_path, &saved_app.client_id)?;
        report.credentials.push(client_id_path);

        if let Some(secret) = saved_app.secret.as_ref() {
            let secret_path = messaging_global_path(PROVIDER_KEY, "client_secret");
            write_string_secret_at(ctx.secrets(), &secret_path, &secret.value)?;
            report.credentials.push(secret_path);
        }

        let config_path = messaging_global_path(PROVIDER_KEY, "app_config.json");
        let config = json!({
            "client_name": client_name,
            "remote_id": saved_app.remote_id,
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
        let client_id = sanitize_field(extras, "client_id")?;
        let client_secret = sanitize_field(extras, "client_secret")?;
        let issuer = extras
            .get("issuer")
            .map(|s| sanitize_value("issuer", s))
            .transpose()?;

        let mut credentials = Vec::new();
        let mut created = Vec::new();

        for (key, value) in [("client_id", client_id), ("client_secret", client_secret)] {
            let path = messaging_tenant_path(tenant, PROVIDER_KEY, key);
            write_string_secret_at(ctx.secrets(), &path, value)?;
            credentials.push(path);
            created.push(key.to_string());
        }

        if let Some(issuer) = issuer {
            let path = messaging_tenant_path(tenant, PROVIDER_KEY, "issuer");
            write_string_secret_at(ctx.secrets(), &path, issuer)?;
            credentials.push(path);
            created.push("issuer".into());
        }

        Ok(ProvisionReport {
            provider: self.name().into(),
            tenant: tenant.into(),
            created,
            credentials,
            ..ProvisionReport::default()
        })
    }
}

impl AdminProvisioner for KeycloakProvisioner {
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

        let authorize_url = Url::parse_with_params(
            &format!(
                "{}/protocol/openid-connect/auth",
                normalize_issuer(&issuer)?
            ),
            &[
                ("response_type", "code"),
                ("client_id", client_id.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("scope", KEYCLOAK_CONSENT_SCOPES.join(" ").as_str()),
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
        if let Some(error) = find_param(query, "error") {
            let desc = find_param(query, "error_description").unwrap_or_default();
            bail!("Keycloak admin consent failed: {error} ({desc})");
        }
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

        let token_url = format!(
            "{}/protocol/openid-connect/token",
            normalize_issuer(issuer)?
        );
        let token_body = self
            .consent_http
            .exchange_code(&token_url, &form)
            .context("Keycloak token request failed")?;
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
    Ok(trimmed.trim_end_matches('/').to_string())
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
struct KeycloakClient {
    label: String,
    client_id: String,
    remote_id: Option<String>,
    redirect_uris: BTreeSet<String>,
    scopes: BTreeSet<String>,
    secret: Option<KeycloakSecret>,
}

impl KeycloakClient {
    fn new(client_name: String) -> Self {
        Self {
            label: client_name.clone(),
            client_id: format!("{}_{}", client_name.replace(' ', "_"), Ulid::new()),
            remote_id: None,
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
            self.secret = Some(KeycloakSecret {
                value: new_secret,
                created_at: SystemTime::now(),
            });
        }
        needs_rotation
    }
}

#[derive(Clone)]
struct KeycloakSecret {
    value: String,
    created_at: SystemTime,
}

trait KeycloakDirectory: Send + Sync {
    fn fetch_client(&self, label: &str) -> Result<Option<KeycloakClient>>;
    fn save_client(&self, app: KeycloakClient) -> Result<KeycloakClient>;
}

#[derive(Default)]
struct MockKeycloakDirectory {
    clients: Mutex<BTreeMap<String, KeycloakClient>>,
}

impl KeycloakDirectory for MockKeycloakDirectory {
    fn fetch_client(&self, label: &str) -> Result<Option<KeycloakClient>> {
        Ok(self.clients.lock().unwrap().get(label).cloned())
    }

    fn save_client(&self, mut app: KeycloakClient) -> Result<KeycloakClient> {
        if app.remote_id.is_none() {
            app.remote_id = Some(format!("mock-{}", Ulid::new()));
        }
        self.clients
            .lock()
            .unwrap()
            .insert(app.label.clone(), app.clone());
        Ok(app)
    }
}

struct LiveKeycloakDirectory {
    api: KeycloakApiClient,
}

impl LiveKeycloakDirectory {
    fn from_store(secrets: &dyn SecretStore) -> Result<Option<Self>> {
        let base = read_string_secret_at(secrets, SECRET_KEYCLOAK_BASE_URL)?;
        let realm = read_string_secret_at(secrets, SECRET_KEYCLOAK_REALM)?;
        let client = read_string_secret_at(secrets, SECRET_KEYCLOAK_CLIENT_ID)?;
        let secret = read_string_secret_at(secrets, SECRET_KEYCLOAK_CLIENT_SECRET)?;

        let any = base.is_some() || realm.is_some() || client.is_some() || secret.is_some();
        if any {
            let base =
                base.ok_or_else(|| anyhow!("secret `{SECRET_KEYCLOAK_BASE_URL}` must be set"))?;
            let realm =
                realm.ok_or_else(|| anyhow!("secret `{SECRET_KEYCLOAK_REALM}` must be set"))?;
            let client = client
                .ok_or_else(|| anyhow!("secret `{SECRET_KEYCLOAK_CLIENT_ID}` must be set"))?;
            let secret = secret
                .ok_or_else(|| anyhow!("secret `{SECRET_KEYCLOAK_CLIENT_SECRET}` must be set"))?;
            let api = KeycloakApiClient::new(&base, &realm, &client, &secret)?;
            return Ok(Some(Self { api }));
        }

        let base_env = std::env::var("KC_BASE_URL").ok();
        let realm_env = std::env::var("KC_REALM").ok();
        let client_env = std::env::var("KC_CLIENT_ID").ok();
        let secret_env = std::env::var("KC_CLIENT_SECRET").ok();
        match (base_env, realm_env, client_env, secret_env) {
            (Some(base), Some(realm), Some(client), Some(secret)) => {
                let api = KeycloakApiClient::new(&base, &realm, &client, &secret)?;
                Ok(Some(Self { api }))
            }
            (base, realm, client, secret) => {
                if base.is_some() || realm.is_some() || client.is_some() || secret.is_some() {
                    bail!(
                        "KC_BASE_URL, KC_REALM, KC_CLIENT_ID, and KC_CLIENT_SECRET must all be set for live provisioning"
                    );
                }
                Ok(None)
            }
        }
    }
}

impl KeycloakDirectory for LiveKeycloakDirectory {
    fn fetch_client(&self, _label: &str) -> Result<Option<KeycloakClient>> {
        self.api.fetch_client(_label)
    }

    fn save_client(&self, app: KeycloakClient) -> Result<KeycloakClient> {
        self.api.save_client(app)
    }
}

struct KeycloakApiClient {
    http: HttpClient,
    base_url: Url,
    realm: String,
    admin_client_id: String,
    admin_client_secret: String,
    token: Mutex<Option<AccessToken>>,
}

struct AccessToken {
    value: String,
    expires_at: Instant,
}

impl KeycloakApiClient {
    fn new(base_url: &str, realm: &str, client_id: &str, client_secret: &str) -> Result<Self> {
        let mut base =
            Url::parse(base_url).with_context(|| format!("invalid KC_BASE_URL `{base_url}`"))?;
        if !base.path().ends_with('/') {
            base.set_path(&(base.path().to_string() + "/"));
        }
        let http = HttpClient::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("failed to build Keycloak HTTP client")?;
        Ok(Self {
            http,
            base_url: base,
            realm: realm.to_string(),
            admin_client_id: client_id.to_string(),
            admin_client_secret: client_secret.to_string(),
            token: Mutex::new(None),
        })
    }

    fn fetch_client(&self, label: &str) -> Result<Option<KeycloakClient>> {
        let url = self.base_url.join(&format!(
            "admin/realms/{}/clients?clientId={}",
            self.realm, label
        ))?;
        let response: Vec<serde_json::Value> = self.send_json(self.http.get(url))?;
        for item in response {
            if item
                .get("clientId")
                .and_then(|v| v.as_str())
                .map(|val| val.eq_ignore_ascii_case(label))
                .unwrap_or(false)
            {
                return Ok(Some(Self::value_to_client(&item)?));
            }
        }
        Ok(None)
    }

    fn save_client(&self, app: KeycloakClient) -> Result<KeycloakClient> {
        if let Some(id) = app.remote_id.clone() {
            let url = self
                .base_url
                .join(&format!("admin/realms/{}/clients/{}", self.realm, id))?;
            let payload = self.client_payload(&app);
            self.send_no_content(self.http.put(url).json(&payload))?;
            let mut updated = self
                .fetch_client(&app.client_id)?
                .ok_or_else(|| anyhow!("keycloak client disappeared after update"))?;
            if app.secret.is_some()
                && let Some(secret) = self.rotate_secret(updated.remote_id.as_deref())?
            {
                updated.secret = Some(secret);
            }
            Ok(updated)
        } else {
            let url = self
                .base_url
                .join(&format!("admin/realms/{}/clients", self.realm))?;
            let payload = self.client_payload(&app);
            self.send_no_content(self.http.post(url).json(&payload))?;
            let mut created = self
                .fetch_client(&app.client_id)?
                .ok_or_else(|| anyhow!("keycloak client not found after creation"))?;
            if app.secret.is_some()
                && let Some(secret) = self.rotate_secret(created.remote_id.as_deref())?
            {
                created.secret = Some(secret);
            }
            Ok(created)
        }
    }

    fn rotate_secret(&self, remote_id: Option<&str>) -> Result<Option<KeycloakSecret>> {
        let Some(id) = remote_id else {
            return Ok(None);
        };
        let url = self.base_url.join(&format!(
            "admin/realms/{}/clients/{}/client-secret",
            self.realm, id
        ))?;
        let value: serde_json::Value = self.send_json(self.http.post(url))?;
        Ok(value
            .get("value")
            .and_then(|v| v.as_str())
            .map(|val| KeycloakSecret {
                value: val.to_string(),
                created_at: SystemTime::now(),
            }))
    }

    fn client_payload(&self, app: &KeycloakClient) -> serde_json::Value {
        let redirect_uris: Vec<&str> = app.redirect_uris.iter().map(|s| s.as_str()).collect();
        json!({
            "clientId": app.client_id,
            "name": app.label,
            "protocol": "openid-connect",
            "publicClient": false,
            "standardFlowEnabled": true,
            "serviceAccountsEnabled": false,
            "redirectUris": redirect_uris,
        })
    }

    fn value_to_client(value: &serde_json::Value) -> Result<KeycloakClient> {
        let client_id = value
            .get("clientId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Keycloak client missing clientId"))?
            .to_string();
        let label = value
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&client_id)
            .to_string();
        let redirect_uris = value
            .get("redirectUris")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(String::from))
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        Ok(KeycloakClient {
            label,
            client_id,
            remote_id: value
                .get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            redirect_uris,
            scopes: BTreeSet::new(),
            secret: None,
        })
    }

    fn send_json<T: DeserializeOwned>(&self, builder: RequestBuilder) -> Result<T> {
        let response = builder
            .bearer_auth(self.access_token()?)
            .header("Accept", "application/json")
            .send()
            .context("Keycloak API call failed")?;
        if response.status().is_success() {
            response
                .json::<T>()
                .context("failed to parse Keycloak response")
        } else {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            Err(anyhow!("Keycloak API error {status}: {body}"))
        }
    }

    fn send_no_content(&self, builder: RequestBuilder) -> Result<()> {
        let response = builder
            .bearer_auth(self.access_token()?)
            .header("Content-Type", "application/json")
            .send()
            .context("Keycloak API mutation failed")?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            Err(anyhow!("Keycloak API error {status}: {body}"))
        }
    }

    fn access_token(&self) -> Result<String> {
        {
            let guard = self.token.lock().expect("keycloak token lock poisoned");
            if let Some(token) = guard.as_ref()
                && token.expires_at > Instant::now() + Duration::from_secs(30)
            {
                return Ok(token.value.clone());
            }
        }

        let token_url = self.base_url.join(&format!(
            "realms/{}/protocol/openid-connect/token",
            self.realm
        ))?;
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", self.admin_client_id.as_str()),
            ("client_secret", self.admin_client_secret.as_str()),
        ];
        let response = self
            .http
            .post(token_url)
            .form(&form)
            .send()
            .context("failed to obtain Keycloak token")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!("Keycloak token request failed {status}: {body}");
        }
        let value: serde_json::Value =
            response.json().context("invalid Keycloak token response")?;
        let token = value
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("token response missing access_token"))?
            .to_string();
        let expires_in = value
            .get("expires_in")
            .and_then(|v| v.as_i64())
            .unwrap_or(60 * 5) as u64;
        *self.token.lock().unwrap() = Some(AccessToken {
            value: token.clone(),
            expires_at: Instant::now() + Duration::from_secs(expires_in),
        });
        Ok(token)
    }
}

trait KeycloakConsentHttpClient: Send + Sync {
    fn exchange_code(&self, url: &str, form: &[(String, String)]) -> Result<serde_json::Value>;
}

#[derive(Default)]
struct ReqwestKeycloakConsentHttpClient;

impl KeycloakConsentHttpClient for ReqwestKeycloakConsentHttpClient {
    fn exchange_code(&self, url: &str, form: &[(String, String)]) -> Result<serde_json::Value> {
        let owned_form: Vec<(String, String)> = form.to_vec();
        let response = HttpClient::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("failed to build Keycloak consent HTTP client")?
            .post(url)
            .form(&owned_form)
            .send()
            .context("Keycloak token request failed")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!("Keycloak token request failed {status}: {body}");
        }
        response
            .json::<serde_json::Value>()
            .context("invalid Keycloak token response")
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
            display_name: "Greentic Keycloak".into(),
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

    impl KeycloakConsentHttpClient for StubConsentHttp {
        fn exchange_code(&self, url: &str, form: &[(String, String)]) -> Result<serde_json::Value> {
            assert!(
                url.ends_with("/protocol/openid-connect/token"),
                "expected keycloak token endpoint, got {url}"
            );
            *self.last_request.lock().unwrap() = Some((url.to_string(), form.to_vec()));
            Ok(json!({ "refresh_token": self.refresh_token }))
        }
    }

    #[test]
    fn ensures_global_app() {
        let directory: Arc<dyn KeycloakDirectory> = Arc::new(MockKeycloakDirectory::default());
        let provisioner = KeycloakProvisioner::with_directory(directory);
        let store = MemoryStore::default();
        let ctx = ProvisionContext::new("global", &store);
        let report = provisioner
            .ensure_application(ctx, &desired_app())
            .expect("ensure");
        assert!(
            report
                .credentials
                .iter()
                .any(|path| path.contains("messaging/global/keycloak/client_id"))
        );
    }

    #[test]
    fn stores_tenant_credentials() {
        let directory: Arc<dyn KeycloakDirectory> = Arc::new(MockKeycloakDirectory::default());
        let provisioner = KeycloakProvisioner::with_directory(directory);
        let store = MemoryStore::default();
        let mut extras = BTreeMap::new();
        extras.insert("client_id".into(), "CLIENT".into());
        extras.insert("client_secret".into(), "SECRET".into());
        extras.insert("issuer".into(), "https://kc.example.com/realms/acme".into());
        let mut desired = desired_app();
        desired.extra_params = Some(extras);
        let ctx = ProvisionContext::new("tenant-a", &store);
        let report = provisioner
            .ensure_application(ctx, &desired)
            .expect("ensure");
        assert!(
            report
                .credentials
                .iter()
                .any(|path| path.contains("tenant-a/keycloak/client_secret"))
        );
    }

    #[tokio::test]
    async fn admin_consent_flow_persists_refresh_token() {
        let secrets = MemoryStore::default();
        let issuer = "https://kc.example.com/realms/demo".to_string();
        let tenant = "kc-tenant";
        for (key, value) in [
            ("issuer", issuer.as_str()),
            ("client_id", "kc-client"),
            ("client_secret", "kc-secret"),
        ] {
            let path = messaging_tenant_path(tenant, PROVIDER_KEY, key);
            write_string_secret_at(&secrets, &path, value).unwrap();
        }

        let consent_http = Arc::new(StubConsentHttp::new("rt-keycloak"));
        let provisioner = KeycloakProvisioner::with_directory_and_http(
            Arc::new(MockKeycloakDirectory::default()),
            consent_http.clone(),
        );
        let consent_store = AdminConsentStore::new(Duration::from_secs(300));
        let start_ctx = AdminActionContext::new(&secrets, &consent_store);
        let start_url = provisioner
            .authorize_admin_start(start_ctx, tenant)
            .expect("start")
            .expect("url");
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
            Some("rt-keycloak")
        );
    }
}
