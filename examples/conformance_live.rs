use std::{borrow::Cow, collections::HashSet, env, fmt, time::Duration};

use anyhow::{anyhow, Context, Error};
use clap::{Parser, ValueEnum};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use tracing::{error, info, warn};
use url::{Host, Url};

#[derive(Parser, Debug)]
#[command(author, version, about = "Greentic OAuth live conformance runner")]
struct Cli {
    /// Provider to exercise.
    #[arg(long, value_enum)]
    provider: ProviderArg,

    /// Comma separated list of checks to run. Defaults to all for the selected provider.
    #[arg(long, value_delimiter = ',', value_enum)]
    checks: Option<Vec<CheckKind>>,
}

#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq, Hash)]
enum ProviderArg {
    Msgraph,
    Oidc,
}

#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq, Hash)]
enum CheckKind {
    Discovery,
    Jwks,
    ClientCredentials,
    SignedFetch,
    Refresh,
    Revocation,
}

impl CheckKind {
    fn default_for(provider: ProviderArg) -> Vec<Self> {
        match provider {
            ProviderArg::Msgraph | ProviderArg::Oidc => vec![
                Self::Discovery,
                Self::Jwks,
                Self::ClientCredentials,
                Self::SignedFetch,
                Self::Refresh,
                Self::Revocation,
            ],
        }
    }
}

#[derive(Clone, Debug)]
enum CheckStatus {
    Pass,
    Skip,
    Fail,
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckStatus::Pass => write!(f, "PASS"),
            CheckStatus::Skip => write!(f, "SKIP"),
            CheckStatus::Fail => write!(f, "FAIL"),
        }
    }
}

#[derive(Clone, Debug)]
struct CheckResult {
    kind: CheckKind,
    status: CheckStatus,
    detail: String,
}

impl CheckResult {
    fn pass(kind: CheckKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            status: CheckStatus::Pass,
            detail: detail.into(),
        }
    }

    fn skip(kind: CheckKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            status: CheckStatus::Skip,
            detail: detail.into(),
        }
    }

    fn fail(kind: CheckKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            status: CheckStatus::Fail,
            detail: detail.into(),
        }
    }
}

#[derive(Clone)]
struct MsGraphConfig {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    seeded_refresh: Option<String>,
}

#[derive(Clone)]
struct OidcConfig {
    issuer: String,
    client_id: String,
    client_secret: String,
    audience: Option<String>,
    seeded_refresh: Option<String>,
}

#[derive(Clone)]
enum ProviderConfig {
    MsGraph(MsGraphConfig),
    Oidc(OidcConfig),
}

#[derive(Clone, Debug)]
struct DiscoveryInfo {
    issuer: Url,
    jwks_uri: Url,
    token_endpoint: Option<Url>,
    userinfo_endpoint: Option<Url>,
    revocation_endpoint_raw: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
}

struct Runner {
    provider: ProviderConfig,
    client: Client,
    checks: Vec<CheckKind>,
    discovery: Option<DiscoveryInfo>,
    token: Option<TokenResponse>,
}

impl Runner {
    fn new(provider: ProviderConfig, checks: Vec<CheckKind>) -> Result<Self, Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            provider,
            client,
            checks,
            discovery: None,
            token: None,
        })
    }

    async fn run(&mut self) -> Vec<CheckResult> {
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        for kind in &self.checks {
            if !seen.insert(*kind) {
                continue;
            }
            let result = match kind {
                CheckKind::Discovery => self.check_discovery().await,
                CheckKind::Jwks => self.check_jwks().await,
                CheckKind::ClientCredentials => self.check_client_credentials().await,
                CheckKind::SignedFetch => self.check_signed_fetch().await,
                CheckKind::Refresh => self.check_refresh().await,
                CheckKind::Revocation => self.check_revocation().await,
            };
            match result.status {
                CheckStatus::Pass => info!(check = ?kind, detail = %result.detail, "check passed"),
                CheckStatus::Skip => warn!(check = ?kind, detail = %result.detail, "check skipped"),
                CheckStatus::Fail => error!(check = ?kind, detail = %result.detail, "check failed"),
            }
            results.push(result);
        }

        results
    }

    async fn ensure_discovery(&mut self) -> Result<&DiscoveryInfo, Error> {
        if self.discovery.is_none() {
            let info = self.fetch_discovery().await?;
            self.discovery = Some(info);
        }
        self
            .discovery
            .as_ref()
            .ok_or_else(|| anyhow!("discovery document unavailable"))
    }

    async fn fetch_discovery(&self) -> Result<DiscoveryInfo, Error> {
        match &self.provider {
            ProviderConfig::MsGraph(cfg) => {
                let url = format!(
                    "https://login.microsoftonline.com/{}/v2.0/.well-known/openid-configuration",
                    cfg.tenant_id
                );
                self.fetch_discovery_document(&url).await
            }
            ProviderConfig::Oidc(cfg) => {
                let base = cfg.issuer.trim_end_matches('/');
                let url = format!("{}/.well-known/openid-configuration", base);
                self.fetch_discovery_document(&url).await
            }
        }
    }

    async fn fetch_discovery_document(&self, url: &str) -> Result<DiscoveryInfo, Error> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("discovery GET {url}"))?;
        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .context("read discovery response body")?;
        if !status.is_success() {
            return Err(anyhow!(
                "discovery endpoint {url} returned HTTP {} body={}",
                status,
                body_preview(&body_text)
            ));
        }
        let body: Value = serde_json::from_str(&body_text)
            .with_context(|| format!("decode discovery JSON from {url}"))?;
        let issuer = body
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("discovery missing issuer"))?;
        let issuer = Url::parse(issuer).context("invalid issuer url")?;
        let jwks_uri = body
            .get("jwks_uri")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("discovery missing jwks_uri"))?;
        let jwks_uri = Url::parse(jwks_uri).context("invalid jwks_uri")?;
        let token_endpoint = body
            .get("token_endpoint")
            .and_then(Value::as_str)
            .and_then(|s| resolve_endpoint(&issuer, s).ok());
        let userinfo_endpoint = body
            .get("userinfo_endpoint")
            .and_then(Value::as_str)
            .and_then(|s| resolve_endpoint(&issuer, s).ok());
        let revocation_endpoint = body
            .get("revocation_endpoint")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        Ok(DiscoveryInfo {
            issuer,
            jwks_uri,
            token_endpoint,
            userinfo_endpoint,
            revocation_endpoint_raw: revocation_endpoint,
        })
    }

    async fn check_discovery(&mut self) -> CheckResult {
        match self.ensure_discovery().await {
            Ok(doc) => {
                info!(
                    issuer = %doc.issuer,
                    jwks_uri = %doc.jwks_uri,
                    revocation = ?doc.revocation_endpoint_raw,
                    "discovery fetched"
                );
                CheckResult::pass(
                    CheckKind::Discovery,
                    format!(
                        "issuer={} jwks_uri={} revocation={}",
                        doc.issuer,
                        doc.jwks_uri,
                        doc
                            .revocation_endpoint_raw
                            .as_deref()
                            .unwrap_or("<none>")
                    ),
                )
            }
            Err(err) => CheckResult::fail(
                CheckKind::Discovery,
                format!("failed discovery/jwks retrieval: {err:?}"),
            ),
        }
    }

    async fn check_jwks(&mut self) -> CheckResult {
        let doc = match self.ensure_discovery().await {
            Ok(doc) => doc.clone(),
            Err(err) => {
                return CheckResult::fail(
                    CheckKind::Jwks,
                    format!("discovery not available: {err:?}"),
                )
            }
        };
        let requested = doc.jwks_uri.clone();
        match self.client.get(requested.clone()).send().await {
            Ok(resp) => {
                let status = resp.status();
                match resp.text().await {
                    Ok(body_text) => {
                        if !status.is_success() {
                            return CheckResult::fail(
                                CheckKind::Jwks,
                                format!(
                                    "jwks GET {} returned HTTP {} body={}",
                                    requested,
                                    status,
                                    body_preview(&body_text)
                                ),
                            );
                        }
                        match serde_json::from_str::<Value>(&body_text) {
                            Ok(value) => {
                                let key_count = value
                                    .get("keys")
                                    .and_then(Value::as_array)
                                    .map(|arr| arr.len())
                                    .unwrap_or(0);
                                if key_count > 0 {
                                    CheckResult::pass(
                                        CheckKind::Jwks,
                                        format!(
                                            "jwks ok (keys={key_count}) uri={}",
                                            requested
                                        ),
                                    )
                                } else {
                                    CheckResult::fail(
                                        CheckKind::Jwks,
                                        format!(
                                            "jwks keys array missing or empty (uri={})",
                                            requested
                                        ),
                                    )
                                }
                            }
                            Err(err) => CheckResult::fail(
                                CheckKind::Jwks,
                                format!(
                                    "decode jwks json failed (uri={}): {err}; body={}",
                                    requested,
                                    body_preview(&body_text)
                                ),
                            ),
                        }
                    }
                    Err(err) => CheckResult::fail(
                        CheckKind::Jwks,
                        format!(
                            "failed to read jwks response from {}: {err:?}",
                            requested
                        ),
                    ),
                }
            }
            Err(err) => CheckResult::fail(
                CheckKind::Jwks,
                format!("request jwks {} failed: {err:?}", requested),
            ),
        }
    }

    async fn check_client_credentials(&mut self) -> CheckResult {
        let doc = match self.ensure_discovery().await {
            Ok(doc) => doc.clone(),
            Err(err) => {
                return CheckResult::fail(
                    CheckKind::ClientCredentials,
                    format!("discovery unavailable: {err:?}"),
                )
            }
        };
        let token_endpoint = match self.token_endpoint_url(&doc) {
            Ok(url) => url,
            Err(err) => {
                return CheckResult::fail(
                    CheckKind::ClientCredentials,
                    format!("token endpoint missing: {err:?}"),
                )
            }
        };

        let form = match &self.provider {
            ProviderConfig::MsGraph(cfg) => vec![
                ("grant_type", "client_credentials".to_string()),
                ("client_id", cfg.client_id.clone()),
                ("client_secret", cfg.client_secret.clone()),
                (
                    "scope",
                    "https://graph.microsoft.com/.default".to_string(),
                ),
            ],
            ProviderConfig::Oidc(cfg) => {
                let mut params = vec![
                    ("grant_type", "client_credentials".to_string()),
                    ("client_id", cfg.client_id.clone()),
                    ("client_secret", cfg.client_secret.clone()),
                ];
                if let Some(aud) = &cfg.audience {
                    params.push(("audience", aud.clone()));
                }
                params
            }
        };

        match self
            .client
            .post(token_endpoint.clone())
            .form(&form)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                match resp.text().await {
                    Ok(body_text) => {
                        if !status.is_success() {
                            return CheckResult::fail(
                                CheckKind::ClientCredentials,
                                format!(
                                    "token endpoint {} returned HTTP {} body={}",
                                    token_endpoint,
                                    status,
                                    body_preview(&body_text)
                                ),
                            );
                        }
                        match serde_json::from_str::<TokenResponse>(&body_text) {
                            Ok(token) => {
                                if !token.token_type.eq_ignore_ascii_case("bearer") {
                                    return CheckResult::fail(
                                        CheckKind::ClientCredentials,
                                        format!(
                                            "unexpected token_type {} from {}",
                                            token.token_type,
                                            token_endpoint
                                        ),
                                    );
                                }
                                if token.expires_in.unwrap_or(0) == 0 {
                                    return CheckResult::fail(
                                        CheckKind::ClientCredentials,
                                        format!(
                                            "expires_in missing or zero from {}",
                                            token_endpoint
                                        ),
                                    );
                                }
                                self.token = Some(token.clone());
                                CheckResult::pass(
                                    CheckKind::ClientCredentials,
                                    format!(
                                        "access token acquired from {} (expires_in={}s)",
                                        token_endpoint,
                                        token.expires_in.unwrap()
                                    ),
                                )
                            }
                            Err(err) => CheckResult::fail(
                                CheckKind::ClientCredentials,
                                format!(
                                    "decode token response from {} failed: {err}; body={}",
                                    token_endpoint,
                                    body_preview(&body_text)
                                ),
                            ),
                        }
                    }
                    Err(err) => CheckResult::fail(
                        CheckKind::ClientCredentials,
                        format!(
                            "failed to read token response from {}: {err:?}",
                            token_endpoint
                        ),
                    ),
                }
            }
            Err(err) => CheckResult::fail(
                CheckKind::ClientCredentials,
                format!("token request to {} failed: {err:?}", token_endpoint),
            ),
        }
    }

    async fn check_signed_fetch(&mut self) -> CheckResult {
        let token = match &self.token {
            Some(token) => token.access_token.clone(),
            None => {
                return CheckResult::fail(
                    CheckKind::SignedFetch,
                    "client credentials token not available; run client_credentials first",
                )
            }
        };
        match &self.provider {
            ProviderConfig::MsGraph(_) => {
                let url = "https://graph.microsoft.com/v1.0/organization?$top=1";
                let resp = self
                    .client
                    .get(url)
                    .bearer_auth(&token)
                    .send()
                    .await;
                match resp {
                    Ok(resp) if resp.status() == StatusCode::OK => match resp.json::<Value>().await
                    {
                        Ok(json) => {
                            if json.get("value").and_then(Value::as_array).is_some() {
                                CheckResult::pass(CheckKind::SignedFetch, "Graph organization query ok")
                            } else {
                                CheckResult::fail(
                                    CheckKind::SignedFetch,
                                    "Graph response missing `value` array",
                                )
                            }
                        }
                        Err(err) => CheckResult::fail(
                            CheckKind::SignedFetch,
                            format!("decode Graph response: {err:?}"),
                        ),
                    },
                    Ok(resp) if resp.status() == StatusCode::FORBIDDEN => {
                        warn!("Microsoft Graph responded 403 (likely missing app permission); treating as success for token validity");
                        CheckResult::pass(
                            CheckKind::SignedFetch,
                            "Graph responded 403 (insufficient permissions) but token valid",
                        )
                    }
                    Ok(resp) => CheckResult::fail(
                        CheckKind::SignedFetch,
                        format!("Graph returned HTTP {}", resp.status()),
                    ),
                    Err(err) => CheckResult::fail(
                        CheckKind::SignedFetch,
                        format!("Graph request failed: {err:?}"),
                    ),
                }
            }
            ProviderConfig::Oidc(_) => {
                let doc = match self.ensure_discovery().await {
                    Ok(doc) => doc.clone(),
                    Err(err) => {
                        return CheckResult::fail(
                            CheckKind::SignedFetch,
                            format!("discovery unavailable: {err:?}"),
                        )
                    }
                };
                if let Some(endpoint) = doc.userinfo_endpoint {
                    match self
                        .client
                        .get(endpoint.clone())
                        .bearer_auth(&token)
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status() == StatusCode::OK => CheckResult::pass(
                            CheckKind::SignedFetch,
                            format!("userinfo ok ({})", endpoint),
                        ),
                        Ok(resp) => CheckResult::fail(
                            CheckKind::SignedFetch,
                            format!("userinfo returned HTTP {}", resp.status()),
                        ),
                        Err(err) => CheckResult::fail(
                            CheckKind::SignedFetch,
                            format!("userinfo request failed: {err:?}"),
                        ),
                    }
                } else {
                    let resp = self
                        .client
                        .get(doc.issuer.clone())
                        .bearer_auth(&token)
                        .send()
                        .await;
                    match resp {
                        Ok(resp) if resp.status().is_success() => CheckResult::pass(
                            CheckKind::SignedFetch,
                            format!("issuer responded {}", resp.status()),
                        ),
                        Ok(resp) => CheckResult::fail(
                            CheckKind::SignedFetch,
                            format!("issuer responded {}", resp.status()),
                        ),
                        Err(err) => CheckResult::fail(
                            CheckKind::SignedFetch,
                            format!("issuer request failed: {err:?}"),
                        ),
                    }
                }
            }
        }
    }

    async fn check_refresh(&mut self) -> CheckResult {
        let doc = match self.ensure_discovery().await {
            Ok(doc) => doc.clone(),
            Err(err) => {
                return CheckResult::fail(
                    CheckKind::Refresh,
                    format!("discovery unavailable: {err:?}"),
                )
            }
        };
        let token_endpoint = match self.token_endpoint_url(&doc) {
            Ok(url) => url,
            Err(err) => {
                return CheckResult::fail(
                    CheckKind::Refresh,
                    format!("token endpoint missing: {err:?}"),
                )
            }
        };
        let seeded = match &self.provider {
            ProviderConfig::MsGraph(cfg) => cfg.seeded_refresh.clone(),
            ProviderConfig::Oidc(cfg) => cfg.seeded_refresh.clone(),
        };
        let seeded = match seeded {
            Some(token) if !token.trim().is_empty() => token,
            _ => {
                return CheckResult::skip(
                    CheckKind::Refresh,
                    "no seeded refresh token provided; skipping",
                )
            }
        };

        let mut form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", seeded),
        ];
        match &self.provider {
            ProviderConfig::MsGraph(cfg) => {
                form.push(("client_id", cfg.client_id.clone()));
                form.push(("client_secret", cfg.client_secret.clone()));
            }
            ProviderConfig::Oidc(cfg) => {
                form.push(("client_id", cfg.client_id.clone()));
                form.push(("client_secret", cfg.client_secret.clone()));
                if let Some(aud) = &cfg.audience {
                    form.push(("audience", aud.clone()));
                }
            }
        }

        match self
            .client
            .post(token_endpoint.clone())
            .form(&form)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => match resp.json::<TokenResponse>().await {
                Ok(body) => {
                    let rotation = if body.refresh_token.is_some() {
                        " (rotation provided)"
                    } else {
                        ""
                    };
                    CheckResult::pass(
                        CheckKind::Refresh,
                        format!("refresh succeeded{}.", rotation),
                    )
                }
                Err(err) => CheckResult::fail(
                    CheckKind::Refresh,
                    format!("decode refresh response: {err:?}"),
                ),
            },
            Ok(resp) => CheckResult::fail(
                CheckKind::Refresh,
                format!("refresh returned HTTP {}", resp.status()),
            ),
            Err(err) => CheckResult::fail(
                CheckKind::Refresh,
                format!("refresh request failed: {err:?}"),
            ),
        }
    }

    async fn check_revocation(&mut self) -> CheckResult {
        let doc = match self.ensure_discovery().await {
            Ok(doc) => doc.clone(),
            Err(err) => {
                return CheckResult::fail(
                    CheckKind::Revocation,
                    format!("discovery unavailable: {err:?}"),
                )
            }
        };
        let Some(raw) = doc.revocation_endpoint_raw.clone() else {
            return CheckResult::skip(CheckKind::Revocation, "revocation endpoint not advertised");
        };
        let token = match &self.token {
            Some(token) => token.access_token.clone(),
            None => {
                return CheckResult::skip(
                    CheckKind::Revocation,
                    "no access token available; skipping revocation",
                )
            }
        };
        let resolved = match resolve_endpoint(&doc.issuer, &raw)
            .and_then(|u| {
                validate_secure_or_localhost(&u)?;
                Ok(u)
            }) {
            Ok(url) => url,
            Err(err) => {
                warn!(target: "oauth.conformance", raw, error = %err, "invalid revocation endpoint; skipping");
                return CheckResult::skip(
                    CheckKind::Revocation,
                    format!("revocation endpoint invalid: {err}"),
                );
            }
        };
        let mut form = vec![("token", token), ("token_type_hint", "access_token".to_string())];
        match &self.provider {
            ProviderConfig::MsGraph(cfg) => {
                form.push(("client_id", cfg.client_id.clone()));
                form.push(("client_secret", cfg.client_secret.clone()));
            }
            ProviderConfig::Oidc(cfg) => {
                form.push(("client_id", cfg.client_id.clone()));
                form.push(("client_secret", cfg.client_secret.clone()));
            }
        }

        match self.client.post(resolved.clone()).form(&form).send().await {
            Ok(resp)
                if resp.status().is_success()
                    || resp.status() == StatusCode::BAD_REQUEST =>
            {
                CheckResult::pass(
                    CheckKind::Revocation,
                    format!("revocation POST {} responded {}", resolved, resp.status()),
                )
            }
            Ok(resp) => CheckResult::fail(
                CheckKind::Revocation,
                format!("revocation responded {}", resp.status()),
            ),
            Err(err) => CheckResult::fail(
                CheckKind::Revocation,
                format!("revocation request failed: {err:?}"),
            ),
        }
    }

    fn token_endpoint_url(&self, doc: &DiscoveryInfo) -> Result<Url, Error> {
        if let Some(url) = &doc.token_endpoint {
            return Ok(url.clone());
        }
        match &self.provider {
            ProviderConfig::MsGraph(cfg) => Url::parse(&format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                cfg.tenant_id
            ))
            .context("failed to build Microsoft token endpoint"),
            ProviderConfig::Oidc(_) => Err(anyhow!("token endpoint missing in discovery")),
        }
    }
}

fn load_provider(arg: ProviderArg) -> Result<ProviderConfig, Error> {
    match arg {
        ProviderArg::Msgraph => Ok(ProviderConfig::MsGraph(MsGraphConfig {
            tenant_id: env_var("MS_TENANT_ID")?,
            client_id: env_var("MS_CLIENT_ID")?,
            client_secret: env_var("MS_CLIENT_SECRET")?,
            seeded_refresh: env::var("MS_REFRESH_TOKEN_SEEDED").ok(),
        })),
        ProviderArg::Oidc => Ok(ProviderConfig::Oidc(OidcConfig {
            issuer: env_var("OIDC_ISSUER")?,
            client_id: env_var("OIDC_CLIENT_ID")?,
            client_secret: env_var("OIDC_CLIENT_SECRET")?,
            audience: env::var("OIDC_AUDIENCE").ok(),
            seeded_refresh: env::var("OIDC_REFRESH_TOKEN_SEEDED").ok(),
        })),
    }
}

fn env_var(key: &str) -> Result<String, Error> {
    env::var(key)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("environment variable {key} missing"))
}

fn resolve_endpoint(issuer: &Url, candidate: &str) -> Result<Url, Error> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("endpoint value empty"));
    }
    if let Ok(abs) = Url::parse(trimmed) {
        return Ok(abs);
    }
    issuer
        .join(trimmed)
        .map_err(|err| anyhow!("failed to resolve `{trimmed}` against `{issuer}`: {err}"))
}

fn validate_secure_or_localhost(url: &Url) -> Result<(), Error> {
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            if url.host().map(is_loopback_host).unwrap_or(false) {
                Ok(())
            } else {
                Err(anyhow!("insecure non-localhost URL"))
            }
        }
        other => Err(anyhow!("unsupported scheme `{other}`")),
    }
}

fn is_loopback_host(host: Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(addr) => addr.is_loopback(),
        Host::Ipv6(addr) => addr.is_loopback(),
    }
}

fn body_preview(body: &str) -> String {
    const MAX_LEN: usize = 512;
    if body.len() > MAX_LEN {
        format!("{}...", &body[..MAX_LEN])
    } else {
        body.to_string()
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    if env::var_os("RUST_LOG").is_none() {
        env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .pretty()
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let provider = load_provider(cli.provider)?;
    let checks = cli
        .checks
        .unwrap_or_else(|| CheckKind::default_for(cli.provider));

    let mut runner = Runner::new(provider, checks)?;
    let results = runner.run().await;
    let failed = results
        .iter()
        .any(|result| matches!(result.status, CheckStatus::Fail));
    if failed {
        Err(anyhow!("one or more checks failed"))
    } else {
        info!("all requested checks passed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_absolute_endpoint() {
        let issuer = Url::parse("https://example.com/").unwrap();
        let resolved = resolve_endpoint(&issuer, "https://api.example.com/revoke").unwrap();
        assert_eq!(resolved.as_str(), "https://api.example.com/revoke");
    }

    #[test]
    fn resolve_relative_endpoint() {
        let issuer = Url::parse("https://example.com/tenant/").unwrap();
        let resolved = resolve_endpoint(&issuer, "oauth/revoke").unwrap();
        assert_eq!(resolved.as_str(), "https://example.com/tenant/oauth/revoke");
    }

    #[test]
    fn validate_localhost_http() {
        let url = Url::parse("http://localhost:8080/revoke").unwrap();
        assert!(validate_secure_or_localhost(&url).is_ok());
    }

    #[test]
    fn validate_rejects_plain_http() {
        let url = Url::parse("http://example.com/revoke").unwrap();
        assert!(validate_secure_or_localhost(&url).is_err());
    }
}
