use std::{collections::BTreeMap, time::Duration};

use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::ClientError;

/// High-level HTTP client for the Greentic OAuth broker.
#[derive(Clone)]
pub struct Client {
    http: HttpClient,
    base_url: Url,
}

/// Builder for [`Client`].
pub struct ClientBuilder {
    base_url: Option<Url>,
    timeout: Duration,
}

impl ClientBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            base_url: None,
            timeout: Duration::from_secs(30),
        }
    }

    /// Set the broker base URL (e.g. `https://broker.example.com/`).
    pub fn base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, ClientError> {
        let parsed = Url::parse(base_url.as_ref())
            .map_err(|err| ClientError::InvalidBaseUrl(format!("{} ({err})", base_url.as_ref())))?;
        self.base_url = Some(parsed);
        Ok(self)
    }

    /// Override the HTTP client timeout (defaults to 30 seconds).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Finalise the builder and create a [`Client`].
    pub fn build(self) -> Result<Client, ClientError> {
        let base_url = self.base_url.ok_or(ClientError::MissingBaseUrl)?;
        let http = HttpClient::builder().timeout(self.timeout).build()?;
        Ok(Client { http, base_url })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Begin building a new client.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Call `/oauth/start` to create a new authorization session.
    pub async fn start(&self, request: StartRequest) -> Result<StartResponse, ClientError> {
        let url = self.base_url.join("oauth/start")?;
        let payload = ApiStartRequest::from(&request);
        let response = self.http.post(url).json(&payload).send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let message = extract_error_message(&body);
            return Err(ClientError::status(status, message));
        }

        let body: ApiStartResponse = response.json().await?;
        Ok(StartResponse {
            start_url: body.start_url,
        })
    }
}

fn extract_error_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("error").cloned())
        .and_then(|value| {
            if value.is_string() {
                value.as_str().map(|s| s.to_string())
            } else {
                Some(value.to_string())
            }
        })
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| body.to_string())
}

#[derive(Clone, Debug)]
pub struct StartRequest {
    pub env: String,
    pub tenant: String,
    pub provider: String,
    pub team: Option<String>,
    pub owner_kind: OwnerKind,
    pub owner_id: String,
    pub flow_id: String,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
    pub visibility: Option<Visibility>,
    pub extra_params: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Serialize)]
struct ApiStartRequest<'a> {
    env: &'a str,
    tenant: &'a str,
    provider: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    team: Option<&'a str>,
    owner_kind: &'a str,
    owner_id: &'a str,
    flow_id: &'a str,
    #[serde(skip_serializing_if = "slice_is_empty")]
    scopes: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    visibility: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra_params: Option<&'a BTreeMap<String, String>>,
}

impl<'a> From<&'a StartRequest> for ApiStartRequest<'a> {
    fn from(request: &'a StartRequest) -> Self {
        Self {
            env: &request.env,
            tenant: &request.tenant,
            provider: &request.provider,
            team: request.team.as_deref(),
            owner_kind: request.owner_kind.as_str(),
            owner_id: &request.owner_id,
            flow_id: &request.flow_id,
            scopes: &request.scopes,
            redirect_uri: request.redirect_uri.as_deref(),
            visibility: request.visibility.as_ref().map(Visibility::as_str),
            extra_params: request.extra_params.as_ref(),
        }
    }
}

fn slice_is_empty<T>(value: &&[T]) -> bool {
    value.is_empty()
}

#[derive(Clone, Debug, Deserialize)]
struct ApiStartResponse {
    start_url: String,
}

/// Response returned by [`Client::start`].
#[derive(Clone, Debug)]
pub struct StartResponse {
    pub start_url: String,
}

/// Owner classification for the OAuth flow.
#[derive(Clone, Debug)]
pub enum OwnerKind {
    User,
    Service,
}

impl OwnerKind {
    fn as_str(&self) -> &'static str {
        match self {
            OwnerKind::User => "user",
            OwnerKind::Service => "service",
        }
    }
}

/// Visibility requested for the resulting token.
#[derive(Clone, Debug)]
pub enum Visibility {
    Private,
    Team,
    Tenant,
}

impl Visibility {
    fn as_str(&self) -> &'static str {
        match self {
            Visibility::Private => "private",
            Visibility::Team => "team",
            Visibility::Tenant => "tenant",
        }
    }
}
