use std::{fmt, time::Duration};

use async_nats::Client as NatsClient;
use futures_util::StreamExt;
use oauth_core::TokenHandleClaims;
use reqwest::{Client as HttpClient, Method, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::time;
use url::Url;
use base64::Engine;

use crate::error::SdkError;

/// Configuration parameters for establishing a broker client.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub http_base_url: String,
    pub nats_url: String,
    pub env: String,
    pub tenant: String,
    pub provider: String,
    pub team: Option<String>,
}

impl ClientConfig {
    pub fn http_base_url(mut self, url: impl Into<String>) -> Self {
        self.http_base_url = url.into();
        self
    }
}

/// High-level client for interacting with the OAuth broker.
#[derive(Clone)]
pub struct Client {
    http: HttpClient,
    http_base: Url,
    nats: NatsClient,
    env: String,
    tenant: String,
    provider: String,
    team: Option<String>,
}

impl Client {
    /// Establish a new client using the supplied configuration.
    pub async fn connect(config: ClientConfig) -> Result<Self, SdkError> {
        let http_base = Url::parse(&config.http_base_url)?;
        let http = HttpClient::builder().build()?;
        let nats = async_nats::connect(config.nats_url).await?;
        Ok(Self {
            http,
            http_base,
            nats,
            env: config.env,
            tenant: config.tenant,
            provider: config.provider,
            team: config.team,
        })
    }

    /// Initiate an OAuth flow via NATS and receive the redirect URL and state token.
    pub async fn initiate_auth(
        &self,
        request: InitiateAuthRequest,
    ) -> Result<InitiateAuthResponse, SdkError> {
        let subject = self.request_subject(&request.flow_id);
        let payload = InitiateAuthPayload {
            owner_kind: request.owner_kind.as_str(),
            owner_id: &request.owner_id,
            scopes: if request.scopes.is_empty() {
                None
            } else {
                Some(&request.scopes)
            },
            visibility: request.visibility.map(|v| v.to_string()),
            redirect_uri: request.redirect_uri.as_deref(),
        };
        let data = serde_json::to_vec(&payload)?;
        let message = self.nats.request(subject, data.into()).await?;
        let response: InitiateAuthEnvelope = serde_json::from_slice(&message.payload)?;
        Ok(InitiateAuthResponse {
            flow_id: response.flow_id,
            redirect_url: response.redirect_url,
            state: response.state,
        })
    }

    /// Await the completion event for a previously initiated flow.
    pub async fn await_result(
        &self,
        flow_id: &str,
        timeout: Option<Duration>,
    ) -> Result<FlowResult, SdkError> {
        let subject = self.result_subject(flow_id);
        let mut subscription = self.nats.subscribe(subject.clone()).await?;

        let message = if let Some(duration) = timeout {
            time::timeout(duration, subscription.next()).await??
        } else {
            subscription.next().await
        }
        .ok_or_else(|| SdkError::InvalidResponse("subscription closed".into()))?;

        let event: BrokerEvent = serde_json::from_slice(&message.payload)?;
        Ok(FlowResult {
            flow_id: event.flow_id,
            env: event.env,
            tenant: event.tenant,
            team: event.team,
            provider: event.provider,
            token_handle_claims: event.token_handle,
            storage_path: event.storage_path,
        })
    }

    /// Retrieve an access token for the supplied token handle via the broker HTTP endpoint.
    pub async fn get_access_token(
        &self,
        token_handle: &str,
        force_refresh: bool,
    ) -> Result<AccessToken, SdkError> {
        let url = self.http_base.join("token")?;
        let response = self
            .http
            .post(url)
            .json(&HttpAccessTokenRequest {
                token_handle,
                force_refresh,
            })
            .send()
            .await?;

        Self::ensure_success(response.status()).await?;
        let body: HttpAccessTokenResponse = response.json().await?;
        Ok(AccessToken {
            access_token: body.access_token,
            expires_at: body.expires_at,
        })
    }

    /// Perform a signed fetch through the broker using the provided token handle.
    pub async fn signed_fetch(
        &self,
        request: SignedFetchRequest,
    ) -> Result<SignedFetchResponse, SdkError> {
        let url = self.http_base.join("signed-fetch")?;
        let encoded_body = request
            .body
            .as_ref()
            .map(|body| base64::engine::general_purpose::STANDARD.encode(body));
        let headers: Vec<_> = request
            .headers
            .iter()
            .map(|(name, value)| HttpHeader {
                name: name.as_str(),
                value: value.as_str(),
            })
            .collect();
        let payload = HttpSignedFetchRequest {
            token_handle: request.token_handle.as_str(),
            method: request.method.as_str(),
            url: request.url.as_str(),
            headers: &headers,
            body: encoded_body.as_deref(),
            body_encoding: "base64",
        };

        let response = self.http.post(url).json(&payload).send().await?;
        Self::ensure_success(response.status()).await?;
        let body: HttpSignedFetchResponse = response.json().await?;

        if body.body_encoding != "base64" {
            return Err(SdkError::InvalidResponse(format!(
                "unexpected body encoding `{}`",
                body.body_encoding
            )));
        }

        let decoded_body = base64::engine::general_purpose::STANDARD
            .decode(body.body.as_bytes())
            .map_err(|err| SdkError::InvalidResponse(format!("invalid base64 body: {err}")))?;

        Ok(SignedFetchResponse {
            status: body.status,
            headers: body
                .headers
                .into_iter()
                .map(|header| (header.name, header.value))
                .collect(),
            body: decoded_body,
        })
    }

    fn request_subject(&self, flow_id: &str) -> String {
        let team_segment = self.team.as_deref().unwrap_or("_");
        format!(
            "oauth.req.{}.{}.{}.{}.{}",
            self.tenant, self.env, team_segment, self.provider, flow_id
        )
    }

    fn result_subject(&self, flow_id: &str) -> String {
        let team_segment = self.team.as_deref().unwrap_or("_");
        format!(
            "oauth.res.{}.{}.{}.{}.{}",
            self.tenant, self.env, team_segment, self.provider, flow_id
        )
    }

    async fn ensure_success(status: StatusCode) -> Result<(), SdkError> {
        if status.is_success() {
            Ok(())
        } else {
            Err(SdkError::InvalidResponse(format!(
                "http status {status}"
            )))
        }
    }
}

/// Request parameters for initiating an OAuth flow.
#[derive(Clone, Debug)]
pub struct InitiateAuthRequest {
    pub owner_kind: OwnerKind,
    pub owner_id: String,
    pub flow_id: String,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
    pub visibility: Option<Visibility>,
}

impl InitiateAuthRequest {
    pub fn new(owner_kind: OwnerKind, owner_id: impl Into<String>, flow_id: impl Into<String>) -> Self {
        Self {
            owner_kind,
            owner_id: owner_id.into(),
            flow_id: flow_id.into(),
            scopes: Vec::new(),
            redirect_uri: None,
            visibility: None,
        }
    }

    pub fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    pub fn visibility(mut self, visibility: Visibility) -> Self {
        self.visibility = Some(visibility);
        self
    }
}

/// Result of initiating an OAuth flow.
#[derive(Clone, Debug)]
pub struct InitiateAuthResponse {
    pub flow_id: String,
    pub redirect_url: String,
    pub state: String,
}

/// Result emitted when the broker completes an OAuth flow.
#[derive(Clone, Debug)]
pub struct FlowResult {
    pub flow_id: String,
    pub env: String,
    pub tenant: String,
    pub team: Option<String>,
    pub provider: String,
    pub token_handle_claims: TokenHandleClaims,
    pub storage_path: String,
}

/// Access token information returned by the broker.
#[derive(Clone, Debug)]
pub struct AccessToken {
    pub access_token: String,
    pub expires_at: u64,
}

/// Parameters for issuing a signed fetch request.
#[derive(Clone, Debug)]
pub struct SignedFetchRequest {
    pub token_handle: String,
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl SignedFetchRequest {
    pub fn new(token_handle: impl Into<String>, method: Method, url: impl Into<String>) -> Self {
        Self {
            token_handle: token_handle.into(),
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

/// Response returned from a signed fetch invocation.
#[derive(Clone, Debug)]
pub struct SignedFetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Owner classification for initiating flows.
#[derive(Clone, Copy, Debug)]
pub enum OwnerKind {
    User,
    Service,
}

impl OwnerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            OwnerKind::User => "user",
            OwnerKind::Service => "service",
        }
    }
}

impl fmt::Display for OwnerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Visibility scope for stored connections.
#[derive(Clone, Copy, Debug)]
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

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Serialize)]
struct InitiateAuthPayload<'a> {
    owner_kind: &'a str,
    owner_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    visibility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<&'a str>,
}

#[derive(Deserialize)]
struct InitiateAuthEnvelope {
    flow_id: String,
    redirect_url: String,
    state: String,
}

#[derive(Deserialize)]
struct BrokerEvent {
    flow_id: String,
    env: String,
    tenant: String,
    team: Option<String>,
    provider: String,
    token_handle: TokenHandleClaims,
    storage_path: String,
}

#[derive(Serialize)]
struct HttpAccessTokenRequest<'a> {
    token_handle: &'a str,
    force_refresh: bool,
}

#[derive(Deserialize)]
struct HttpAccessTokenResponse {
    access_token: String,
    expires_at: u64,
}

#[derive(Serialize)]
struct HttpSignedFetchRequest<'a> {
    token_handle: &'a str,
    method: &'a str,
    url: &'a str,
    headers: &'a [HttpHeader<'a>],
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<&'a str>,
    body_encoding: &'static str,
}

#[derive(Serialize)]
struct HttpHeader<'a> {
    name: &'a str,
    value: &'a str,
}

#[derive(Deserialize)]
struct HttpSignedFetchResponse {
    status: u16,
    headers: Vec<HttpHeaderOwned>,
    body: String,
    body_encoding: String,
}

#[derive(Deserialize)]
struct HttpHeaderOwned {
    name: String,
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_kind_to_string() {
        assert_eq!(OwnerKind::User.as_str(), "user");
        assert_eq!(OwnerKind::Service.as_str(), "service");
    }

    #[test]
    fn visibility_to_string() {
        assert_eq!(Visibility::Private.as_str(), "private");
        assert_eq!(Visibility::Team.as_str(), "team");
        assert_eq!(Visibility::Tenant.as_str(), "tenant");
    }
}
