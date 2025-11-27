use std::time::Duration;

use async_nats::Client as NatsClient;
use async_trait::async_trait;
use base64::Engine;
use futures_util::StreamExt;
use greentic_oauth_core::{AccessToken, OAuthError, TokenHandleClaims};
use greentic_oauth_host::OAuthBroker;
use greentic_types::TenantCtx;
use reqwest::{Client as HttpClient, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::time;
use url::Url;

use crate::error::SdkError;
use crate::types::{
    ClientConfig, FlowResult, InitiateAuthRequest, InitiateAuthResponse, SignedFetchRequest,
    SignedFetchResponse,
};

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
            time::timeout(duration, subscription.next())
                .await?
                .ok_or_else(|| SdkError::InvalidResponse("subscription closed".into()))?
        } else {
            subscription
                .next()
                .await
                .ok_or_else(|| SdkError::InvalidResponse("subscription closed".into()))?
        };

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

        Self::ensure_success(response.status())?;
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
        Self::ensure_success(response.status())?;
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

    /// List available provider identifiers from the broker discovery API.
    pub async fn list_providers(&self) -> Result<Vec<String>, SdkError> {
        let url = self.http_base.join("oauth/discovery/providers")?;
        let response = self.http.get(url).send().await?;
        Self::ensure_success(response.status())?;
        let body = response.text().await?;
        let providers: Vec<ProviderSummary> = serde_json::from_str(&body)?;
        Ok(providers.into_iter().map(|provider| provider.id).collect())
    }

    /// Request a resource-scoped token (provider/registry/etc.) for the given tenant context.
    pub async fn request_resource_token(
        &self,
        tenant: &TenantCtx,
        resource_id: &str,
        scopes: &[String],
    ) -> Result<AccessToken, SdkError> {
        let url = self.http_base.join("resource-token")?;
        let payload = ResourceTokenRequest {
            env: tenant.env.to_string(),
            tenant: tenant.tenant.to_string(),
            team: tenant.team.as_ref().map(|t| t.to_string()),
            resource_id,
            scopes,
        };
        let response = self.http.post(url).json(&payload).send().await?;
        Self::ensure_success(response.status())?;
        let body: ResourceTokenResponse = response.json().await?;
        Ok(AccessToken {
            access_token: body.access_token,
            expires_at: body.expires_at,
        })
    }

    /// Fetch the merged provider descriptor scoped to the supplied context.
    pub async fn get_provider_descriptor_json(
        &self,
        tenant: &str,
        provider: &str,
        team: Option<&str>,
        user: Option<&str>,
    ) -> Result<String, SdkError> {
        let mut url = self
            .http_base
            .join(&format!("oauth/discovery/{tenant}/providers/{provider}"))?;
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(team) = team {
                pairs.append_pair("team", team);
            }
            if let Some(user) = user {
                pairs.append_pair("user", user);
            }
        }
        let response = self.http.get(url).send().await?;
        Self::ensure_success(response.status())?;
        let body = response.text().await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        Ok(json.to_string())
    }

    /// Retrieve configuration requirements for the supplied provider context.
    pub async fn get_config_requirements_json(
        &self,
        tenant: &str,
        provider: &str,
        team: Option<&str>,
        user: Option<&str>,
    ) -> Result<String, SdkError> {
        let path = format!("oauth/discovery/{tenant}/providers/{provider}/requirements");
        let mut url = self.http_base.join(&path)?;
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(team) = team {
                pairs.append_pair("team", team);
            }
            if let Some(user) = user {
                pairs.append_pair("user", user);
            }
        }
        let response = self.http.get(url).send().await?;
        Self::ensure_success(response.status())?;
        let body = response.text().await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        Ok(json.to_string())
    }

    /// Generate a flow blueprint for the supplied grant type and context.
    pub async fn start_flow_blueprint_json(
        &self,
        tenant: &str,
        provider: &str,
        grant_type: &str,
        team: Option<&str>,
        user: Option<&str>,
    ) -> Result<String, SdkError> {
        let url = self.http_base.join(&format!(
            "oauth/discovery/{tenant}/providers/{provider}/blueprint"
        ))?;
        let payload = HttpBlueprintRequest {
            grant_type,
            team,
            user,
        };
        let response = self.http.post(url).json(&payload).send().await?;
        Self::ensure_success(response.status())?;
        let body = response.text().await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        Ok(json.to_string())
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

    fn ensure_success(status: StatusCode) -> Result<(), SdkError> {
        if status.is_success() {
            Ok(())
        } else {
            Err(SdkError::InvalidResponse(format!("http status {status}")))
        }
    }
}

#[async_trait]
impl OAuthBroker for Client {
    async fn request_token(
        &self,
        tenant: &TenantCtx,
        resource: &str,
        scopes: &[String],
    ) -> greentic_oauth_core::OAuthResult<AccessToken> {
        // Ensure caller and client are using the same tenant/env context; the broker
        // enforces context via token handles, but we still guard obvious mismatches here.
        if self.env != tenant.env.to_string() || self.tenant != tenant.tenant.to_string() {
            return Err(OAuthError::Broker(
                "tenant or env mismatch between client and request".into(),
            ));
        }

        self.request_resource_token(tenant, resource, scopes)
            .await
            .map_err(map_sdk_error)
    }
}

fn map_sdk_error(err: SdkError) -> OAuthError {
    match err {
        SdkError::Http(e) => OAuthError::Transport(e.to_string()),
        SdkError::Nats(e) => OAuthError::Transport(e),
        SdkError::Serialization(e) => OAuthError::Other(e.to_string()),
        SdkError::Url(e) => OAuthError::Other(e.to_string()),
        SdkError::Timeout => OAuthError::Other("timeout".into()),
        SdkError::InvalidResponse(msg) => OAuthError::Broker(msg),
        SdkError::Unsupported(msg) => OAuthError::Broker(msg.to_string()),
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
struct ResourceTokenRequest<'a> {
    env: String,
    tenant: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    team: Option<String>,
    resource_id: &'a str,
    #[serde(skip_serializing_if = "scopes_empty", default)]
    scopes: &'a [String],
}

#[derive(Deserialize)]
struct ResourceTokenResponse {
    access_token: String,
    expires_at: u64,
}

fn scopes_empty(scopes: &&[String]) -> bool {
    scopes.is_empty()
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

#[derive(Deserialize)]
struct ProviderSummary {
    id: String,
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

#[derive(Serialize)]
struct HttpBlueprintRequest<'a> {
    grant_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    team: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<&'a str>,
}

#[derive(Deserialize)]
struct HttpHeaderOwned {
    name: String,
    value: String,
}

#[cfg(test)]
mod tests {
    use crate::types::{OwnerKind, Visibility};

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
