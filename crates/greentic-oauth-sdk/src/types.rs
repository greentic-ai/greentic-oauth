use std::{fmt, str::FromStr};

use greentic_oauth_core::TokenHandleClaims;
use reqwest::Method;

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

impl ClientConfig {}

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
    pub fn new(
        owner_kind: OwnerKind,
        owner_id: impl Into<String>,
        flow_id: impl Into<String>,
    ) -> Self {
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

impl FromStr for OwnerKind {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(OwnerKind::User),
            "service" => Ok(OwnerKind::Service),
            _ => Err("unknown owner kind"),
        }
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
    pub fn as_str(&self) -> &'static str {
        match self {
            Visibility::Private => "private",
            Visibility::Team => "team",
            Visibility::Tenant => "tenant",
        }
    }
}

impl FromStr for Visibility {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "private" => Ok(Visibility::Private),
            "team" => Ok(Visibility::Team),
            "tenant" => Ok(Visibility::Tenant),
            _ => Err("unknown visibility"),
        }
    }
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
