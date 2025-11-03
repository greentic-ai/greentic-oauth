use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// Stable identifier for a supported OAuth provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProviderId {
    Google,
    Microsoft,
    GitHub,
    Custom(String),
}

impl ProviderId {
    /// Returns the slug form of the provider identifier.
    pub fn as_str(&self) -> &str {
        match self {
            ProviderId::Google => "google",
            ProviderId::Microsoft => "microsoft",
            ProviderId::GitHub => "github",
            ProviderId::Custom(value) => value.as_str(),
        }
    }

    /// Construct a provider identifier from an arbitrary slug.
    pub fn from_slug(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_str() {
            "google" => ProviderId::Google,
            "microsoft" => ProviderId::Microsoft,
            "github" => ProviderId::GitHub,
            other => ProviderId::Custom(other.to_owned()),
        }
    }

    /// Returns `true` if the provider is one of the built-in integrations.
    pub fn is_builtin(&self) -> bool {
        !matches!(self, ProviderId::Custom(_))
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProviderId {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_slug(s))
    }
}

impl Serialize for ProviderId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProviderId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let slug = String::deserialize(deserializer)?;
        Ok(Self::from_slug(slug))
    }
}

/// Execution context derived from an OAuth request.
#[cfg_attr(feature = "schemas", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthRequestCtx {
    pub tenant_ctx: TenantCtx,
    pub provider: ProviderId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
}

impl OAuthRequestCtx {
    pub fn new(tenant_ctx: TenantCtx, provider: ProviderId, redirect_to: Option<String>) -> Self {
        Self {
            tenant_ctx,
            provider,
            redirect_to,
        }
    }

    pub fn tenant_ctx(&self) -> &TenantCtx {
        &self.tenant_ctx
    }

    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    pub fn redirect_target(&self) -> Option<&str> {
        self.redirect_to.as_deref()
    }
}

/// Execution context for multi-tenant OAuth flows.
#[cfg_attr(feature = "schemas", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantCtx {
    /// Deployment environment (e.g. "prod", "staging").
    pub env: String,
    /// Identifier for the customer tenant.
    pub tenant: String,
    /// Optional team qualifier within the tenant.
    pub team: Option<String>,
}

/// Classification of the principal that owns an OAuth token.
#[cfg_attr(feature = "schemas", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OwnerKind {
    /// A human user (subject captures the external identifier).
    User { subject: String },
    /// A service account (subject captures the automation identifier).
    Service { subject: String },
}

/// Exchange-able OAuth token bundle (access + optional refresh data).
#[cfg_attr(feature = "schemas", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub scopes: Vec<String>,
}

/// Claims stored alongside an issued token handle.
#[cfg_attr(feature = "schemas", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenHandleClaims {
    pub provider: String,
    pub subject: String,
    pub owner: OwnerKind,
    pub tenant: TenantCtx,
    pub scopes: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Request payload for initiating an interactive OAuth authorization flow.
#[cfg_attr(feature = "schemas", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthFlowRequest {
    pub tenant: TenantCtx,
    pub owner: OwnerKind,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// High-level result of building an authorization redirect.
#[cfg_attr(feature = "schemas", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthFlowResult {
    pub redirect_url: String,
    pub state: Option<String>,
    pub scopes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, to_string};

    fn example_tenant() -> TenantCtx {
        TenantCtx {
            env: "prod".to_owned(),
            tenant: "acme".to_owned(),
            team: Some("platform".to_owned()),
        }
    }

    fn example_owner() -> OwnerKind {
        OwnerKind::User {
            subject: "user:12345".to_owned(),
        }
    }

    #[test]
    fn tenant_ctx_roundtrip() {
        let ctx = example_tenant();
        let json = to_string(&ctx).expect("serialize tenant");
        let parsed: TenantCtx = from_str(&json).expect("deserialize tenant");
        assert_eq!(ctx, parsed);
    }

    #[test]
    fn owner_kind_roundtrip() {
        let owner = example_owner();
        let json = to_string(&owner).expect("serialize owner");
        let parsed: OwnerKind = from_str(&json).expect("deserialize owner");
        assert_eq!(owner, parsed);
    }

    #[test]
    fn token_set_roundtrip() {
        let token = TokenSet {
            access_token: "access-xyz".to_owned(),
            expires_in: Some(3600),
            refresh_token: Some("refresh-abc".to_owned()),
            token_type: Some("Bearer".to_owned()),
            scopes: vec!["email".to_owned(), "profile".to_owned()],
        };
        let json = to_string(&token).expect("serialize token");
        let parsed: TokenSet = from_str(&json).expect("deserialize token");
        assert_eq!(token, parsed);
    }

    #[test]
    fn token_handle_claims_roundtrip() {
        let claims = TokenHandleClaims {
            provider: "github".to_owned(),
            subject: "user:12345".to_owned(),
            owner: example_owner(),
            tenant: example_tenant(),
            scopes: vec!["repo".to_owned(), "workflow".to_owned()],
            issued_at: 1_700_000_000,
            expires_at: 1_700_003_600,
        };
        let json = to_string(&claims).expect("serialize claims");
        let parsed: TokenHandleClaims = from_str(&json).expect("deserialize claims");
        assert_eq!(claims, parsed);
    }

    #[test]
    fn oauth_flow_request_roundtrip() {
        let request = OAuthFlowRequest {
            tenant: example_tenant(),
            owner: example_owner(),
            redirect_uri: "https://example.com/callback".to_owned(),
            state: Some("state-123".to_owned()),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        };
        let json = to_string(&request).expect("serialize request");
        let parsed: OAuthFlowRequest = from_str(&json).expect("deserialize request");
        assert_eq!(request, parsed);
    }

    #[test]
    fn oauth_flow_result_roundtrip() {
        let result = OAuthFlowResult {
            redirect_url: "https://auth.example.com/redirect".to_owned(),
            state: Some("state-123".to_owned()),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
        };
        let json = to_string(&result).expect("serialize result");
        let parsed: OAuthFlowResult = from_str(&json).expect("deserialize result");
        assert_eq!(result, parsed);
    }

    #[test]
    fn provider_id_parsing() {
        assert_eq!(ProviderId::from_str("google").unwrap(), ProviderId::Google);
        assert_eq!(
            ProviderId::from_str("custom-service").unwrap(),
            ProviderId::Custom("custom-service".into())
        );
        assert_eq!(ProviderId::Google.to_string(), "google");
    }

    #[test]
    fn oauth_request_ctx_serializes() {
        let ctx = OAuthRequestCtx::new(
            example_tenant(),
            ProviderId::Microsoft,
            Some("https://app.example.com/return".into()),
        );
        let json = to_string(&ctx).expect("serialize ctx");
        let parsed: OAuthRequestCtx = from_str(&json).expect("deserialize ctx");
        assert_eq!(parsed.provider, ProviderId::Microsoft);
        assert_eq!(
            parsed.redirect_to.as_deref(),
            Some("https://app.example.com/return")
        );
    }
}
