use std::{error::Error, fmt};

use crate::types::{OAuthFlowRequest, OAuthFlowResult, TokenHandleClaims, TokenSet};

/// Convenience alias for provider interactions.
pub type ProviderResult<T> = Result<T, ProviderError>;

/// High-level trait all OAuth providers must implement for the broker.
pub trait Provider: Send + Sync {
    /// Authorization endpoint for the provider.
    fn auth_url(&self) -> &str;
    /// Token endpoint for the provider.
    fn token_url(&self) -> &str;
    /// Registered redirect URI the provider will callback with.
    fn redirect_uri(&self) -> &str;
    /// Build an authorization redirect response for a flow request.
    fn build_authorize_redirect(
        &self,
        request: &OAuthFlowRequest,
    ) -> ProviderResult<OAuthFlowResult>;
    /// Exchange an authorization code for tokens.
    fn exchange_code(
        &self,
        claims: &TokenHandleClaims,
        code: &str,
        pkce_verifier: Option<&str>,
    ) -> ProviderResult<TokenSet>;
    /// Refresh an existing token set.
    fn refresh(&self, claims: &TokenHandleClaims, refresh_token: &str) -> ProviderResult<TokenSet>;
    /// Revoke an access or refresh token.
    fn revoke(&self, claims: &TokenHandleClaims, token: &str) -> ProviderResult<()>;
}

/// Lightweight error type for provider implementers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderError {
    kind: ProviderErrorKind,
    message: Option<String>,
}

impl ProviderError {
    /// Create a new error for the given kind with an optional detail message.
    pub fn new(kind: ProviderErrorKind, message: impl Into<Option<String>>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Access the classification of this error.
    pub fn kind(&self) -> ProviderErrorKind {
        self.kind
    }

    /// Optional descriptive message supplied when the error was created.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(message) => write!(f, "{}: {}", self.kind, message),
            None => write!(f, "{}", self.kind),
        }
    }
}

impl Error for ProviderError {}

/// Classification of errors returned by providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderErrorKind {
    /// Misconfiguration or invalid request was issued.
    Configuration,
    /// Upstream transport or network error.
    Transport,
    /// Provider rejected the request due to lack of permissions.
    Authorization,
    /// Provider returned an unexpected payload.
    InvalidResponse,
    /// The operation is not supported by the provider implementation.
    Unsupported,
    /// Catch-all for miscellaneous failures.
    Other,
}

impl fmt::Display for ProviderErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            ProviderErrorKind::Configuration => "configuration error",
            ProviderErrorKind::Transport => "transport error",
            ProviderErrorKind::Authorization => "authorization error",
            ProviderErrorKind::InvalidResponse => "invalid response",
            ProviderErrorKind::Unsupported => "unsupported operation",
            ProviderErrorKind::Other => "provider error",
        };
        f.write_str(label)
    }
}
