//! Greentic OAuth core primitives shared across services.
//!
//! The crate exposes a consistent provider interface, including optional PKCE
//! verifier forwarding and pass-through `extra_params` so higher-level brokers
//! can enrich authorization and token requests for specific providers without
//! reinventing serialization concerns.

pub mod constants;
#[cfg(not(target_arch = "wasm32"))]
pub mod oidc;
pub mod pkce;
pub mod provider;
#[cfg(not(target_arch = "wasm32"))]
pub mod provider_tokens;
pub mod state;
pub mod types;
pub mod verifier;

#[cfg(feature = "schemas")]
pub mod schemas;

pub use greentic_types::TenantCtx;
#[cfg(not(target_arch = "wasm32"))]
pub use oidc::{IdClaims, OidcClient, OidcError, PkceState};
pub use pkce::PkcePair;
pub use provider::{Provider, ProviderError, ProviderResult};
#[cfg(not(target_arch = "wasm32"))]
pub use provider_tokens::{
    ProviderOAuthClientConfig, ProviderOAuthFlow, ProviderSecretStore, ProviderToken,
    ProviderTokenError, ProviderTokenService, client_credentials_path, refresh_token_path,
};
pub use state::{DEFAULT_STATE_TTL, StateClaims, StateError, sign_state, verify_state};
pub use types::{
    OAuthFlowRequest, OAuthFlowResult, OAuthRequestCtx, OwnerKind, ProviderId, TokenHandleClaims,
    TokenSet,
};
pub use verifier::{CodeVerifierStore, InMemoryCodeVerifierStore};

/// Lightweight probe to ensure the crate is wired in correctly.
pub fn health_check() -> &'static str {
    "ok"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_check_returns_ok() {
        assert_eq!(health_check(), "ok");
    }
}
