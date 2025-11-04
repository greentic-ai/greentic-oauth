//! Greentic OAuth core primitives shared across services.

pub mod constants;
pub mod oidc;
pub mod pkce;
pub mod provider;
pub mod state;
pub mod types;
pub mod verifier;

#[cfg(feature = "schemas")]
pub mod schemas;

pub use oidc::{IdClaims, OidcClient, OidcError, PkceState};
pub use pkce::PkcePair;
pub use provider::{Provider, ProviderError, ProviderResult};
pub use state::{DEFAULT_STATE_TTL, StateClaims, StateError, sign_state, verify_state};
pub use types::{
    OAuthFlowRequest, OAuthFlowResult, OAuthRequestCtx, OwnerKind, ProviderId, TenantCtx,
    TokenHandleClaims, TokenSet,
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
