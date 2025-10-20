//! Greentic OAuth core primitives shared across services.

pub mod constants;
pub mod provider;
pub mod types;

#[cfg(feature = "schemas")]
pub mod schemas;

pub use provider::{Provider, ProviderError, ProviderResult};
pub use types::{
    OAuthFlowRequest, OAuthFlowResult, OwnerKind, TenantCtx, TokenHandleClaims, TokenSet,
};

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
