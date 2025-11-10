use std::sync::{Arc, Mutex};

use greentic_oauth_core::{
    provider::{Provider, ProviderError, ProviderErrorKind, ProviderResult},
    types::{OAuthFlowRequest, OAuthFlowResult, OwnerKind, TenantCtx, TokenHandleClaims, TokenSet},
};

struct RecordingProvider {
    pkce_history: Arc<Mutex<Vec<Option<String>>>>,
}

impl RecordingProvider {
    fn new(store: Arc<Mutex<Vec<Option<String>>>>) -> Self {
        Self {
            pkce_history: store,
        }
    }

    fn sample_claims() -> TokenHandleClaims {
        TokenHandleClaims {
            provider: "demo".into(),
            subject: "sub".into(),
            owner: OwnerKind::Service {
                subject: "svc".into(),
            },
            tenant: TenantCtx {
                env: "prod".into(),
                tenant: "acme".into(),
                team: None,
            },
            scopes: vec!["openid".into()],
            issued_at: 1,
            expires_at: 2,
        }
    }
}

impl Provider for RecordingProvider {
    fn auth_url(&self) -> &str {
        "https://example.com/auth"
    }

    fn token_url(&self) -> &str {
        "https://example.com/token"
    }

    fn redirect_uri(&self) -> &str {
        "https://app.example.com/callback"
    }

    fn build_authorize_redirect(
        &self,
        request: &OAuthFlowRequest,
    ) -> ProviderResult<OAuthFlowResult> {
        Ok(OAuthFlowResult {
            redirect_url: request.redirect_uri.clone(),
            state: request.state.clone(),
            scopes: request.scopes.clone(),
        })
    }

    fn exchange_code(
        &self,
        _claims: &TokenHandleClaims,
        _code: &str,
        pkce_verifier: Option<&str>,
    ) -> ProviderResult<TokenSet> {
        self.pkce_history
            .lock()
            .expect("history lock")
            .push(pkce_verifier.map(|value| value.to_string()));
        Ok(TokenSet {
            access_token: "token".into(),
            expires_in: None,
            refresh_token: None,
            token_type: Some("Bearer".into()),
            scopes: vec!["openid".into()],
            id_token: None,
        })
    }

    fn refresh(
        &self,
        _claims: &TokenHandleClaims,
        _refresh_token: &str,
    ) -> ProviderResult<TokenSet> {
        Err(ProviderError::new(
            ProviderErrorKind::Unsupported,
            Some("not needed".into()),
        ))
    }

    fn revoke(&self, _claims: &TokenHandleClaims, _token: &str) -> ProviderResult<()> {
        Ok(())
    }
}

#[test]
fn provider_exchange_code_records_pkce_verifier() {
    let history = Arc::new(Mutex::new(Vec::new()));
    let provider = RecordingProvider::new(Arc::clone(&history));
    let claims = RecordingProvider::sample_claims();

    provider
        .exchange_code(&claims, "code-a", Some("verifier-123"))
        .expect("pkce exchange");
    provider
        .exchange_code(&claims, "code-b", None)
        .expect("non-pkce exchange");

    let stored = history.lock().expect("history lock").clone();
    assert_eq!(
        stored,
        vec![Some("verifier-123".into()), None],
        "expected pkce hints to be recorded in order"
    );
}
