//! OpenID Connect relying party utilities.
//!
//! ```no_run
//! use greentic_oauth_core::oidc::{OidcClient, PkceState};
//! use url::Url;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let issuer = Url::parse("https://accounts.example.com")?;
//! let redirect = Url::parse("https://app.example.com/oauth/callback")?;
//! let client_id = "oauth-demo-client";
//!
//! let mut rp = OidcClient::discover(&issuer).await?;
//! rp.set_client_credentials(client_id, None)?;
//!
//! let (authorize_url, pkce) = rp.auth_url(&redirect, &["openid", "email"])?;
//! println!("Redirect the browser to {}", authorize_url);
//!
//! // ... later, exchange the returned code + PKCE verifier ...
//! # let code = "dummy-code";
//! let token_set = rp.exchange_code(code, &pkce, &redirect).await?;
//! if let Some(id_token) = token_set.id_token.as_deref() {
//!     let claims = rp.validate_id_token(id_token, pkce.nonce())?;
//!     println!("Authenticated subject {}", claims.subject);
//! }
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AccessToken, AdditionalProviderMetadata, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IssuerUrl, LogoutProviderMetadata, Nonce, ProviderMetadata, RevocationUrl,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
    core::{
        CoreAuthenticationFlow, CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient,
        CoreClientAuthMethod, CoreGrantType, CoreIdToken, CoreIdTokenClaims,
        CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode,
        CoreResponseType, CoreRevocableToken, CoreSubjectIdentifierType, CoreTokenResponse,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use tracing::instrument;
use url::Url;

use crate::{pkce::PkcePair, types::TokenSet};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct GreenticAdditionalMetadata {
    #[serde(default)]
    revocation_endpoint: Option<String>,
}

impl AdditionalProviderMetadata for GreenticAdditionalMetadata {}

type GreenticProviderMetadata = ProviderMetadata<
    LogoutProviderMetadata<GreenticAdditionalMetadata>,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

/// Errors returned by [`OidcClient`].
#[derive(Debug, Error)]
pub enum OidcError {
    /// Generic HTTP failure.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    /// The OAuth client configuration was invalid.
    #[error("client configuration error: {0}")]
    Configuration(#[from] openidconnect::ConfigurationError),
    /// No client credentials configured.
    #[error("client credentials have not been configured")]
    MissingClientCredentials,
    /// ID token validation failed.
    #[error("id token validation failed: {0}")]
    IdToken(#[from] openidconnect::ClaimsVerificationError),
    /// The provider does not advertise end-session support.
    #[error("provider does not expose an end session endpoint")]
    EndSessionNotSupported,
    /// Generic error.
    #[error("{0}")]
    Other(String),
}

/// Claims extracted from a validated ID token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdClaims {
    pub issuer: Url,
    pub subject: String,
    pub audience: Vec<String>,
    pub expires_at: Option<OffsetDateTime>,
    pub issued_at: Option<OffsetDateTime>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub nonce: Option<String>,
    pub gender: Option<String>,
}

/// Persisted PKCE state returned by [`OidcClient::auth_url`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkceState {
    verifier: String,
    csrf: String,
    nonce: String,
}

impl PkceState {
    /// Returns the PKCE verifier associated with the authorization request.
    pub fn verifier_secret(&self) -> &str {
        &self.verifier
    }

    /// Returns the CSRF token that was bundled into the authorization URL.
    pub fn csrf_token(&self) -> &str {
        &self.csrf
    }

    /// Returns the nonce that should be echoed in the ID token.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    fn pkce_verifier(&self) -> PkceCodeVerifier {
        PkceCodeVerifier::new(self.verifier.clone())
    }
}

/// Thin wrapper around OpenID Connect provider discovery and RP interactions.
#[derive(Clone)]
pub struct OidcClient {
    metadata: Arc<GreenticProviderMetadata>,
    client_id: Option<ClientId>,
    client_secret: Option<ClientSecret>,
}

impl OidcClient {
    /// Discovers the provider configuration and JSON Web Key Set for `issuer`.
    #[instrument(skip_all, fields(issuer = %issuer))]
    pub async fn discover(issuer: &Url) -> Result<Self, OidcError> {
        let issuer_url = IssuerUrl::from_url(issuer.clone());

        let metadata: GreenticProviderMetadata =
            GreenticProviderMetadata::discover_async(issuer_url.clone(), async_http_client)
                .await
                .map_err(|err| OidcError::Other(err.to_string()))?;
        Ok(Self {
            metadata: Arc::new(metadata),
            client_id: None,
            client_secret: None,
        })
    }

    /// Configures the OAuth client credentials.
    pub fn set_client_credentials(
        &mut self,
        client_id: impl Into<String>,
        client_secret: Option<String>,
    ) -> Result<(), OidcError> {
        self.client_id = Some(ClientId::new(client_id.into()));
        self.client_secret = client_secret.map(ClientSecret::new);
        Ok(())
    }

    /// Returns the authorization URL and PKCE material for the authorization code flow.
    #[instrument(skip(self, scopes))]
    pub fn auth_url(&self, redirect: &Url, scopes: &[&str]) -> Result<(Url, PkceState), OidcError> {
        let client = self
            .core_client()?
            .set_redirect_uri(RedirectUrl::from_url(redirect.clone()));

        let pkce = PkcePair::generate();
        let pkce_verifier = PkceCodeVerifier::new(pkce.verifier.clone());
        let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(&pkce_verifier);

        let (auth_url, csrf, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge)
            .add_scope(Scope::new("openid".into()))
            .add_scopes(
                scopes
                    .iter()
                    .filter(|scope| !scope.is_empty())
                    .map(|scope| Scope::new(scope.to_string())),
            )
            .url();

        Ok((
            auth_url,
            PkceState {
                verifier: pkce.verifier,
                csrf: csrf.secret().to_string(),
                nonce: nonce.secret().to_string(),
            },
        ))
    }

    /// Exchanges the authorization code for tokens.
    #[instrument(skip(self, pkce))]
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce: &PkceState,
        redirect: &Url,
    ) -> Result<TokenSet, OidcError> {
        let client = self
            .core_client()?
            .set_redirect_uri(RedirectUrl::from_url(redirect.clone()));

        let response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(pkce.pkce_verifier())
            .request_async(async_http_client)
            .await
            .map_err(|err| OidcError::Other(err.to_string()))?;

        Ok(token_set_from_response(&response))
    }

    /// Validates an ID token using the downloaded JWKS.
    pub fn validate_id_token(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<IdClaims, OidcError> {
        let client = self.core_client()?;
        let verifier = client.id_token_verifier();
        let nonce = Nonce::new(expected_nonce.to_owned());
        let token: CoreIdToken = id_token
            .parse()
            .map_err(|err| OidcError::Other(format!("invalid id token: {err}")))?;

        let claims = token.claims(&verifier, &nonce)?;
        Ok(IdClaims::from_claims(claims))
    }

    /// Refreshes an access token using the refresh token.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenSet, OidcError> {
        let client = self.core_client()?;
        let response = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|err| OidcError::Other(err.to_string()))?;

        Ok(token_set_from_response(&response))
    }

    /// Revokes a refresh or access token.
    pub async fn revoke(
        &self,
        token: &str,
        token_type_hint: Option<&str>,
    ) -> Result<(), OidcError> {
        let client = self.core_client()?;
        let hint_lower = token_type_hint.map(|hint| hint.to_ascii_lowercase());
        let revocable = match hint_lower.as_deref() {
            Some("refresh_token") => CoreRevocableToken::from(RefreshToken::new(token.to_string())),
            _ => CoreRevocableToken::from(AccessToken::new(token.to_string())),
        };
        let mut request = client.revoke_token(revocable)?;
        if let Some(hint) = token_type_hint
            && !matches!(
                hint_lower.as_deref(),
                Some("refresh_token" | "access_token")
            )
        {
            request = request.add_extra_param("token_type_hint", hint.to_string());
        }
        request
            .request_async(async_http_client)
            .await
            .map_err(|err| OidcError::Other(err.to_string()))?;
        Ok(())
    }

    /// Constructs the provider's end-session URL.
    pub fn end_session_url(
        &self,
        id_token_hint: &str,
        post_logout_redirect_uri: &url::Url,
    ) -> Result<url::Url, OidcError> {
        let end_session = self
            .metadata
            .additional_metadata()
            .end_session_endpoint
            .as_ref()
            .ok_or(OidcError::EndSessionNotSupported)?
            .url()
            .clone();
        let mut url = end_session;
        url.query_pairs_mut()
            .append_pair("id_token_hint", id_token_hint)
            .append_pair(
                "post_logout_redirect_uri",
                post_logout_redirect_uri.as_str(),
            );
        Ok(url)
    }

    fn core_client(&self) -> Result<CoreClient, OidcError> {
        let client_id = self
            .client_id
            .clone()
            .ok_or(OidcError::MissingClientCredentials)?;
        let client = CoreClient::from_provider_metadata(
            (*self.metadata).clone(),
            client_id,
            self.client_secret.clone(),
        );
        let client = if let Some(revocation) = &self
            .metadata
            .additional_metadata()
            .additional_metadata
            .revocation_endpoint
        {
            match Url::parse(revocation) {
                Ok(url) => client.set_revocation_uri(RevocationUrl::from_url(url)),
                Err(err) => {
                    tracing::warn!(target: "oauth.oidc", revocation, error = %err, "ignoring invalid revocation endpoint");
                    client
                }
            }
        } else {
            client
        };
        Ok(client)
    }

    #[cfg(test)]
    fn test_new(
        mut metadata: GreenticProviderMetadata,
        jwks: openidconnect::core::CoreJsonWebKeySet,
    ) -> Self {
        metadata = metadata.set_jwks(jwks);
        Self {
            metadata: Arc::new(metadata),
            client_id: None,
            client_secret: None,
        }
    }
}

fn token_set_from_response(response: &CoreTokenResponse) -> TokenSet {
    let access_token = response.access_token().secret().to_owned();
    let expires_in = response.expires_in().map(|d| d.as_secs());
    let refresh_token = response
        .refresh_token()
        .map(|token| token.secret().to_owned());
    let scopes = response
        .scopes()
        .map(|scopes| scopes.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();
    let id_token = response.extra_fields().id_token().map(|id| id.to_string());

    TokenSet {
        access_token,
        expires_in,
        refresh_token,
        token_type: Some(response.token_type().as_ref().to_string()),
        scopes,
        id_token,
    }
}

impl IdClaims {
    fn from_claims(claims: &CoreIdTokenClaims) -> Self {
        let expires_at = OffsetDateTime::from_unix_timestamp(claims.expiration().timestamp()).ok();
        let issued_at = OffsetDateTime::from_unix_timestamp(claims.issue_time().timestamp()).ok();

        IdClaims {
            issuer: claims.issuer().url().clone(),
            subject: claims.subject().as_str().to_string(),
            audience: claims
                .audiences()
                .iter()
                .map(|aud| aud.as_str().to_string())
                .collect(),
            expires_at,
            issued_at,
            email: claims.email().map(|email| email.as_str().to_string()),
            name: claims
                .name()
                .and_then(|claim| claim.iter().next())
                .map(|(_, value)| value.to_string()),
            preferred_username: claims
                .preferred_username()
                .map(|username| username.as_str().to_string()),
            nonce: claims.nonce().map(|n| n.secret().to_string()),
            gender: claims.gender().map(|g| g.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openidconnect::JsonWebKeyId;
    use openidconnect::core::{CoreJsonWebKey, CoreJsonWebKeySet};
    use serde_json::json;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method, path},
    };

    #[tokio::test]
    async fn discover_fetches_metadata_and_jwks() {
        let Ok(server) = tokio::spawn(async { MockServer::start().await }).await else {
            eprintln!("skipping discovery test: mock server unavailable");
            return;
        };
        let issuer = server.uri();
        let issuer_root = issuer.trim_end_matches('/');
        let issuer_with_trailing = format!("{issuer_root}/");

        let discovery_body = json!({
            "issuer": issuer_with_trailing,
            "authorization_endpoint": format!("{}/oauth2/auth", issuer_root),
            "token_endpoint": format!("{}/oauth2/token", issuer_root),
            "jwks_uri": format!("{}/oauth2/jwks", issuer_root),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        });

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(discovery_body))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/oauth2/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": sample_jwks().keys()
            })))
            .mount(&server)
            .await;

        let issuer = Url::parse(&issuer_with_trailing).expect("issuer url");
        let client = OidcClient::discover(&issuer).await.expect("discover");

        assert_eq!(client.metadata.issuer().as_str(), issuer.as_str());
        assert!(!client.metadata.jwks().keys().is_empty());
    }

    #[tokio::test]
    async fn exchange_and_refresh_tokens() {
        let Ok(server) = tokio::spawn(async { MockServer::start().await }).await else {
            eprintln!("skipping exchange test: mock server unavailable");
            return;
        };
        let issuer_base = server.uri();
        let metadata = provider_metadata(&issuer_base);
        assert!(
            metadata
                .additional_metadata()
                .additional_metadata
                .revocation_endpoint
                .is_some(),
            "test metadata missing revocation endpoint"
        );
        let jwks = sample_jwks();

        let mut client = OidcClient::test_new(metadata, jwks);
        client
            .set_client_credentials("client", Some("secret".to_string()))
            .expect("credentials");

        let token_response = json!({
            "access_token": "access-123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-456",
            "scope": "openid profile"
        });

        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_response.clone()))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_response.clone()))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/oauth2/revoke"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let redirect = Url::parse("https://app.example.com/callback").unwrap();
        let (_, pkce) = client.auth_url(&redirect, &["openid"]).expect("auth url");

        let tokens = client
            .exchange_code("code123", &pkce, &redirect)
            .await
            .expect("token exchange");

        assert_eq!(tokens.access_token, "access-123");
        assert_eq!(tokens.refresh_token.as_deref(), Some("refresh-456"));
        assert!(tokens.scopes.contains(&"openid".to_string()));

        let refreshed = client.refresh("refresh-456").await.expect("refresh");
        assert_eq!(refreshed.access_token, "access-123");

        client
            .revoke("refresh-456", Some("refresh_token"))
            .await
            .expect("revoke");
    }

    fn provider_metadata(base: &str) -> GreenticProviderMetadata {
        let trimmed = base.trim_end_matches('/');
        let issuer = format!("{trimmed}/");
        let auth = format!("{trimmed}/oauth2/auth");
        let token = format!("{trimmed}/oauth2/token");
        let jwks = format!("{trimmed}/oauth2/jwks");
        let revocation = format!("{trimmed}/oauth2/revoke");
        let end_session = format!("{trimmed}/logout");

        serde_json::from_value(json!({
            "issuer": issuer,
            "authorization_endpoint": auth,
            "token_endpoint": token,
            "jwks_uri": jwks,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "email", "profile"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "revocation_endpoint": revocation,
            "end_session_endpoint": end_session
        }))
        .expect("metadata")
    }

    fn sample_jwks() -> CoreJsonWebKeySet {
        CoreJsonWebKeySet::new(vec![CoreJsonWebKey::new_rsa(
            vec![0x01],
            vec![0x01],
            Some(JsonWebKeyId::new("kid".into())),
        )])
    }

    #[test]
    fn pkce_state_contains_secrets() {
        let metadata = provider_metadata("https://example.com");
        let jwks = sample_jwks();
        let client = OidcClient::test_new(metadata, jwks);
        let mut client = client;
        client
            .set_client_credentials("client", None)
            .expect("credentials");

        let redirect = url::Url::parse("https://example.com/callback").unwrap();
        let (url, pkce) = client.auth_url(&redirect, &["email"]).unwrap();

        assert!(url.as_str().contains("code_challenge="));
        assert!(!pkce.verifier_secret().is_empty());
        assert!(!pkce.csrf_token().is_empty());
        assert!(!pkce.nonce().is_empty());
    }
}
