use oauth_core::{
    provider::{Provider, ProviderError, ProviderErrorKind, ProviderResult},
    types::{OAuthFlowRequest, OAuthFlowResult, TokenHandleClaims, TokenSet},
};
use serde::Deserialize;
use ureq::{Agent, Error as UreqError};
use url::Url;

use crate::security::pkce::PkcePair;

pub struct GenericOidcProvider {
    agent: Agent,
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    default_scopes: Vec<String>,
    redirect_uri: String,
}

impl GenericOidcProvider {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        default_scopes: impl Into<Vec<String>>,
    ) -> Result<Self, ProviderError> {
        let client_id = client_id.into();
        let client_secret = client_secret.into();
        let auth_url = auth_url.into();
        let token_url = token_url.into();
        let redirect_uri = redirect_uri.into();
        let default_scopes = default_scopes.into();

        if client_id.is_empty() || client_secret.is_empty() {
            return Err(ProviderError::new(
                ProviderErrorKind::Configuration,
                "missing OIDC client credentials".to_string(),
            ));
        }

        Ok(Self {
            agent: Agent::new(),
            client_id,
            client_secret,
            auth_url,
            token_url,
            default_scopes,
            redirect_uri,
        })
    }

    fn build_query(
        &self,
        request: &OAuthFlowRequest,
    ) -> Result<(Url, Option<String>), ProviderError> {
        let mut url = Url::parse(&self.auth_url).map_err(|err| {
            ProviderError::new(
                ProviderErrorKind::Configuration,
                format!("invalid auth url: {err}"),
            )
        })?;

        let scopes = if request.scopes.is_empty() {
            self.default_scopes.join(" ")
        } else {
            request.scopes.join(" ")
        };

        let (challenge, method, verifier) = match (
            request.code_challenge.clone(),
            request.code_challenge_method.clone(),
        ) {
            (Some(challenge), Some(method)) => (challenge, method, None),
            _ => {
                let pair = PkcePair::generate();
                (pair.challenge, "S256".to_string(), Some(pair.verifier))
            }
        };

        {
            let mut query = url.query_pairs_mut();
            query.append_pair("client_id", &self.client_id);
            query.append_pair("response_type", "code");
            query.append_pair("redirect_uri", &request.redirect_uri);
            query.append_pair("scope", &scopes);
            query.append_pair("code_challenge", &challenge);
            query.append_pair("code_challenge_method", &method);

            if let Some(state) = &request.state {
                query.append_pair("state", state);
            }
        }

        Ok((url, verifier))
    }

    fn execute_token_request(&self, params: &[(&str, &str)]) -> ProviderResult<TokenSet> {
        let response = match self
            .agent
            .post(&self.token_url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_form(params)
        {
            Ok(resp) => resp,
            Err(UreqError::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                return Err(ProviderError::new(
                    ProviderErrorKind::Authorization,
                    format!("token endpoint returned {status}: {body}"),
                ));
            }
            Err(UreqError::Transport(err)) => {
                return Err(ProviderError::new(
                    ProviderErrorKind::Transport,
                    err.to_string(),
                ));
            }
        };

        let payload: TokenEndpointResponse = response.into_json().map_err(|err| {
            ProviderError::new(ProviderErrorKind::InvalidResponse, err.to_string())
        })?;

        Ok(payload.into())
    }
}

impl Provider for GenericOidcProvider {
    fn auth_url(&self) -> &str {
        &self.auth_url
    }

    fn token_url(&self) -> &str {
        &self.token_url
    }

    fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    fn build_authorize_redirect(
        &self,
        request: &OAuthFlowRequest,
    ) -> ProviderResult<OAuthFlowResult> {
        let (url, _verifier) = self.build_query(request)?;

        Ok(OAuthFlowResult {
            redirect_url: url.to_string(),
            state: request.state.clone(),
            scopes: if request.scopes.is_empty() {
                self.default_scopes.clone()
            } else {
                request.scopes.clone()
            },
        })
    }

    fn exchange_code(&self, _claims: &TokenHandleClaims, code: &str) -> ProviderResult<TokenSet> {
        let scopes_owned = if self.default_scopes.is_empty() {
            String::new()
        } else {
            self.default_scopes.join(" ")
        };
        let code_owned = code.to_string();
        let params = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code_owned.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("scope", scopes_owned.as_str()),
        ];

        self.execute_token_request(&params)
    }

    fn refresh(
        &self,
        _claims: &TokenHandleClaims,
        refresh_token: &str,
    ) -> ProviderResult<TokenSet> {
        let scopes_owned = if self.default_scopes.is_empty() {
            String::new()
        } else {
            self.default_scopes.join(" ")
        };
        let refresh_owned = refresh_token.to_string();
        let params = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_owned.as_str()),
            ("scope", scopes_owned.as_str()),
        ];

        self.execute_token_request(&params)
    }

    fn revoke(&self, _claims: &TokenHandleClaims, _token: &str) -> ProviderResult<()> {
        Err(ProviderError::new(
            ProviderErrorKind::Unsupported,
            "Generic OIDC revoke not implemented".to_string(),
        ))
    }
}

#[derive(Deserialize)]
struct TokenEndpointResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

impl From<TokenEndpointResponse> for TokenSet {
    fn from(value: TokenEndpointResponse) -> Self {
        let scopes = value
            .scope
            .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_default();
        TokenSet {
            access_token: value.access_token,
            expires_in: value.expires_in,
            refresh_token: value.refresh_token,
            token_type: value.token_type,
            scopes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oauth_core::types::{OwnerKind, TenantCtx};
    use serde_json::json;
    use std::collections::HashMap;
    use tokio::runtime::Runtime;
    use ureq::Agent;
    use wiremock::{
        matchers::{body_string_contains, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn sample_request() -> OAuthFlowRequest {
        OAuthFlowRequest {
            tenant: TenantCtx {
                env: "prod".into(),
                tenant: "acme".into(),
                team: None,
            },
            owner: OwnerKind::Service {
                subject: "service:api".into(),
            },
            redirect_uri: "https://app.example.com/oidc".into(),
            state: Some("state456".into()),
            scopes: vec!["openid".into(), "profile".into()],
            code_challenge: Some("challenge456".into()),
            code_challenge_method: Some("S256".into()),
        }
    }

    fn sample_claims() -> TokenHandleClaims {
        TokenHandleClaims {
            provider: "oidc".into(),
            subject: "service:api".into(),
            owner: OwnerKind::Service {
                subject: "service:api".into(),
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

    #[test]
    fn authorize_redirect_includes_expected_parameters() {
        let provider = GenericOidcProvider::new(
            "client",
            "secret",
            "https://idp.example.com/oauth2/v1/authorize",
            "https://idp.example.com/oauth2/v1/token",
            "https://app.example.com/oidc",
            vec!["openid".into(), "profile".into()],
        )
        .expect("provider");

        let result = provider
            .build_authorize_redirect(&sample_request())
            .expect("redirect");
        let url = Url::parse(&result.redirect_url).expect("valid url");
        let params: HashMap<_, _> = url.query_pairs().into_owned().collect();

        assert_eq!(params.get("client_id"), Some(&"client".to_string()));
        assert_eq!(
            params.get("redirect_uri"),
            Some(&"https://app.example.com/oidc".to_string())
        );
        assert_eq!(params.get("scope"), Some(&"openid profile".to_string()));
        assert_eq!(
            params.get("code_challenge"),
            Some(&"challenge456".to_string())
        );
        assert_eq!(params.get("state"), Some(&"state456".to_string()));
    }

    #[cfg_attr(not(feature = "wiremock_tests"), ignore)]
    #[test]
    fn exchange_code_hits_token_endpoint() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/oauth2/v1/token"))
                .and(body_string_contains("client_id=client"))
                .and(body_string_contains("grant_type=authorization_code"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "oidc-token",
                    "expires_in": 1200,
                    "refresh_token": "oidc-refresh",
                    "scope": "openid profile",
                    "token_type": "Bearer"
                })))
                .mount(&server)
                .await;

            let token_url = format!("{}/oauth2/v1/token", server.uri());
            let auth_url = format!("{}/oauth2/v1/authorize", server.uri());

            let token_set = tokio::task::spawn_blocking(move || {
                let provider = GenericOidcProvider {
                    agent: Agent::new(),
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    auth_url,
                    token_url,
                    default_scopes: vec!["openid".into(), "profile".into()],
                    redirect_uri: "https://app.example.com/oidc".into(),
                };
                provider.exchange_code(&sample_claims(), "authcode")
            })
            .await
            .expect("spawn")
            .expect("token");

            assert_eq!(token_set.access_token, "oidc-token");
            assert_eq!(token_set.refresh_token.as_deref(), Some("oidc-refresh"));
            assert_eq!(
                token_set.scopes,
                vec!["openid".to_string(), "profile".to_string()]
            );
        });
    }

    #[cfg_attr(not(feature = "wiremock_tests"), ignore)]
    #[test]
    fn refresh_hits_token_endpoint() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/oauth2/v1/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "oidc-token",
                    "expires_in": 900,
                    "refresh_token": "oidc-refresh",
                    "scope": "openid profile",
                    "token_type": "Bearer"
                })))
                .mount(&server)
                .await;

            let token_url = format!("{}/oauth2/v1/token", server.uri());
            let auth_url = format!("{}/oauth2/v1/authorize", server.uri());

            let token_set = tokio::task::spawn_blocking(move || {
                let provider = GenericOidcProvider {
                    agent: Agent::new(),
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    auth_url,
                    token_url,
                    default_scopes: vec!["openid".into(), "profile".into()],
                    redirect_uri: "https://app.example.com/oidc".into(),
                };
                provider.refresh(&sample_claims(), "oidc-refresh")
            })
            .await
            .expect("spawn")
            .expect("token");

            assert_eq!(token_set.access_token, "oidc-token");
        });
    }
}
