use oauth_core::{
    provider::{Provider, ProviderError, ProviderErrorKind, ProviderResult},
    types::{OAuthFlowRequest, OAuthFlowResult, TokenHandleClaims, TokenSet},
};
use serde::Deserialize;
use ureq::{Agent, Error as UreqError};
use url::Url;

use crate::security::pkce::PkcePair;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantMode {
    Multi,
    Single(String),
}

impl TenantMode {
    pub fn from_env(value: &str) -> Result<Self, ProviderError> {
        if value == "multi" {
            return Ok(TenantMode::Multi);
        }
        if let Some(rest) = value.strip_prefix("single:") {
            if rest.is_empty() {
                return Err(ProviderError::new(
                    ProviderErrorKind::Configuration,
                    "single tenant mode requires tenant id".to_string(),
                ));
            }
            return Ok(TenantMode::Single(rest.to_string()));
        }
        Err(ProviderError::new(
            ProviderErrorKind::Configuration,
            format!("unsupported tenant mode '{value}'"),
        ))
    }

    fn authority_segment(&self) -> &str {
        match self {
            TenantMode::Multi => "common",
            TenantMode::Single(tenant_id) => tenant_id.as_str(),
        }
    }
}

pub struct MicrosoftProvider {
    agent: Agent,
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    redirect_uri: String,
}

impl MicrosoftProvider {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        tenant_mode: TenantMode,
        redirect_uri: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        let client_id = client_id.into();
        let client_secret = client_secret.into();
        let redirect_uri = redirect_uri.into();

        if client_id.is_empty() || client_secret.is_empty() {
            return Err(ProviderError::new(
                ProviderErrorKind::Configuration,
                "missing Microsoft client credentials".to_string(),
            ));
        }

        let authority = tenant_mode.authority_segment().to_string();
        let auth_url =
            format!("https://login.microsoftonline.com/{authority}/oauth2/v2.0/authorize");
        let token_url = format!("https://login.microsoftonline.com/{authority}/oauth2/v2.0/token");

        Ok(Self {
            agent: Agent::new(),
            client_id,
            client_secret,
            auth_url,
            token_url,
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

        let scopes = request.scopes.join(" ");

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
            query.append_pair("response_mode", "query");
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

impl Provider for MicrosoftProvider {
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
            scopes: request.scopes.clone(),
        })
    }

    fn exchange_code(&self, _claims: &TokenHandleClaims, code: &str) -> ProviderResult<TokenSet> {
        let scope_owned = "offline_access openid profile".to_string();
        let code_owned = code.to_string();
        let params = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code_owned.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("scope", scope_owned.as_str()),
        ];

        self.execute_token_request(&params)
    }

    fn refresh(
        &self,
        _claims: &TokenHandleClaims,
        refresh_token: &str,
    ) -> ProviderResult<TokenSet> {
        let scope_owned = "offline_access openid profile".to_string();
        let refresh_owned = refresh_token.to_string();
        let params = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_owned.as_str()),
            ("scope", scope_owned.as_str()),
        ];

        self.execute_token_request(&params)
    }

    fn revoke(&self, _claims: &TokenHandleClaims, _token: &str) -> ProviderResult<()> {
        Err(ProviderError::new(
            ProviderErrorKind::Unsupported,
            "Microsoft Graph revoke not implemented".to_string(),
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
                team: Some("platform".into()),
            },
            owner: OwnerKind::User {
                subject: "user:1".into(),
            },
            redirect_uri: "https://app.example.com/callback".into(),
            state: Some("state123".into()),
            scopes: vec!["User.Read".into(), "offline_access".into()],
            code_challenge: Some("challenge123".into()),
            code_challenge_method: Some("S256".into()),
        }
    }

    fn sample_claims() -> TokenHandleClaims {
        TokenHandleClaims {
            provider: "microsoft".into(),
            subject: "user:1".into(),
            owner: OwnerKind::User {
                subject: "user:1".into(),
            },
            tenant: TenantCtx {
                env: "prod".into(),
                tenant: "acme".into(),
                team: Some("platform".into()),
            },
            scopes: vec!["User.Read".into()],
            issued_at: 1,
            expires_at: 2,
        }
    }

    #[test]
    fn authorize_redirect_includes_expected_parameters() {
        let provider = MicrosoftProvider::new(
            "client",
            "secret",
            TenantMode::Multi,
            "https://app.example.com/callback",
        )
        .expect("provider setup");

        let result = provider
            .build_authorize_redirect(&sample_request())
            .expect("build redirect");
        let url = Url::parse(&result.redirect_url).expect("valid url");
        let params: HashMap<_, _> = url.query_pairs().into_owned().collect();

        assert_eq!(params.get("client_id"), Some(&"client".to_string()));
        assert_eq!(
            params.get("redirect_uri"),
            Some(&"https://app.example.com/callback".to_string())
        );
        assert_eq!(
            params.get("scope"),
            Some(&"User.Read offline_access".to_string())
        );
        assert_eq!(
            params.get("code_challenge"),
            Some(&"challenge123".to_string())
        );
        assert_eq!(params.get("state"), Some(&"state123".to_string()));
    }

    #[cfg_attr(not(feature = "wiremock_tests"), ignore)]
    #[test]
    fn exchange_code_hits_token_endpoint() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/oauth2/v2.0/token"))
                .and(body_string_contains("client_id=client"))
                .and(body_string_contains("grant_type=authorization_code"))
                .and(body_string_contains("code=authcode"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "token",
                    "expires_in": 3600,
                    "refresh_token": "refresh",
                    "scope": "User.Read offline_access",
                    "token_type": "Bearer"
                })))
                .mount(&server)
                .await;

            let token_url = format!("{}/oauth2/v2.0/token", server.uri());
            let auth_url = format!("{}/oauth2/v2.0/authorize", server.uri());

            let token_set = tokio::task::spawn_blocking(move || {
                let provider = MicrosoftProvider {
                    agent: Agent::new(),
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    auth_url,
                    token_url,
                    redirect_uri: "https://app.example.com/callback".into(),
                };
                provider.exchange_code(&sample_claims(), "authcode")
            })
            .await
            .expect("spawn")
            .expect("token");

            assert_eq!(token_set.access_token, "token");
            assert_eq!(token_set.refresh_token.as_deref(), Some("refresh"));
            assert_eq!(
                token_set.scopes,
                vec!["User.Read".to_string(), "offline_access".to_string()]
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
                .and(path("/oauth2/v2.0/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains("refresh_token=refresh"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "token",
                    "expires_in": 3600,
                    "refresh_token": "refresh",
                    "scope": "User.Read offline_access",
                    "token_type": "Bearer"
                })))
                .mount(&server)
                .await;

            let token_url = format!("{}/oauth2/v2.0/token", server.uri());
            let auth_url = format!("{}/oauth2/v2.0/authorize", server.uri());

            let token_set = tokio::task::spawn_blocking(move || {
                let provider = MicrosoftProvider {
                    agent: Agent::new(),
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    auth_url,
                    token_url,
                    redirect_uri: "https://app.example.com/callback".into(),
                };
                provider.refresh(&sample_claims(), "refresh")
            })
            .await
            .expect("spawn")
            .expect("token");

            assert_eq!(token_set.access_token, "token");
        });
    }
}
