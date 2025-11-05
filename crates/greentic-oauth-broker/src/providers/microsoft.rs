use greentic_oauth_core::{
    provider::{Provider, ProviderError, ProviderErrorKind, ProviderResult},
    types::{OAuthFlowRequest, OAuthFlowResult, TokenHandleClaims, TokenSet},
};
use serde::Deserialize;
use ureq::Agent;
use url::Url;

use crate::security::pkce::PkcePair;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantMode {
    Common,
    Organizations,
    Consumers,
    Tenant(String),
}

impl TenantMode {
    pub fn from_env(value: &str) -> Result<Self, ProviderError> {
        let trimmed = value.trim();
        if trimmed.eq_ignore_ascii_case("multi") || trimmed.eq_ignore_ascii_case("common") {
            return Ok(TenantMode::Common);
        }

        if trimmed.eq_ignore_ascii_case("organizations") {
            return Ok(TenantMode::Organizations);
        }

        if trimmed.eq_ignore_ascii_case("consumers") {
            return Ok(TenantMode::Consumers);
        }

        if let Some(rest) = trimmed.strip_prefix("single:") {
            let tenant_id = rest.trim();
            if tenant_id.is_empty() {
                return Err(ProviderError::new(
                    ProviderErrorKind::Configuration,
                    "single tenant mode requires tenant id".to_string(),
                ));
            }
            return Ok(TenantMode::Tenant(tenant_id.to_string()));
        }

        if !trimmed.is_empty() {
            return Ok(TenantMode::Tenant(trimmed.to_string()));
        }

        Err(ProviderError::new(
            ProviderErrorKind::Configuration,
            "tenant mode value empty".to_string(),
        ))
    }

    fn authority_segment(&self) -> &str {
        match self {
            TenantMode::Common => "common",
            TenantMode::Organizations => "organizations",
            TenantMode::Consumers => "consumers",
            TenantMode::Tenant(tenant_id) => tenant_id.as_str(),
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
    default_scopes: Vec<String>,
    resource_audience: Option<String>,
}

impl MicrosoftProvider {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        tenant_mode: TenantMode,
        redirect_uri: impl Into<String>,
        default_scopes: Vec<String>,
        resource_audience: Option<String>,
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

        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();

        let scopes = if default_scopes.is_empty() {
            vec![
                "offline_access".to_string(),
                "openid".to_string(),
                "profile".to_string(),
            ]
        } else {
            default_scopes
        };

        Ok(Self {
            agent,
            client_id,
            client_secret,
            auth_url,
            token_url,
            redirect_uri,
            default_scopes: scopes,
            resource_audience: resource_audience.filter(|value| !value.trim().is_empty()),
        })
    }

    fn normalized_scopes(&self, requested: &[String]) -> Vec<String> {
        if requested.is_empty() {
            if !self.default_scopes.is_empty() {
                return self.default_scopes.clone();
            }
            if let Some(resource) = &self.resource_audience {
                return vec![format!("{resource}/.default")];
            }
            return vec![
                "offline_access".to_string(),
                "openid".to_string(),
                "profile".to_string(),
            ];
        }
        requested.to_vec()
    }

    fn build_query(
        &self,
        request: &OAuthFlowRequest,
        scopes: &[String],
    ) -> Result<(Url, Option<String>), ProviderError> {
        let mut url = Url::parse(&self.auth_url).map_err(|err| {
            ProviderError::new(
                ProviderErrorKind::Configuration,
                format!("invalid auth url: {err}"),
            )
        })?;

        let scope_string = scopes.join(" ");

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
            query.append_pair("scope", &scope_string);
            query.append_pair("response_mode", "query");
            query.append_pair("code_challenge", &challenge);
            query.append_pair("code_challenge_method", &method);

            if let Some(state) = &request.state {
                query.append_pair("state", state);
            }
        }

        Ok((url, verifier))
    }

    fn execute_token_request(&self, params: Vec<(String, String)>) -> ProviderResult<TokenSet> {
        let mut response = self
            .agent
            .post(&self.token_url)
            .send_form(params.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .map_err(|err| ProviderError::new(ProviderErrorKind::Transport, err.to_string()))?;

        let status = response.status();

        if !status.is_success() {
            let status_code = status.as_u16();
            let reason = status.canonical_reason().unwrap_or("token endpoint error");
            let body = response
                .body_mut()
                .read_to_string()
                .unwrap_or_else(|_| String::new());

            return Err(ProviderError::new(
                ProviderErrorKind::Authorization,
                format!("token endpoint returned {status_code} {reason}: {body}"),
            ));
        }

        let payload: TokenEndpointResponse = response.body_mut().read_json().map_err(|err| {
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
        let scopes = self.normalized_scopes(&request.scopes);
        let (url, _verifier) = self.build_query(request, &scopes)?;

        Ok(OAuthFlowResult {
            redirect_url: url.to_string(),
            state: request.state.clone(),
            scopes,
        })
    }

    fn exchange_code(&self, _claims: &TokenHandleClaims, code: &str) -> ProviderResult<TokenSet> {
        let scope_list = self.normalized_scopes(&_claims.scopes);
        let scope_owned = scope_list.join(" ");
        let code_owned = code.to_string();
        let params = vec![
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code_owned),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("scope".to_string(), scope_owned),
        ];

        self.execute_token_request(params)
    }

    fn refresh(
        &self,
        _claims: &TokenHandleClaims,
        refresh_token: &str,
    ) -> ProviderResult<TokenSet> {
        let scope_list = self.normalized_scopes(&_claims.scopes);
        let scope_owned = scope_list.join(" ");
        let refresh_owned = refresh_token.to_string();
        let params = vec![
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_owned),
            ("scope".to_string(), scope_owned),
        ];

        self.execute_token_request(params)
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
    #[serde(default)]
    id_token: Option<String>,
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
            id_token: value.id_token,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router, body::Bytes, extract::State, http::StatusCode, response::IntoResponse,
        routing::post,
    };
    use greentic_oauth_core::types::{OwnerKind, TenantCtx};
    use serde_json::json;
    use std::{
        collections::HashMap,
        net::SocketAddr,
        sync::{Arc, Mutex},
    };
    use tokio::{runtime::Runtime, sync::oneshot};
    use ureq::Agent;

    struct StubServer {
        base_url: String,
        requests: Arc<Mutex<Vec<String>>>,
        shutdown: Option<oneshot::Sender<()>>,
    }

    #[derive(Clone)]
    struct AppState {
        requests: Arc<Mutex<Vec<String>>>,
        response: Arc<serde_json::Value>,
    }

    async fn token_handler(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
        let body_str = String::from_utf8(body.to_vec()).expect("request body utf8");
        state.requests.lock().expect("requests lock").push(body_str);
        (StatusCode::OK, Json((*state.response).clone()))
    }

    impl StubServer {
        async fn start(
            path: &'static str,
            response_body: serde_json::Value,
        ) -> Result<Self, std::io::Error> {
            let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await?;
            let addr = listener.local_addr()?;
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let app_state = AppState {
                requests: Arc::clone(&requests),
                response: Arc::new(response_body),
            };

            let app = Router::new()
                .route(path, post(token_handler))
                .with_state(app_state);

            let server = axum::serve(listener, app.into_make_service());
            tokio::spawn(async move {
                let _ = server
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });

            Ok(Self {
                base_url: format!("http://{}", addr),
                requests,
                shutdown: Some(shutdown_tx),
            })
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn take_requests(&self) -> Vec<String> {
            self.requests.lock().expect("requests lock").clone()
        }
    }

    impl Drop for StubServer {
        fn drop(&mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
        }
    }

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
            scopes: vec!["User.Read".into(), "offline_access".into()],
            issued_at: 1,
            expires_at: 2,
        }
    }

    fn test_agent() -> Agent {
        Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into()
    }

    #[test]
    fn authorize_redirect_includes_expected_parameters() {
        let provider = MicrosoftProvider::new(
            "client",
            "secret",
            TenantMode::Common,
            "https://app.example.com/callback",
            vec!["offline_access".into(), "User.Read".into()],
            None,
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

    #[cfg_attr(
        not(feature = "network-tests"),
        ignore = "requires loopback networking"
    )]
    #[test]
    fn exchange_code_hits_token_endpoint() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let server = match StubServer::start(
                "/oauth2/v2.0/token",
                json!({
                    "access_token": "token",
                    "expires_in": 3600,
                    "refresh_token": "refresh",
                    "scope": "User.Read offline_access",
                    "token_type": "Bearer"
                }),
            )
            .await
            {
                Ok(server) => server,
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    eprintln!("skipping exchange_code_hits_token_endpoint test: {err}");
                    return;
                }
                Err(err) => panic!("bind stub listener: {err}"),
            };

            let token_url = format!("{}/oauth2/v2.0/token", server.base_url());
            let auth_url = format!("{}/oauth2/v2.0/authorize", server.base_url());

            let token_set = tokio::task::spawn_blocking(move || {
                let provider = MicrosoftProvider {
                    agent: test_agent(),
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    auth_url,
                    token_url,
                    redirect_uri: "https://app.example.com/callback".into(),
                    default_scopes: vec!["User.Read".into(), "offline_access".into()],
                    resource_audience: None,
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

            let requests = server.take_requests();
            assert!(
                requests
                    .iter()
                    .any(|body| body.contains("grant_type=authorization_code")),
                "expected authorization_code grant request"
            );
            assert!(
                requests.iter().any(|body| body.contains("code=authcode")),
                "expected authorization_code request to include code"
            );
        });
    }

    #[cfg_attr(
        not(feature = "network-tests"),
        ignore = "requires loopback networking"
    )]
    #[test]
    fn refresh_hits_token_endpoint() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let server = match StubServer::start(
                "/oauth2/v2.0/token",
                json!({
                    "access_token": "token",
                    "expires_in": 3600,
                    "refresh_token": "refresh",
                    "scope": "User.Read offline_access",
                    "token_type": "Bearer"
                }),
            )
            .await
            {
                Ok(server) => server,
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    eprintln!("skipping refresh_hits_token_endpoint test: {err}");
                    return;
                }
                Err(err) => panic!("bind stub listener: {err}"),
            };

            let token_url = format!("{}/oauth2/v2.0/token", server.base_url());
            let auth_url = format!("{}/oauth2/v2.0/authorize", server.base_url());

            let token_set = tokio::task::spawn_blocking(move || {
                let provider = MicrosoftProvider {
                    agent: test_agent(),
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    auth_url,
                    token_url,
                    redirect_uri: "https://app.example.com/callback".into(),
                    default_scopes: vec!["User.Read".into(), "offline_access".into()],
                    resource_audience: None,
                };
                provider.refresh(&sample_claims(), "refresh")
            })
            .await
            .expect("spawn")
            .expect("token");

            assert_eq!(token_set.access_token, "token");

            let requests = server.take_requests();
            assert!(
                requests
                    .iter()
                    .any(|body| body.contains("grant_type=refresh_token")),
                "expected refresh_token grant request"
            );
            assert!(
                requests
                    .iter()
                    .any(|body| body.contains("refresh_token=refresh")),
                "expected refresh_token request to include refresh token"
            );
        });
    }
}
