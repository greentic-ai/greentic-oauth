use anyhow::Result as AnyhowResult;
use base64::Engine;
use reqwest::Method;
use serde_json;
use std::{future::Future, time::Duration};
use tokio::runtime::Handle;

use crate::{Client, InitiateAuthRequest, OwnerKind, SignedFetchRequest, Visibility};

pub mod broker {
    #[derive(Clone, Debug)]
    pub struct Header {
        pub name: String,
        pub value: String,
    }

    #[derive(Clone, Copy, Debug)]
    pub enum OwnerKind {
        User,
        Service,
    }

    #[derive(Clone, Copy, Debug)]
    pub enum Visibility {
        Private,
        Team,
        Tenant,
    }

    #[derive(Clone, Debug)]
    pub struct InitiateRequest {
        pub flow_id: String,
        pub owner_kind: OwnerKind,
        pub owner_id: String,
        pub scopes: Vec<String>,
        pub redirect_uri: Option<String>,
        pub visibility: Option<Visibility>,
    }

    #[derive(Clone, Debug)]
    pub struct InitiateResponse {
        pub flow_id: String,
        pub redirect_url: String,
        pub state: String,
    }

    #[derive(Clone, Debug)]
    pub struct FlowResult {
        pub flow_id: String,
        pub env: String,
        pub tenant: String,
        pub team: Option<String>,
        pub provider: String,
        pub storage_path: String,
        pub token_handle_claims_json: String,
    }

    #[derive(Clone, Debug)]
    pub struct SignedFetchRequest {
        pub token_handle: String,
        pub method: String,
        pub url: String,
        pub headers: Vec<Header>,
        pub body: Option<String>,
        pub body_encoding: String,
    }

    #[derive(Clone, Debug)]
    pub struct SignedFetchResponse {
        pub status: u16,
        pub headers: Vec<Header>,
        pub body: String,
        pub body_encoding: String,
    }

    #[derive(Clone, Debug)]
    pub struct GetAccessTokenResult {
        pub access_token: String,
        pub expires_at: u64,
    }

    pub trait Host {
        type Error;

        fn health_check(&mut self) -> Result<String, Self::Error>;
        fn initiate_auth(
            &mut self,
            request: InitiateRequest,
        ) -> Result<InitiateResponse, Self::Error>;
        fn await_result(
            &mut self,
            flow_id: String,
            timeout_ms: Option<u64>,
        ) -> Result<FlowResult, Self::Error>;
        fn get_access_token(
            &mut self,
            token_handle: String,
            force_refresh: bool,
        ) -> Result<GetAccessTokenResult, Self::Error>;
        fn signed_fetch(
            &mut self,
            request: SignedFetchRequest,
        ) -> Result<SignedFetchResponse, Self::Error>;
    }
}

pub mod discovery {
    pub trait Host {
        type Error;

        fn list_providers(&mut self) -> Result<Vec<String>, Self::Error>;
        fn get_descriptor(
            &mut self,
            tenant: String,
            provider: String,
            team: Option<String>,
            user: Option<String>,
        ) -> Result<String, Self::Error>;
        fn get_requirements(
            &mut self,
            tenant: String,
            provider: String,
            team: Option<String>,
            user: Option<String>,
        ) -> Result<String, Self::Error>;
        fn start_flow(
            &mut self,
            tenant: String,
            provider: String,
            grant_type: String,
            team: Option<String>,
            user: Option<String>,
        ) -> Result<String, Self::Error>;
    }
}

/// Host adapter that wires the SDK client into the mock WIT surface.
#[derive(Clone)]
pub struct BrokerHost {
    pub client: Client,
}

impl broker::Host for BrokerHost {
    type Error = anyhow::Error;

    fn health_check(&mut self) -> AnyhowResult<String> {
        Ok("ok".to_string())
    }

    fn initiate_auth(
        &mut self,
        request: broker::InitiateRequest,
    ) -> AnyhowResult<broker::InitiateResponse> {
        let owner_kind = match request.owner_kind {
            broker::OwnerKind::User => OwnerKind::User,
            broker::OwnerKind::Service => OwnerKind::Service,
        };
        let visibility = request.visibility.map(|value| match value {
            broker::Visibility::Private => Visibility::Private,
            broker::Visibility::Team => Visibility::Team,
            broker::Visibility::Tenant => Visibility::Tenant,
        });
        let init_request = InitiateAuthRequest {
            owner_kind,
            owner_id: request.owner_id,
            flow_id: request.flow_id,
            scopes: request.scopes,
            redirect_uri: request.redirect_uri,
            visibility,
        };
        let client = self.client.clone();
        let response = self.block(async move { client.initiate_auth(init_request).await })?;
        Ok(broker::InitiateResponse {
            flow_id: response.flow_id,
            redirect_url: response.redirect_url,
            state: response.state,
        })
    }

    fn await_result(
        &mut self,
        flow_id: String,
        timeout_ms: Option<u64>,
    ) -> AnyhowResult<broker::FlowResult> {
        let timeout = timeout_ms.map(Duration::from_millis);
        let client = self.client.clone();
        let result = self.block(async move { client.await_result(&flow_id, timeout).await })?;
        let token_handle =
            serde_json::to_string(&result.token_handle_claims).map_err(anyhow::Error::from)?;
        Ok(broker::FlowResult {
            flow_id: result.flow_id,
            env: result.env,
            tenant: result.tenant,
            team: result.team,
            provider: result.provider,
            storage_path: result.storage_path,
            token_handle_claims_json: token_handle,
        })
    }

    fn get_access_token(
        &mut self,
        token_handle: String,
        force_refresh: bool,
    ) -> AnyhowResult<broker::GetAccessTokenResult> {
        let client = self.client.clone();
        let token =
            self.block(async move { client.get_access_token(&token_handle, force_refresh).await })?;
        Ok(broker::GetAccessTokenResult {
            access_token: token.access_token,
            expires_at: token.expires_at,
        })
    }

    fn signed_fetch(
        &mut self,
        request: broker::SignedFetchRequest,
    ) -> AnyhowResult<broker::SignedFetchResponse> {
        let method = Method::from_bytes(request.method.as_bytes())?;
        let headers: Vec<_> = request
            .headers
            .iter()
            .map(|header| (header.name.clone(), header.value.clone()))
            .collect();
        let body = match &request.body {
            Some(body) => Some(
                base64::engine::general_purpose::STANDARD
                    .decode(body.as_bytes())
                    .map_err(anyhow::Error::from)?,
            ),
            None => None,
        };
        let signed_request = SignedFetchRequest {
            token_handle: request.token_handle,
            method,
            url: request.url,
            headers,
            body,
        };
        let client = self.client.clone();
        let response = self.block(async move { client.signed_fetch(signed_request).await })?;
        let headers = response
            .headers
            .into_iter()
            .map(|(name, value)| broker::Header { name, value })
            .collect();
        Ok(broker::SignedFetchResponse {
            status: response.status,
            headers,
            body: base64::engine::general_purpose::STANDARD.encode(response.body),
            body_encoding: "base64".to_string(),
        })
    }
}

impl discovery::Host for BrokerHost {
    type Error = anyhow::Error;

    fn list_providers(&mut self) -> AnyhowResult<Vec<String>> {
        let client = self.client.clone();
        self.block(async move { client.list_providers().await })
    }

    fn get_descriptor(
        &mut self,
        tenant: String,
        provider: String,
        team: Option<String>,
        user: Option<String>,
    ) -> AnyhowResult<String> {
        let client = self.client.clone();
        self.block(async move {
            client
                .get_provider_descriptor_json(&tenant, &provider, team.as_deref(), user.as_deref())
                .await
        })
    }

    fn get_requirements(
        &mut self,
        tenant: String,
        provider: String,
        team: Option<String>,
        user: Option<String>,
    ) -> AnyhowResult<String> {
        let client = self.client.clone();
        self.block(async move {
            client
                .get_config_requirements_json(&tenant, &provider, team.as_deref(), user.as_deref())
                .await
        })
    }

    fn start_flow(
        &mut self,
        tenant: String,
        provider: String,
        grant_type: String,
        team: Option<String>,
        user: Option<String>,
    ) -> AnyhowResult<String> {
        let client = self.client.clone();
        self.block(async move {
            client
                .start_flow_blueprint_json(
                    &tenant,
                    &provider,
                    &grant_type,
                    team.as_deref(),
                    user.as_deref(),
                )
                .await
        })
    }
}

impl BrokerHost {
    fn block<F, T>(&self, fut: F) -> AnyhowResult<T>
    where
        F: Future<Output = Result<T, crate::SdkError>> + Send + 'static,
        T: Send + 'static,
    {
        Handle::current().block_on(fut).map_err(anyhow::Error::from)
    }
}
