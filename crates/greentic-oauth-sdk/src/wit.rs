use anyhow::{Result as AnyhowResult, anyhow};
use base64::Engine;
use reqwest::Method;
use std::{future::Future, time::Duration};
use tokio::runtime::Handle;

use crate::{
    Client, FlowResult, InitiateAuthRequest, InitiateAuthResponse, OwnerKind, SignedFetchRequest,
    SignedFetchResponse, Visibility,
};

wasmtime::component::bindgen!({
    path: "../../oauth-wit/greentic.oauth@0.1.0.wit",
    world: "broker",
});

/// Host adapter that wires the SDK client into the WASM component model.
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
        Ok(to_wit_initiate_response(response))
    }

    fn await_result(
        &mut self,
        flow_id: String,
        timeout_ms: Option<u64>,
    ) -> AnyhowResult<broker::FlowResult> {
        let timeout = timeout_ms.map(Duration::from_millis);
        let client = self.client.clone();
        let result = self.block(async move { client.await_result(&flow_id, timeout).await })?;
        Ok(to_wit_flow_result(result)?)
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
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|_| anyhow!("invalid HTTP method"))?;
        let headers = request
            .headers
            .into_iter()
            .map(|header| (header.name, header.value))
            .collect();
        let body = match request.body {
            Some(body) => Some(
                base64::engine::general_purpose::STANDARD
                    .decode(body.as_bytes())
                    .map_err(|err| anyhow!("invalid base64 body: {err}"))?,
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
        Ok(to_wit_signed_fetch_response(response))
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

fn to_wit_initiate_response(response: InitiateAuthResponse) -> broker::InitiateResponse {
    broker::InitiateResponse {
        flow_id: response.flow_id,
        redirect_url: response.redirect_url,
        state: response.state,
    }
}

fn to_wit_flow_result(result: FlowResult) -> AnyhowResult<broker::FlowResult> {
    let token_handle = serde_json::to_string(&result.token_handle_claims)
        .map_err(|err| anyhow!("serialize token handle: {err}"))?;
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

fn to_wit_signed_fetch_response(response: SignedFetchResponse) -> broker::SignedFetchResponse {
    broker::SignedFetchResponse {
        status: response.status,
        headers: response
            .headers
            .into_iter()
            .map(|(name, value)| broker::Header { name, value })
            .collect(),
        body: base64::engine::general_purpose::STANDARD.encode(response.body),
        body_encoding: "base64".to_string(),
    }
}

fn map_sdk_error(err: crate::SdkError) -> anyhow::Error {
    anyhow!(err)
}

impl BrokerHost {
    fn block<F, T>(&self, fut: F) -> AnyhowResult<T>
    where
        F: Future<Output = Result<T, crate::SdkError>> + Send + 'static,
        T: Send + 'static,
    {
        Handle::current().block_on(fut).map_err(map_sdk_error)
    }
}
