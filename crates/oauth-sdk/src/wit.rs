use anyhow::{anyhow, Result as AnyhowResult};
use async_trait::async_trait;
use reqwest::Method;
use std::time::Duration;

use crate::{
    AccessToken, Client, FlowResult, InitiateAuthRequest, InitiateAuthResponse, OwnerKind,
    SignedFetchRequest, SignedFetchResponse, Visibility,
};

wasmtime::component::bindgen!({
    path: "../../oauth-wit/greentic.oauth@0.1.0.wit",
    world: "broker",
    async: true,
});

/// Host adapter that wires the SDK client into the WASM component model.
pub struct BrokerHost {
    pub client: Client,
}

#[async_trait]
impl broker::Host for BrokerHost {
    type Error = anyhow::Error;

    async fn health_check(&mut self) -> AnyhowResult<String> {
        Ok("ok".to_string())
    }

    async fn initiate_auth(
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
        let response = self
            .client
            .initiate_auth(init_request)
            .await
            .map_err(map_sdk_error)?;
        Ok(to_wit_initiate_response(response))
    }

    async fn await_result(
        &mut self,
        flow_id: String,
        timeout_ms: Option<u64>,
    ) -> AnyhowResult<broker::FlowResult> {
        let timeout = timeout_ms.map(Duration::from_millis);
        let result = self
            .client
            .await_result(&flow_id, timeout)
            .await
            .map_err(map_sdk_error)?;
        Ok(to_wit_flow_result(result)?)
    }

    async fn get_access_token(
        &mut self,
        token_handle: String,
        force_refresh: bool,
    ) -> AnyhowResult<broker::GetAccessTokenResult> {
        let token = self
            .client
            .get_access_token(&token_handle, force_refresh)
            .await
            .map_err(map_sdk_error)?;
        Ok(broker::GetAccessTokenResult {
            access_token: token.access_token,
            expires_at: token.expires_at,
        })
    }

    async fn signed_fetch(
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
        let response = self
            .client
            .signed_fetch(signed_request)
            .await
            .map_err(map_sdk_error)?;
        Ok(broker::SignedFetchResponse {
            status: response.status,
            headers: response
                .headers
                .into_iter()
                .map(|(name, value)| broker::Header { name, value })
                .collect(),
            body: base64::engine::general_purpose::STANDARD.encode(response.body),
            body_encoding: "base64".to_string(),
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
    let claims_json = serde_json::to_string(&result.token_handle_claims)?;
    Ok(broker::FlowResult {
        flow_id: result.flow_id,
        env: result.env,
        tenant: result.tenant,
        team: result.team,
        provider: result.provider,
        storage_path: result.storage_path,
        token_handle_claims_json: claims_json,
    })
}

fn map_sdk_error(err: crate::SdkError) -> anyhow::Error {
    anyhow!(err)
}
