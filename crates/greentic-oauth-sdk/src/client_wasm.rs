use std::time::Duration;

use crate::error::SdkError;
use crate::types::{
    AccessToken, ClientConfig, FlowResult, InitiateAuthRequest, InitiateAuthResponse,
    SignedFetchRequest, SignedFetchResponse,
};

/// Placeholder client for wasm32 targets. The SDK currently depends on host networking
/// stacks (reqwest, tokio, async-nats) that are unavailable when compiling to wasm, so the
/// exported API simply reports this constraint in a structured error.
#[derive(Clone, Debug, Default)]
pub struct Client;

impl Client {
    /// The async constructor always fails on wasm targets.
    pub async fn connect(config: ClientConfig) -> Result<Self, SdkError> {
        let _ = config;
        Err(SdkError::Unsupported(
            "greentic-oauth-sdk client is unavailable on wasm32 targets",
        ))
    }

    pub async fn initiate_auth(
        &self,
        _request: InitiateAuthRequest,
    ) -> Result<InitiateAuthResponse, SdkError> {
        Err(SdkError::Unsupported(
            "initiate_auth is not implemented on wasm32 targets",
        ))
    }

    pub async fn await_result(
        &self,
        _flow_id: &str,
        _timeout: Option<Duration>,
    ) -> Result<FlowResult, SdkError> {
        Err(SdkError::Unsupported(
            "await_result is not implemented on wasm32 targets",
        ))
    }

    pub async fn get_access_token(
        &self,
        _token_handle: &str,
        _force_refresh: bool,
    ) -> Result<AccessToken, SdkError> {
        Err(SdkError::Unsupported(
            "get_access_token is not implemented on wasm32 targets",
        ))
    }

    pub async fn signed_fetch(
        &self,
        _request: SignedFetchRequest,
    ) -> Result<SignedFetchResponse, SdkError> {
        Err(SdkError::Unsupported(
            "signed_fetch is not implemented on wasm32 targets",
        ))
    }

    pub async fn list_providers(&self) -> Result<Vec<String>, SdkError> {
        Err(SdkError::Unsupported(
            "list_providers is not implemented on wasm32 targets",
        ))
    }

    pub async fn get_provider_descriptor_json(
        &self,
        _tenant: &str,
        _provider: &str,
        _team: Option<&str>,
        _user: Option<&str>,
    ) -> Result<String, SdkError> {
        Err(SdkError::Unsupported(
            "get_provider_descriptor_json is not implemented on wasm32 targets",
        ))
    }

    pub async fn get_config_requirements_json(
        &self,
        _tenant: &str,
        _provider: &str,
        _team: Option<&str>,
        _user: Option<&str>,
    ) -> Result<String, SdkError> {
        Err(SdkError::Unsupported(
            "get_config_requirements_json is not implemented on wasm32 targets",
        ))
    }

    pub async fn start_flow_blueprint_json(
        &self,
        _tenant: &str,
        _provider: &str,
        _grant_type: &str,
        _team: Option<&str>,
        _user: Option<&str>,
    ) -> Result<String, SdkError> {
        Err(SdkError::Unsupported(
            "start_flow_blueprint_json is not implemented on wasm32 targets",
        ))
    }
}
