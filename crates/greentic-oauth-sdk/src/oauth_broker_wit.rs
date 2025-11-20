//! Host bindings for `greentic:oauth-broker@1.0.0`.
//!
//! This adapter wires the SDK `Client` into the WIT world so Wasmtime hosts can
//! expose OAuth operations to components without linking against the broker
//! binary.

use std::future::Future;

use anyhow::{Result as AnyhowResult, anyhow};
use serde::Serialize;
use serde_json::Value;
use tokio::runtime::Handle;
use wasmtime::component::Linker;

use crate::{Client, InitiateAuthRequest, OwnerKind};

pub mod broker {
    pub trait Host {
        type Error;
        fn get_consent_url(
            &mut self,
            provider_id: String,
            subject: String,
            scopes: Vec<String>,
            redirect_path: String,
            extra_json: String,
        ) -> String;
        fn exchange_code(
            &mut self,
            provider_id: String,
            subject: String,
            code: String,
            redirect_path: String,
        ) -> String;
        fn get_token(
            &mut self,
            provider_id: String,
            subject: String,
            scopes: Vec<String>,
        ) -> String;
    }

    pub fn add_to_linker<TCtx, H>(
        _linker: &mut wasmtime::component::Linker<TCtx>,
        _make: impl Fn(&TCtx) -> H + Send + Sync + Copy + 'static,
    ) -> wasmtime::Result<()>
    where
        H: Host + 'static,
        TCtx: 'static,
    {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
struct TokenSet {
    access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<String>,
    #[serde(default)]
    extra: Value,
}

/// Host implementation for the OAuth broker world.
#[derive(Clone)]
pub struct BrokerHost {
    pub client: Client,
}

impl BrokerHost {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    fn block<F, T>(&self, fut: F) -> AnyhowResult<T>
    where
        F: Future<Output = Result<T, crate::SdkError>> + Send + 'static,
        T: Send + 'static,
    {
        Handle::current().block_on(fut).map_err(anyhow::Error::from)
    }
}

impl broker::Host for BrokerHost {
    type Error = anyhow::Error;

    fn get_consent_url(
        &mut self,
        provider_id: String,
        subject: String,
        scopes: Vec<String>,
        redirect_path: String,
        _extra_json: String,
    ) -> String {
        // Map to the existing "initiate auth" flow; flow_id is treated as provider_id.
        let request = InitiateAuthRequest {
            owner_kind: OwnerKind::User,
            owner_id: subject,
            flow_id: provider_id,
            scopes,
            redirect_uri: Some(redirect_path),
            visibility: None,
        };
        let client = self.client.clone();
        match self.block(async move { client.initiate_auth(request).await }) {
            Ok(resp) => resp.redirect_url,
            Err(err) => {
                tracing::warn!("get_consent_url failed: {err:#}");
                String::new()
            }
        }
    }

    fn exchange_code(
        &mut self,
        _provider_id: String,
        _subject: String,
        code: String,
        _redirect_path: String,
    ) -> String {
        // Best-effort: treat `code` as an existing token handle and fetch an access token.
        let client = self.client.clone();
        match self.block(async move { client.get_access_token(&code, true).await }) {
            Ok(token) => serde_json::to_string(&TokenSet {
                access_token: token.access_token,
                refresh_token: None,
                expires_at: Some(token.expires_at),
                token_type: None,
                extra: Value::Null,
            })
            .unwrap_or_default(),
            Err(err) => {
                tracing::warn!("exchange_code failed: {err:#}");
                String::new()
            }
        }
    }

    fn get_token(&mut self, _provider_id: String, subject: String, _scopes: Vec<String>) -> String {
        // Best-effort: treat `subject` as a token handle.
        let client = self.client.clone();
        match self.block(async move { client.get_access_token(&subject, false).await }) {
            Ok(token) => serde_json::to_string(&TokenSet {
                access_token: token.access_token,
                refresh_token: None,
                expires_at: Some(token.expires_at),
                token_type: None,
                extra: Value::Null,
            })
            .unwrap_or_default(),
            Err(err) => {
                tracing::warn!("get_token failed: {err:#}");
                String::new()
            }
        }
    }
}

/// Helper to add the oauth-broker world to a Wasmtime linker.
pub fn add_oauth_broker_world_to_linker<TCtx>(
    linker: &mut Linker<TCtx>,
    make_host: impl Fn(&TCtx) -> BrokerHost + Send + Sync + Copy + 'static,
) -> anyhow::Result<()> {
    broker::add_to_linker(linker, make_host)
        .map_err(|err| anyhow!("failed to add oauth-broker world: {err}"))
}
