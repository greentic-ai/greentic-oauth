#[cfg(not(target_arch = "wasm32"))]
mod client;
#[cfg(target_arch = "wasm32")]
mod client_wasm;
mod error;
mod types;
#[cfg(not(target_arch = "wasm32"))]
mod validator;

#[cfg(not(target_arch = "wasm32"))]
pub use client::Client;
#[cfg(target_arch = "wasm32")]
pub use client_wasm::Client;

pub use error::SdkError;
pub use greentic_oauth_core::{AccessToken, OAuthError, OAuthResult, ValidatedClaims};
#[cfg(not(target_arch = "wasm32"))]
pub use greentic_oauth_host::linker as oauth_broker_wit;
#[cfg(not(target_arch = "wasm32"))]
pub use greentic_oauth_host::{
    OAuthBroker, OauthBrokerHost, request_distributor_token, request_git_token, request_oci_token,
    request_repo_token, request_scanner_token,
};
pub use types::{
    ClientConfig, FlowResult, InitiateAuthRequest, InitiateAuthResponse, OwnerKind,
    SignedFetchRequest, SignedFetchResponse, Visibility,
};
#[cfg(not(target_arch = "wasm32"))]
pub use validator::{TokenValidationConfig, validate_bearer_token};

#[cfg(target_arch = "wasm32")]
pub use http::Method;
#[cfg(not(target_arch = "wasm32"))]
pub use reqwest::Method;
