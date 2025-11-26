#[cfg(not(target_arch = "wasm32"))]
mod client;
#[cfg(target_arch = "wasm32")]
mod client_wasm;
mod error;
mod types;

#[cfg(not(target_arch = "wasm32"))]
pub use client::Client;
#[cfg(target_arch = "wasm32")]
pub use client_wasm::Client;

pub use error::SdkError;
#[cfg(not(target_arch = "wasm32"))]
pub use greentic_oauth_host::{
    request_distributor_token, request_git_token, request_oci_token, request_repo_token,
    request_scanner_token,
};
pub use types::{
    AccessToken, ClientConfig, FlowResult, InitiateAuthRequest, InitiateAuthResponse, OwnerKind,
    SignedFetchRequest, SignedFetchResponse, Visibility,
};

#[cfg(target_arch = "wasm32")]
pub use http::Method;
#[cfg(not(target_arch = "wasm32"))]
pub use reqwest::Method;
