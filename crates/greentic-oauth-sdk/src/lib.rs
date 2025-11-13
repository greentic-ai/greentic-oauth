#[cfg(not(target_arch = "wasm32"))]
mod client;
#[cfg(target_arch = "wasm32")]
mod client_wasm;
mod error;
mod types;

#[cfg(feature = "wasm-host")]
pub mod wit;

#[cfg(not(target_arch = "wasm32"))]
pub use client::Client;
#[cfg(target_arch = "wasm32")]
pub use client_wasm::Client;

pub use error::SdkError;
pub use types::{
    AccessToken, ClientConfig, FlowResult, InitiateAuthRequest, InitiateAuthResponse, OwnerKind,
    SignedFetchRequest, SignedFetchResponse, Visibility,
};

pub use reqwest::Method;
