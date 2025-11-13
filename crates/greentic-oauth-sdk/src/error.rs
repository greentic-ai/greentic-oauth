use thiserror::Error;

#[cfg(not(target_arch = "wasm32"))]
use std::fmt;

/// Errors emitted by the OAuth SDK client.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Error)]
pub enum SdkError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("nats error: {0}")]
    Nats(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
    #[error("operation timed out")]
    Timeout,
    #[error("unexpected response: {0}")]
    InvalidResponse(String),
    #[error("{0}")]
    Unsupported(&'static str),
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Error)]
pub enum SdkError {
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("{0}")]
    Unsupported(&'static str),
}

#[cfg(not(target_arch = "wasm32"))]
impl From<tokio::time::error::Elapsed> for SdkError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        SdkError::Timeout
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<E> From<async_nats::error::Error<E>> for SdkError
where
    E: Clone + fmt::Debug + fmt::Display + PartialEq,
{
    fn from(err: async_nats::error::Error<E>) -> Self {
        SdkError::Nats(format!("{err:?}"))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<async_nats::SubscribeError> for SdkError {
    fn from(err: async_nats::SubscribeError) -> Self {
        SdkError::Nats(err.to_string())
    }
}
