use thiserror::Error;

/// Errors emitted by the OAuth SDK client.
#[derive(Debug, Error)]
pub enum SdkError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("nats error: {0}")]
    Nats(#[from] async_nats::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
    #[error("operation timed out")]
    Timeout,
    #[error("unexpected response: {0}")]
    InvalidResponse(String),
}

impl From<tokio::time::error::Elapsed> for SdkError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        SdkError::Timeout
    }
}
