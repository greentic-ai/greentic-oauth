use reqwest::StatusCode;
use thiserror::Error;
use url::ParseError;

/// Errors produced by the OAuth client helper.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("base_url is required")]
    MissingBaseUrl,
    #[error("invalid base_url: {0}")]
    InvalidBaseUrl(String),
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url error: {0}")]
    Url(#[from] ParseError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("server responded with {status}: {message}")]
    HttpStatus { status: StatusCode, message: String },
}

impl ClientError {
    pub(crate) fn status(status: StatusCode, message: impl Into<String>) -> Self {
        Self::HttpStatus {
            status,
            message: message.into(),
        }
    }
}
