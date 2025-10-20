use std::fmt;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{
    events::PublishError, security::SecurityError, storage::secrets_manager::StorageError,
};

#[derive(Debug)]
pub struct AppError {
    status: StatusCode,
    message: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

impl From<SecurityError> for AppError {
    fn from(value: SecurityError) -> Self {
        match value {
            SecurityError::Encoding(_) | SecurityError::InvalidKey(_) => {
                AppError::bad_request(value.to_string())
            }
            _ => AppError::internal(value.to_string()),
        }
    }
}

impl From<StorageError> for AppError {
    fn from(value: StorageError) -> Self {
        match value {
            StorageError::InvalidPath(_) => AppError::bad_request(value.to_string()),
            StorageError::NotFound(_) => AppError::not_found(value.to_string()),
            _ => AppError::internal(value.to_string()),
        }
    }
}

impl From<PublishError> for AppError {
    fn from(value: PublishError) -> Self {
        AppError::internal(value.to_string())
    }
}

impl From<oauth_core::provider::ProviderError> for AppError {
    fn from(value: oauth_core::provider::ProviderError) -> Self {
        let status = match value.kind() {
            oauth_core::provider::ProviderErrorKind::Configuration => StatusCode::BAD_REQUEST,
            oauth_core::provider::ProviderErrorKind::Authorization => StatusCode::UNAUTHORIZED,
            oauth_core::provider::ProviderErrorKind::Transport
            | oauth_core::provider::ProviderErrorKind::InvalidResponse
            | oauth_core::provider::ProviderErrorKind::Other
            | oauth_core::provider::ProviderErrorKind::Unsupported => StatusCode::BAD_GATEWAY,
        };
        AppError::new(status, value.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        AppError::internal(value.to_string())
    }
}

impl From<url::ParseError> for AppError {
    fn from(value: url::ParseError) -> Self {
        AppError::bad_request(value.to_string())
    }
}
