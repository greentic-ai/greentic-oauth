use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue, Response, StatusCode};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::http::error::AppError;

const SPEC_VERSION: &str = "1.0";
const CACHE_CONTROL_VALUE: &str = "max-age=60";

pub fn json_response(value: Value) -> Result<Response<Body>, AppError> {
    let body = serde_json::to_vec(&value)?;
    build_response(body)
}

pub fn json_response_from_serializable<T>(value: &T) -> Result<Response<Body>, AppError>
where
    T: Serialize,
{
    let json = serde_json::to_value(value)?;
    json_response(json)
}

fn build_response(body: Vec<u8>) -> Result<Response<Body>, AppError> {
    let etag = format!("\"{}\"", compute_etag(&body));
    let etag_value = HeaderValue::from_str(&etag)
        .map_err(|err| AppError::internal(format!("invalid etag value: {err}")))?;
    let cache_control = HeaderValue::from_static(CACHE_CONTROL_VALUE);
    let spec_version = HeaderValue::from_static(SPEC_VERSION);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )
        .header(header::CACHE_CONTROL, cache_control)
        .header(header::ETAG, etag_value)
        .header(HeaderName::from_static("x-spec-version"), spec_version)
        .body(Body::from(body))
        .map_err(|err| AppError::internal(err.to_string()))?;
    Ok(response)
}

fn compute_etag(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let hash = hasher.finalize();
    format!("{:x}", hash)
}
