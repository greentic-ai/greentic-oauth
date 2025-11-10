use axum::http::StatusCode;
use once_cell::sync::Lazy;
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::{KeyValue, global};

static AUTH_START_CREATED: Lazy<Counter<u64>> = Lazy::new(|| {
    global::meter("greentic-oauth-broker")
        .u64_counter("auth.start.created")
        .with_description("Auth sessions created")
        .build()
});

static AUTH_CALLBACK_SUCCESS: Lazy<Counter<u64>> = Lazy::new(|| {
    global::meter("greentic-oauth-broker")
        .u64_counter("auth.callback.success")
        .with_description("Successful OAuth callbacks")
        .build()
});

static AUTH_CALLBACK_FAILURE: Lazy<Counter<u64>> = Lazy::new(|| {
    global::meter("greentic-oauth-broker")
        .u64_counter("auth.callback.failure")
        .with_description("Failed OAuth callbacks")
        .build()
});

static AUTH_CALLBACK_LATENCY: Lazy<Histogram<f64>> = Lazy::new(|| {
    global::meter("greentic-oauth-broker")
        .f64_histogram("auth.callback.latency_ms")
        .with_description("Latency from /oauth/start to /callback in ms")
        .build()
});

pub fn record_start_created(provider: &str, status: StatusCode) {
    AUTH_START_CREATED.add(1, &provider_attrs(provider, status, None));
}

pub fn record_callback_success(provider: &str, latency_ms: Option<f64>, status: StatusCode) {
    AUTH_CALLBACK_SUCCESS.add(1, &provider_attrs(provider, status, None));
    if let Some(value) = latency_ms {
        AUTH_CALLBACK_LATENCY.record(value, &provider_attrs(provider, status, None));
    }
}

pub fn record_callback_failure(
    provider: &str,
    latency_ms: Option<f64>,
    status: StatusCode,
    error_code: &str,
) {
    AUTH_CALLBACK_FAILURE.add(1, &provider_attrs(provider, status, Some(error_code)));
    if let Some(value) = latency_ms {
        AUTH_CALLBACK_LATENCY.record(value, &provider_attrs(provider, status, Some(error_code)));
    }
}

fn provider_attrs(provider: &str, status: StatusCode, error_code: Option<&str>) -> Vec<KeyValue> {
    let mut attrs = vec![
        KeyValue::new("provider", provider.to_string()),
        KeyValue::new("http_status", status.as_u16() as i64),
    ];
    if let Some(code) = error_code {
        attrs.push(KeyValue::new("error_code", code.to_string()));
    }
    attrs
}
