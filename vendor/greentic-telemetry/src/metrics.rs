use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::{
    Counter as OtelCounter, Gauge as OtelGauge, Histogram as OtelHistogram,
};
use opentelemetry::trace::TraceContextExt;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::init::TELEMETRY_STATE;

#[derive(Clone, Debug)]
pub struct Counter {
    inner: Option<OtelCounter<f64>>,
}

impl Counter {
    pub fn add(&self, value: f64) {
        if let Some(counter) = &self.inner {
            counter.add(value, &attributes());
        }
    }
}

#[derive(Clone, Debug)]
pub struct Gauge {
    inner: Option<OtelGauge<f64>>,
}

impl Gauge {
    pub fn record(&self, value: f64) {
        if let Some(gauge) = &self.inner {
            gauge.record(value, &attributes());
        }
    }
}

#[derive(Clone, Debug)]
pub struct Histogram {
    inner: Option<OtelHistogram<f64>>,
}

impl Histogram {
    pub fn record(&self, value: f64) {
        if let Some(histogram) = &self.inner {
            histogram.record(value, &attributes());
        }
    }
}

pub fn counter(name: &'static str) -> Counter {
    let meter = global::meter("greentic-telemetry");
    let inner = Some(meter.f64_counter(name).build());
    Counter { inner }
}

pub fn gauge(name: &'static str) -> Gauge {
    let meter = global::meter("greentic-telemetry");
    let inner = Some(meter.f64_gauge(name).build());
    Gauge { inner }
}

pub fn histogram(name: &'static str) -> Histogram {
    let meter = global::meter("greentic-telemetry");
    let inner = Some(meter.f64_histogram(name).build());
    Histogram { inner }
}

fn attributes() -> Vec<KeyValue> {
    let mut attrs = Vec::new();

    if let Some(state) = TELEMETRY_STATE.get() {
        attrs.push(KeyValue::new(
            "service.name",
            state.service_name.to_string(),
        ));
        attrs.push(KeyValue::new(
            "service.version",
            state.service_version.to_string(),
        ));
        attrs.push(KeyValue::new(
            "deployment.environment",
            state.deployment_env.to_string(),
        ));

        for (key, value) in state.context_snapshot() {
            if let Some(value) = value {
                let masked = crate::redaction::redact_field(key, &value);
                attrs.push(KeyValue::new(key, masked));
            }
        }
    }

    let span = Span::current();
    let span_context = span.context().span().span_context().clone();
    if span_context.is_valid() {
        attrs.push(KeyValue::new(
            "trace_id",
            span_context.trace_id().to_string(),
        ));
        attrs.push(KeyValue::new("span_id", span_context.span_id().to_string()));
    }

    attrs
}
