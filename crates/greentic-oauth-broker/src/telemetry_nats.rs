use std::{cell::RefCell, collections::BTreeMap};

use greentic_telemetry::{TelemetryCtx, set_current_telemetry_ctx, with_current_telemetry_ctx};
use opentelemetry::global;
use opentelemetry::propagation::{Extractor, Injector};
use tracing::{Span, debug, info};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Container for NATS header propagation.
#[derive(Clone, Debug, Default)]
pub struct NatsHeaders {
    inner: BTreeMap<String, String>,
}

impl NatsHeaders {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.inner.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.inner.get(key)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.inner.iter()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = String::from("NATS/1.0\r\n");
        for (key, value) in &self.inner {
            buffer.push_str(key);
            buffer.push_str(": ");
            buffer.push_str(value);
            buffer.push_str("\r\n");
        }
        buffer.push_str("\r\n");
        buffer.into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|err| format!("invalid NATS header encoding: {err}"))?;
        let mut lines = text.split("\r\n");
        let prelude = lines
            .next()
            .ok_or_else(|| "missing NATS header prelude".to_string())?;
        if prelude.trim() != "NATS/1.0" {
            return Err("unexpected NATS header prelude".to_string());
        }

        let mut headers = BTreeMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| format!("invalid header line `{line}`"))?;
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }

        Ok(Self { inner: headers })
    }
}

pub fn inject(headers: &mut NatsHeaders) {
    inject_trace(headers);
    if let Some(ctx) = current_task_telemetry() {
        headers.insert("x-tenant", ctx.tenant.clone());
        if let Some(session) = ctx.session.clone() {
            headers.insert("x-session", session.clone());
            headers.insert("x-run-id", session);
        }
        if let Some(flow) = ctx.flow.clone() {
            headers.insert("x-flow", flow);
        }
        if let Some(node) = ctx.node.clone() {
            headers.insert("x-node", node);
        }
        if let Some(provider) = ctx.provider.clone() {
            headers.insert("x-provider", provider);
        }
    }
}

pub fn extract(headers: &NatsHeaders) {
    if headers.is_empty() {
        return;
    }

    extract_trace_into_current_span(headers);

    if let Some(ctx) = telemetry_from_headers(headers) {
        set_current_telemetry_ctx(ctx);
    }

    info!(
        target: "greentic.telemetry",
        event = "nats.extract",
        headers = headers.len(),
        "trace context extracted from NATS headers"
    );
}

fn current_task_telemetry() -> Option<TelemetryCtx> {
    with_current_telemetry_ctx(|ctx| ctx.cloned())
}

fn inject_trace(headers: &mut NatsHeaders) {
    global::get_text_map_propagator(|propagator| {
        let mut injector = NatsInjector { headers };
        propagator.inject_context(&Span::current().context(), &mut injector);
    });
}

fn extract_trace_into_current_span(headers: &NatsHeaders) {
    let extractor = NatsExtractor::new(headers);
    let parent_ctx = global::get_text_map_propagator(|propagator| propagator.extract(&extractor));
    let span = Span::current();
    if let Err(err) = span.set_parent(parent_ctx) {
        debug!(
            target: "greentic.telemetry",
            error = %err,
            "nats.extract failed to apply remote parent context"
        );
    }
}

fn telemetry_from_headers(headers: &NatsHeaders) -> Option<TelemetryCtx> {
    let tenant = headers.get("x-tenant")?.clone();
    let mut ctx = TelemetryCtx::new(tenant);

    if let Some(session) = headers
        .get("x-session")
        .or_else(|| headers.get("x-run-id"))
        .cloned()
    {
        ctx = ctx.with_session(session);
    }

    if let Some(flow) = headers.get("x-flow").cloned() {
        ctx = ctx.with_flow(flow);
    }

    if let Some(node) = headers.get("x-node").cloned() {
        ctx = ctx.with_node(node);
    }

    if let Some(provider) = headers
        .get("x-provider")
        .or_else(|| headers.get("x-team"))
        .cloned()
    {
        ctx = ctx.with_provider(provider);
    }

    Some(ctx)
}

struct NatsInjector<'a> {
    headers: &'a mut NatsHeaders,
}

impl<'a> Injector for NatsInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        self.headers.insert(key, value);
    }
}

struct NatsExtractor<'a> {
    headers: &'a NatsHeaders,
    storage: RefCell<Vec<Box<str>>>,
}

impl<'a> NatsExtractor<'a> {
    fn new(headers: &'a NatsHeaders) -> Self {
        Self {
            headers,
            storage: RefCell::new(Vec::new()),
        }
    }
}

impl<'a> Extractor for NatsExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key).map(|value| {
            let boxed = value.clone().into_boxed_str();
            let ptr: *const str = boxed.as_ref();
            self.storage.borrow_mut().push(boxed);
            // Safety: storage holds the boxed string for the lifetime of the extractor.
            unsafe { &*ptr }
        })
    }

    fn keys(&self) -> Vec<&str> {
        Vec::new()
    }
}
