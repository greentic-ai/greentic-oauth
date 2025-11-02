use std::cell::RefCell;

use opentelemetry::global;
use opentelemetry::propagation::{Extractor, Injector};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::context::{CloudCtx, set_context};
use crate::init::TELEMETRY_STATE;

/// Minimal header carrier abstraction for propagation.
pub trait Carrier {
    fn set(&mut self, key: &str, value: String);
    fn get(&self, key: &str) -> Option<String>;
}

/// Inject the current span context and cloud metadata into the carrier.
pub fn inject_carrier(headers: &mut impl Carrier) {
    global::get_text_map_propagator(|propagator| {
        let mut injector = CarrierInjector { carrier: headers };
        propagator.inject_context(&Span::current().context(), &mut injector);
    });

    if let Some(state) = TELEMETRY_STATE.get() {
        for (key, value) in state.context_snapshot() {
            if let (Some(header), Some(value)) =
                (header_name_for(key), value.filter(|v| !v.is_empty()))
            {
                headers.set(header, value);
            }
        }
    }
}

/// Extract span context and cloud metadata from the carrier into the current span.
pub fn extract_carrier(headers: &impl Carrier) {
    let span = Span::current();
    extract_carrier_into_span(headers, &span);
}

/// Extract span context and cloud metadata from the carrier into the provided span.
pub fn extract_carrier_into_span(headers: &impl Carrier, span: &Span) {
    let extractor = CarrierExtractor::new(headers);
    let parent_ctx = global::get_text_map_propagator(|propagator| propagator.extract(&extractor));

    if let Err(err) = span.set_parent(parent_ctx) {
        tracing::debug!(
            target: "greentic.telemetry",
            error = %err,
            "extract_carrier could not apply remote parent context"
        );
    }

    let tenant = headers.get("x-tenant");
    let team = headers.get("x-team");
    let flow = headers.get("x-flow");
    let run_id = headers.get("x-run-id");

    set_context(CloudCtx {
        tenant: tenant.as_deref(),
        team: team.as_deref(),
        flow: flow.as_deref(),
        run_id: run_id.as_deref(),
    });
}

struct CarrierInjector<'a, C> {
    carrier: &'a mut C,
}

impl<'a, C: Carrier> Injector for CarrierInjector<'a, C> {
    fn set(&mut self, key: &str, value: String) {
        self.carrier.set(key, value);
    }
}

struct CarrierExtractor<'a, C> {
    carrier: &'a C,
    storage: RefCell<Vec<Box<str>>>,
}

impl<'a, C> CarrierExtractor<'a, C> {
    fn new(carrier: &'a C) -> Self {
        Self {
            carrier,
            storage: RefCell::new(Vec::new()),
        }
    }
}

impl<'a, C: Carrier> Extractor for CarrierExtractor<'a, C> {
    fn get(&self, key: &str) -> Option<&str> {
        self.carrier.get(key).map(|value| {
            let boxed = value.into_boxed_str();
            let ptr: *const str = boxed.as_ref();
            self.storage.borrow_mut().push(boxed);
            // Safety: the boxed string is stored in `storage`, ensuring it lives for
            // the lifetime of the extractor. The propagator consumes the reference
            // synchronously, so returning it here is safe.
            unsafe { &*ptr }
        })
    }

    fn keys(&self) -> Vec<&str> {
        Vec::new()
    }
}

fn header_name_for(key: &str) -> Option<&'static str> {
    match key {
        "tenant" => Some("x-tenant"),
        "team" => Some("x-team"),
        "flow" => Some("x-flow"),
        "run_id" => Some("x-run-id"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::CloudCtx;
    use crate::init::{TELEMETRY_STATE, TelemetryInit, init};
    use crate::set_context;
    use opentelemetry::trace::{Span, TraceContextExt, Tracer};
    use std::collections::HashMap;
    use std::sync::Once;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    #[derive(Default)]
    struct MockCarrier {
        headers: HashMap<String, String>,
    }

    impl Carrier for MockCarrier {
        fn set(&mut self, key: &str, value: String) {
            self.headers.insert(key.to_string(), value);
        }

        fn get(&self, key: &str) -> Option<String> {
            self.headers.get(key).cloned()
        }
    }

    fn ensure_init() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            // Ensure spans are recorded during tests so trace IDs are generated.
            unsafe {
                std::env::set_var("RUST_LOG", "trace");
            }
            init(
                TelemetryInit {
                    service_name: "propagation-test",
                    service_version: "0.0.1",
                    deployment_env: "test",
                },
                &[],
            )
            .expect("telemetry init");
        });
    }

    #[test]
    fn round_trip_trace_and_context() {
        ensure_init();

        set_context(CloudCtx {
            tenant: Some("tenant-123"),
            team: Some("team-xyz"),
            flow: Some("flow-abc"),
            run_id: Some("run-0001"),
        });

        let parent_span = tracing::info_span!("parent");
        let parent_trace_id = parent_span
            .context()
            .span()
            .span_context()
            .trace_id()
            .to_string();

        let mut carrier = MockCarrier::default();
        {
            let _guard = parent_span.enter();
            let span_ctx = tracing::Span::current()
                .context()
                .span()
                .span_context()
                .clone();
            assert!(tracing::Span::current().id().is_some(), "span missing id");
            assert!(span_ctx.is_valid(), "parent span context invalid");
            let mut test_ctx = opentelemetry::global::tracer("manual-test").start("manual-test");
            assert!(
                test_ctx.span_context().is_valid(),
                "manual tracer context invalid"
            );
            test_ctx.end();
            inject_carrier(&mut carrier);
        }

        assert!(carrier.headers.contains_key("traceparent"));
        assert_eq!(
            carrier.headers.get("x-tenant"),
            Some(&"tenant-123".to_string())
        );

        // Clear local context before extraction to ensure values come from headers.
        set_context(CloudCtx::empty());

        let child_span = tracing::info_span!("child");
        extract_carrier_into_span(&carrier, &child_span);
        {
            let _guard = child_span.enter();
        }

        let child_trace_id = child_span
            .context()
            .span()
            .span_context()
            .trace_id()
            .to_string();

        assert_eq!(child_trace_id, parent_trace_id);

        let snapshot = TELEMETRY_STATE
            .get()
            .expect("telemetry state")
            .context_snapshot();
        let context_map: HashMap<_, _> = snapshot.into_iter().collect();
        assert_eq!(
            context_map.get("tenant").cloned().flatten(),
            Some("tenant-123".to_string())
        );
        assert_eq!(
            context_map.get("team").cloned().flatten(),
            Some("team-xyz".to_string())
        );
        assert_eq!(
            context_map.get("flow").cloned().flatten(),
            Some("flow-abc".to_string())
        );
        assert_eq!(
            context_map.get("run_id").cloned().flatten(),
            Some("run-0001".to_string())
        );
    }
}
