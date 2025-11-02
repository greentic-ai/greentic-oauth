use once_cell::sync::Lazy;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use tracing::{Level, event, span};

#[derive(Clone, Copy, Debug)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug)]
pub struct Field<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

static HOST_STATE: Lazy<HostState> = Lazy::new(|| HostState {
    next_id: AtomicU64::new(1),
    spans: Mutex::new(HashMap::new()),
});

thread_local! {
    static SPAN_STACK: RefCell<Vec<(u64, tracing::span::EnteredSpan)>> = const { RefCell::new(Vec::new()) };
}

struct HostState {
    next_id: AtomicU64,
    spans: Mutex<HashMap<u64, tracing::Span>>,
}

pub fn log(level: LogLevel, message: &str, fields: &[Field<'_>]) {
    match level {
        LogLevel::Trace => {
            event!(target: "greentic.wasm", Level::TRACE, runtime = "wasm", message = %message, guest_fields = %FieldsDisplay(fields))
        }
        LogLevel::Debug => {
            event!(target: "greentic.wasm", Level::DEBUG, runtime = "wasm", message = %message, guest_fields = %FieldsDisplay(fields))
        }
        LogLevel::Info => {
            event!(target: "greentic.wasm", Level::INFO, runtime = "wasm", message = %message, guest_fields = %FieldsDisplay(fields))
        }
        LogLevel::Warn => {
            event!(target: "greentic.wasm", Level::WARN, runtime = "wasm", message = %message, guest_fields = %FieldsDisplay(fields))
        }
        LogLevel::Error => {
            event!(target: "greentic.wasm", Level::ERROR, runtime = "wasm", message = %message, guest_fields = %FieldsDisplay(fields))
        }
    }
}

pub fn span_start(name: &str, fields: &[Field<'_>]) -> u64 {
    let span = span!(
        target: "greentic.wasm",
        Level::INFO,
        "guest-span",
        runtime = "wasm",
        span_name = %name,
        guest_fields = tracing::field::Empty
    );

    span.record(
        "guest_fields",
        tracing::field::display(FieldsDisplay(fields)),
    );

    let id = HOST_STATE.next_id.fetch_add(1, Ordering::Relaxed);
    HOST_STATE
        .spans
        .lock()
        .expect("span mutex poisoned")
        .insert(id, span.clone());

    SPAN_STACK.with(|stack| {
        stack.borrow_mut().push((id, span.entered()));
    });

    id
}

pub fn span_end(id: u64) {
    HOST_STATE
        .spans
        .lock()
        .expect("span mutex poisoned")
        .remove(&id);

    let removed = SPAN_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        match stack.pop() {
            Some((current_id, _guard)) if current_id == id => true,
            Some((current_id, guard)) => {
                stack.push((current_id, guard));
                false
            }
            None => false,
        }
    });

    if !removed {
        tracing::warn!(
            target: "greentic.wasm",
            runtime = "native",
            span_id = id,
            "attempted to end unknown wasm span",
        );
    }
}

struct FieldsDisplay<'a>(&'a [Field<'a>]);

impl fmt::Display for FieldsDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for Field { key, value } in self.0 {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            write!(f, "{}={}", key, value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::Subscriber;
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::registry::{LookupSpan, Registry};

    #[derive(Debug, Clone)]
    struct RecordedEvent {
        level: Level,
        runtime: Option<String>,
        guest_fields: Option<String>,
        parent_span_name: Option<String>,
    }

    #[derive(Debug, Default, Clone)]
    struct RecordedSpan {
        name: String,
        runtime: Option<String>,
        guest_fields: Option<String>,
    }

    #[derive(Clone, Default)]
    struct CaptureState {
        events: Arc<Mutex<Vec<RecordedEvent>>>,
        spans: Arc<Mutex<HashMap<tracing::span::Id, RecordedSpan>>>,
    }

    struct CaptureLayer {
        state: CaptureState,
    }

    impl<S> Layer<S> for CaptureLayer
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            id: &tracing::span::Id,
            _ctx: Context<'_, S>,
        ) {
            let mut visitor = Visitor::new();
            attrs.record(&mut visitor);

            let span = RecordedSpan {
                name: attrs.metadata().name().to_string(),
                runtime: visitor.runtime,
                guest_fields: visitor.guest_fields,
            };

            self.state
                .spans
                .lock()
                .expect("lock spans")
                .insert(id.clone(), span);
        }

        fn on_record(
            &self,
            span: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: Context<'_, S>,
        ) {
            if let Some(recorded) = self.state.spans.lock().expect("lock spans").get_mut(span) {
                let mut visitor = Visitor::new();
                values.record(&mut visitor);

                if let Some(runtime) = visitor.runtime {
                    recorded.runtime = Some(runtime);
                }
                if let Some(fields) = visitor.guest_fields {
                    recorded.guest_fields = Some(fields);
                }
            }
        }

        fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
            let mut visitor = Visitor::new();
            event.record(&mut visitor);

            let parent_span_name = ctx.lookup_current().and_then(|span| {
                let spans = self.state.spans.lock().expect("lock spans");
                spans.get(&span.id()).map(|s| s.name.clone())
            });

            let recorded = RecordedEvent {
                level: *event.metadata().level(),
                runtime: visitor.runtime,
                guest_fields: visitor.guest_fields,
                parent_span_name,
            };

            self.state
                .events
                .lock()
                .expect("lock events")
                .push(recorded);
        }
    }

    struct Visitor {
        runtime: Option<String>,
        guest_fields: Option<String>,
    }

    impl Visitor {
        fn new() -> Self {
            Self {
                runtime: None,
                guest_fields: None,
            }
        }
    }

    impl tracing::field::Visit for Visitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            match field.name() {
                "runtime" => self.runtime = Some(value.to_string()),
                "guest_fields" => self.guest_fields = Some(value.to_string()),
                _ => {}
            }
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
            if field.name() == "guest_fields" {
                self.guest_fields = Some(format!("{value:?}"));
            }
        }

        fn record_bool(&mut self, _: &tracing::field::Field, _: bool) {}
        fn record_i64(&mut self, _: &tracing::field::Field, _: i64) {}
        fn record_u64(&mut self, _: &tracing::field::Field, _: u64) {}
        fn record_f64(&mut self, _: &tracing::field::Field, _: f64) {}
        fn record_error(
            &mut self,
            _: &tracing::field::Field,
            _: &(dyn std::error::Error + 'static),
        ) {
        }
    }

    #[test]
    fn logs_and_spans_are_forwarded() {
        let state = CaptureState::default();
        let layer = CaptureLayer {
            state: state.clone(),
        };

        use tracing_subscriber::prelude::*;
        let subscriber = Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let span_id = span_start(
                "outer",
                &[Field {
                    key: "tenant",
                    value: "wasm-tenant",
                }],
            );

            log(
                LogLevel::Info,
                "guest log",
                &[Field {
                    key: "tenant",
                    value: "wasm-tenant",
                }],
            );

            span_end(span_id);
        });

        let events = { state.events.lock().expect("events lock").clone() };
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.level, Level::INFO);
        assert_eq!(event.runtime.as_deref(), Some("wasm"));
        assert_eq!(event.parent_span_name.as_deref(), Some("guest-span"));
        assert_eq!(event.guest_fields.as_deref(), Some("tenant=wasm-tenant"));

        let spans = state.spans.lock().expect("spans lock");
        assert!(
            spans
                .values()
                .any(|span| span.runtime.as_deref() == Some("wasm")),
            "expected runtime=wasm on span"
        );
    }
}
